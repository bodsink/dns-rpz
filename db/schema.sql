-- DNS-RPZ Database Schema
-- PostgreSQL 14+

-- -------------------------------------------------------
-- Settings: application config stored in DB
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key         VARCHAR(64)  PRIMARY KEY,
    value       TEXT         NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- RPZ Zones: list of managed RPZ zones
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS rpz_zones (
    id                  BIGSERIAL       PRIMARY KEY,
    name                VARCHAR(255)    NOT NULL UNIQUE,   -- zone FQDN, e.g. "rpz.example.com"
    mode                VARCHAR(8)      NOT NULL DEFAULT 'slave' CHECK (mode IN ('master', 'slave')),
    master_ip           INET,                              -- primary AXFR master (slave mode only)
    master_ip_secondary INET,                              -- secondary/backup AXFR master (optional)
    master_port         SMALLINT        NOT NULL DEFAULT 53,
    tsig_key            VARCHAR(255),
    tsig_secret         TEXT,                              -- base64-encoded TSIG secret
    sync_interval       INT             NOT NULL DEFAULT 300,
    serial              BIGINT          NOT NULL DEFAULT 0,
    last_sync_at        TIMESTAMPTZ,
    last_sync_status    VARCHAR(16),                       -- success, failed, in_progress
    enabled             BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Add secondary master column for existing databases (safe to run multiple times)
ALTER TABLE rpz_zones ADD COLUMN IF NOT EXISTS master_ip_secondary INET;

-- -------------------------------------------------------
-- RPZ Records: blocked domain entries (can be millions)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS rpz_records (
    id          BIGSERIAL       PRIMARY KEY,
    zone_id     BIGINT          NOT NULL REFERENCES rpz_zones(id) ON DELETE CASCADE,
    name        VARCHAR(255)    NOT NULL,  -- domain to block, e.g. "malware.example.com"
    rtype       VARCHAR(16)     NOT NULL DEFAULT 'CNAME',
    rdata       TEXT            NOT NULL DEFAULT '.',
    ttl         INT             NOT NULL DEFAULT 300,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Critical index for DNS lookup performance (millions of rows)
CREATE UNIQUE INDEX IF NOT EXISTS idx_rpz_records_zone_name  ON rpz_records (zone_id, name);

-- The separate name-only index is no longer needed: DNS queries use the
-- in-memory index, and startup LoadAllNames queries by zone_id (covered by
-- idx_rpz_records_zone_name). Dropping it halves index-maintenance cost during AXFR sync.
DROP INDEX IF EXISTS idx_rpz_records_name;

-- synced_at column added in trust-network milestone (idempotent).
-- source_node_id and axfr_batch_sig are added after nodes table is created (see below).
ALTER TABLE rpz_records ADD COLUMN IF NOT EXISTS synced_at      TIMESTAMPTZ NOT NULL DEFAULT now();

-- -------------------------------------------------------
-- Users: dashboard authentication
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL       PRIMARY KEY,
    username        VARCHAR(64)     NOT NULL UNIQUE,
    password_hash   VARCHAR(255)    NOT NULL,
    role            VARCHAR(16)     NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer')),
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- -------------------------------------------------------
-- Sessions: cookie-based session store
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id          VARCHAR(64)     PRIMARY KEY,
    user_id     BIGINT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ     NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- -------------------------------------------------------
-- IP Filters: allowed client IPs/CIDRs for recursion
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_filters (
    id          BIGSERIAL   PRIMARY KEY,
    cidr        CIDR        NOT NULL UNIQUE,
    description TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- Sync History: AXFR sync audit log
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS sync_history (
    id              BIGSERIAL       PRIMARY KEY,
    zone_id         BIGINT          NOT NULL REFERENCES rpz_zones(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          VARCHAR(16)     NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'success', 'failed')),
    records_added   INT             NOT NULL DEFAULT 0,
    records_removed INT             NOT NULL DEFAULT 0,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sync_history_zone_id    ON sync_history (zone_id);
CREATE INDEX IF NOT EXISTS idx_sync_history_started_at ON sync_history (started_at DESC);

-- -------------------------------------------------------
-- DNS Query Log: per-query audit log for statistics
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_query_log (
    id          BIGSERIAL    PRIMARY KEY,
    client_ip   INET         NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    qtype       VARCHAR(16)  NOT NULL,
    result      VARCHAR(16)  NOT NULL CHECK (result IN ('allowed', 'blocked', 'refused')),
    upstream    VARCHAR(64),
    rtt_ms      INT,
    queried_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Safe to run on existing tables (no-op if columns already exist)
ALTER TABLE dns_query_log ADD COLUMN IF NOT EXISTS upstream VARCHAR(64);
ALTER TABLE dns_query_log ADD COLUMN IF NOT EXISTS rtt_ms   INT;

CREATE INDEX IF NOT EXISTS idx_dns_query_log_queried_at ON dns_query_log (queried_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_result     ON dns_query_log (result);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_domain     ON dns_query_log (domain);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_client_ip  ON dns_query_log (client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_upstream   ON dns_query_log (upstream);

-- -------------------------------------------------------
-- Server Stats: live counters written by dns-rpz-dns process
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS server_stats (
    key         VARCHAR(64)  PRIMARY KEY,
    value       BIGINT       NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- Default settings (first run)
-- -------------------------------------------------------
INSERT INTO settings (key, value) VALUES
    ('mode',                   'slave'),
    ('master_ip',              ''),
    ('master_port',            '53'),
    ('tsig_key',               ''),
    ('tsig_secret',            ''),
    ('sync_interval',          '86400'),
    ('web_port',               '8080'),
    ('timezone',               'UTC'),
    ('dns_upstream',           '8.8.8.8:53,8.8.4.4:53'),
    ('dns_upstream_strategy',  'roundrobin')
ON CONFLICT (key) DO NOTHING;

-- -------------------------------------------------------
-- Trust Network: node identities (all nodes ever known)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key       TEXT        UNIQUE NOT NULL,
    fingerprint      TEXT,
    name             TEXT,
    role             TEXT        NOT NULL CHECK (role IN ('slave', 'master', 'genesis')),
    status           TEXT        NOT NULL CHECK (status IN ('active', 'suspended', 'banned', 'orphaned')),
    suspended_until  TIMESTAMPTZ,            -- NULL = indefinite; non-NULL = auto-reinstate at this time
    joined_at        TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    network_id       UUID        NOT NULL
);

-- Add columns for existing databases (safe to run multiple times)
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS fingerprint     TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMPTZ;

-- Columns added in trust-network milestone (idempotent migration guards).
-- Must be here (after nodes table) because source_node_id references nodes(id).
-- source_node_id: which trust-network node injected this record (NULL = pre-trust or unknown).
-- axfr_batch_sig: Ed25519 signature over the full AXFR batch (zone_id || serial || sorted names).
ALTER TABLE rpz_records ADD COLUMN IF NOT EXISTS source_node_id UUID REFERENCES nodes(id) ON DELETE SET NULL;
ALTER TABLE rpz_records ADD COLUMN IF NOT EXISTS axfr_batch_sig TEXT;

CREATE INDEX IF NOT EXISTS idx_rpz_records_source_node ON rpz_records (source_node_id)
    WHERE source_node_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_nodes_public_key  ON nodes (public_key);
CREATE INDEX IF NOT EXISTS idx_nodes_network_id  ON nodes (network_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status      ON nodes (status);

-- -------------------------------------------------------
-- Trust Network: peer discovery (local peer list)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS peers (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key   TEXT        UNIQUE NOT NULL,
    address      TEXT        NOT NULL,
    last_seen    TIMESTAMPTZ,
    trust_status TEXT        NOT NULL CHECK (trust_status IN ('trusted', 'pending', 'banned')),
    source       TEXT,
    network_id   UUID        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peers_network_id   ON peers (network_id);
CREATE INDEX IF NOT EXISTS idx_peers_trust_status ON peers (trust_status);

-- -------------------------------------------------------
-- Trust Network: append-only ledger (NEVER UPDATE/DELETE)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS trust_ledger (
    seq         BIGSERIAL   PRIMARY KEY,
    prev_hash   TEXT        NOT NULL,
    entry_hash  TEXT        UNIQUE NOT NULL,
    action      TEXT        NOT NULL CHECK (action IN (
                    'genesis', 'vouch', 'revoke', 'reinstate',
                    'role_upgrade', 'revoke_genesis', 'announce', 'purge_injected'
                )),
    subject_id  UUID        REFERENCES nodes(id),
    actor_id    UUID        REFERENCES nodes(id),
    payload     JSONB       NOT NULL,
    priority    BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trust_ledger_action     ON trust_ledger (action);
CREATE INDEX IF NOT EXISTS idx_trust_ledger_subject_id ON trust_ledger (subject_id);
CREATE INDEX IF NOT EXISTS idx_trust_ledger_priority   ON trust_ledger (priority) WHERE priority = true;

-- -------------------------------------------------------
-- Trust Network: signatures per ledger entry
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS trust_signatures (
    entry_hash  TEXT        NOT NULL REFERENCES trust_ledger(entry_hash),
    signer_id   UUID        NOT NULL REFERENCES nodes(id),
    signature   TEXT        NOT NULL,
    signed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_hash, signer_id)
);

-- -------------------------------------------------------
-- Trust Network: pending join requests
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS join_requests (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key    TEXT        NOT NULL,
    name          TEXT,
    role          TEXT        NOT NULL CHECK (role IN ('slave', 'master')),
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    received_via  UUID        REFERENCES nodes(id),
    signatures    INT         NOT NULL DEFAULT 0,
    required_sigs INT         NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ledger_seq    BIGINT      REFERENCES trust_ledger(seq)
);

CREATE INDEX IF NOT EXISTS idx_join_requests_status     ON join_requests (status);
CREATE INDEX IF NOT EXISTS idx_join_requests_public_key ON join_requests (public_key);
CREATE INDEX IF NOT EXISTS idx_join_requests_expires_at ON join_requests (expires_at);

-- -------------------------------------------------------
-- Trust Network: permanent blacklist (BAN)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS revoked_keys (
    public_key  TEXT        PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    reason      TEXT,
    ledger_seq  BIGINT      NOT NULL REFERENCES trust_ledger(seq)
);

-- -------------------------------------------------------
-- Trust Network: orphaned nodes in grace period
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS orphaned_nodes (
    node_id     UUID        NOT NULL REFERENCES nodes(id),
    orphaned_at TIMESTAMPTZ NOT NULL,
    grace_until TIMESTAMPTZ NOT NULL,
    cause_seq   BIGINT      NOT NULL REFERENCES trust_ledger(seq),
    adopted_by  UUID        REFERENCES nodes(id),
    adopted_at  TIMESTAMPTZ,
    PRIMARY KEY (node_id, cause_seq)
);

CREATE INDEX IF NOT EXISTS idx_orphaned_nodes_grace_until ON orphaned_nodes (grace_until)
    WHERE adopted_at IS NULL;

-- -------------------------------------------------------
-- Trust Network: revocation proposals (threshold voting)
-- A SUSPEND requires threshold_suspend votes.
-- A BAN requires threshold_ban votes.
-- Genesis node can execute unilaterally (recorded as 1 vote that meets threshold=1).
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS revocation_proposals (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id            UUID        NOT NULL REFERENCES nodes(id),
    action                TEXT        NOT NULL CHECK (action IN ('suspend', 'ban', 'reinstate')),
    reason                TEXT,
    status                TEXT        NOT NULL DEFAULT 'voting'
                                      CHECK (status IN ('voting', 'executed', 'rejected', 'expired')),
    votes                 INT         NOT NULL DEFAULT 0,
    required_votes        INT         NOT NULL,
    suspend_duration_hours INT,       -- NULL = indefinite suspend; only applies to action='suspend'
    expires_at            TIMESTAMPTZ NOT NULL,
    executed_at           TIMESTAMPTZ,
    ledger_seq            BIGINT      REFERENCES trust_ledger(seq),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE revocation_proposals ADD COLUMN IF NOT EXISTS suspend_duration_hours INT;

CREATE TABLE IF NOT EXISTS revocation_votes (
    proposal_id UUID        NOT NULL REFERENCES revocation_proposals(id),
    voter_id    UUID        NOT NULL REFERENCES nodes(id),
    voted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (proposal_id, voter_id)
);

CREATE INDEX IF NOT EXISTS idx_revocation_proposals_subject  ON revocation_proposals (subject_id);
CREATE INDEX IF NOT EXISTS idx_revocation_proposals_status   ON revocation_proposals (status);
CREATE INDEX IF NOT EXISTS idx_revocation_proposals_expires  ON revocation_proposals (expires_at)
    WHERE status = 'voting';

-- -------------------------------------------------------
-- Trust Network: revoke-genesis proposals (67% supermajority)
-- When executed: genesis node is downgraded to 'master'; trust chain intact.
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS revocation_genesis_proposals (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    reason         TEXT,
    status         TEXT        NOT NULL DEFAULT 'voting'
                               CHECK (status IN ('voting', 'executed', 'expired')),
    votes          INT         NOT NULL DEFAULT 0,
    required_votes INT         NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    executed_at    TIMESTAMPTZ,
    ledger_seq     BIGINT      REFERENCES trust_ledger(seq),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS revocation_genesis_votes (
    proposal_id UUID        NOT NULL REFERENCES revocation_genesis_proposals(id),
    voter_id    UUID        NOT NULL REFERENCES nodes(id),
    voted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (proposal_id, voter_id)
);

CREATE INDEX IF NOT EXISTS idx_revocation_genesis_status ON revocation_genesis_proposals (status)
    WHERE status = 'voting';

-- -------------------------------------------------------
-- Trust Network: role-upgrade proposals (slave → master)
-- Threshold = genesis_config.threshold_role_upgrade (default: 3)
-- Effect when executed: nodes.role updated to 'master'; ledger action='role_upgrade'
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_upgrade_proposals (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id     UUID        NOT NULL REFERENCES nodes(id),
    reason         TEXT,
    status         TEXT        NOT NULL DEFAULT 'voting'
                               CHECK (status IN ('voting', 'executed', 'expired')),
    votes          INT         NOT NULL DEFAULT 0,
    required_votes INT         NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    executed_at    TIMESTAMPTZ,
    ledger_seq     BIGINT      REFERENCES trust_ledger(seq),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS role_upgrade_votes (
    proposal_id UUID        NOT NULL REFERENCES role_upgrade_proposals(id),
    voter_id    UUID        NOT NULL REFERENCES nodes(id),
    voted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (proposal_id, voter_id)
);

CREATE INDEX IF NOT EXISTS idx_role_upgrade_status ON role_upgrade_proposals (status)
    WHERE status = 'voting';

-- Migration guards for role_upgrade tables (idempotent in older deployments)
ALTER TABLE role_upgrade_proposals ADD COLUMN IF NOT EXISTS ledger_seq BIGINT REFERENCES trust_ledger(seq);

-- -------------------------------------------------------
-- Trust Network: TOFU (Trust On First Use) fingerprint store
-- When a node first contacts a bootstrap peer, its TLS fingerprint is
-- recorded here. On subsequent connections the fingerprint is verified
-- without prompting the operator again — exactly like SSH known_hosts.
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS trusted_fingerprints (
    host        TEXT        PRIMARY KEY,   -- "ip:port" of the remote node
    fingerprint TEXT        NOT NULL,      -- "SHA256:<base64>" of genesis pubkey
    network_id  TEXT,                      -- network_id returned by that host
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
