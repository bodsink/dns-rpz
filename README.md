# rpzd

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A DNS RPZ enforcement server with a built-in distributed trust network — written in Go.**

Every node has a cryptographic identity. Membership is controlled by consensus. Zone data is signed and verified. No other DNS server does this.

---

## Why rpzd

BIND9 with RPZ at 8 million entries uses ~8 GB of RAM and spikes CPU during zone reload. The root cause is architectural — a general-purpose resolver stores RPZ records in the same data structures as everything else, carrying per-record overhead that compounds at scale.

rpzd uses a flat `map[string]string` in Go for the in-memory index. The lookup is a hashmap get. Zone reload is an atomic pointer swap. At ~17M entries (the Trustpositif Kominfo blocklist), memory sits at ~800 MB and reload happens in the background with zero query interruption.

The other reason rpzd exists: when TSIG is the only authentication mechanism, every node sharing the secret is one compromise away from injecting bad zone data into the entire fleet. rpzd gives each node an Ed25519 keypair, signs AXFR batches, and controls membership via threshold voting — a compromised node is voted out without touching config on any other node.

A few other things worth mentioning:

- SIGHUP reloads the index, ACL, upstream pool, and RRL atomically — no query interruption, no restart window
- IXFR with SOA serial pre-check — at 17M records, the difference vs full AXFR is ~1,085× in transfer time
- Dashboard for zone management instead of zone files and `rndc reload`
- Single-binary deploy: `make install SERVER=root@ip` provisions everything from scratch
- Two static binaries, no runtime dependencies beyond PostgreSQL

**RFC support**

Every standard that applies to a forwarding RPZ server:

| RFC | Title | Status |
|---|---|---|
| RFC 1035 | Domain Names — Implementation and Specification | ✅ Strict FORMERR on malformed queries |
| RFC 1995 | Incremental Zone Transfer (IXFR) | ✅ Delta sync with AXFR fallback |
| RFC 1996 | DNS NOTIFY | ✅ Master-triggered immediate sync |
| RFC 2308 | Negative Caching — SOA MINIMUM | ✅ |
| RFC 5936 | DNS Zone Transfer (AXFR) | ✅ Full zone transfer + TSIG |
| RFC 6891 | EDNS0 — Extension Mechanisms for DNS | ✅ Payload negotiation, DO bit |
| RFC 7766 | DNS Transport over TCP | ✅ UDP + TCP concurrent, TC fallback |



---

## Background

DNS Response Policy Zones (RPZ) are widely used by ISPs, enterprises, and security teams to enforce domain-level policies — blocking malware, phishing, ad networks, or regulatory blocklists distributed via AXFR from a central master.

The standard approach is to deploy BIND9 or Unbound with RPZ support. Both work well at modest scale, but show significant strain when the blocklist grows into the millions of entries:

**BIND9 with RPZ**
- Memory consumption approaches or exceeds 8 GB at ~8 million entries
- CPU spikes heavily during zone transfer and reload, disrupting query processing
- Zone reload (AXFR) can block queries for several minutes
- Configuration is complex and fragile at this scale

**Unbound with RPZ**
- Similar memory profile — the implementation loads all records into memory in a format designed for general DNS resolution, not mass blocklist lookup
- At large scale, RSS exceeds available RAM and the process is killed by the OOM killer
- Reload requires a full restart, causing downtime

Both are excellent general-purpose DNS servers. The problem is that RPZ enforcement at millions of entries is not what they were optimized for. Their internal data structures carry per-record overhead that compounds at scale.

### Why rpzd

The core operation is simple: given a queried domain, is it in the blocklist? If yes, apply the policy. If no, forward upstream. That is a hashmap lookup.

rpzd stores all RPZ entries in a single `map[string]string` in Go, loaded from PostgreSQL at startup. No zone file parsing overhead, no general-purpose resolver machinery — just the lookup path and forwarding logic:

| Metric | BIND9 / Unbound | rpzd |
|---|---|---|
| Memory at 8M entries | ~8 GB (OOM in practice) | ~800 MB |
| Startup / RPZ load time | 3–10 minutes | < 35 seconds |
| CPU during zone reload | 100% spike, queries disrupted | Background goroutine, atomic index swap |
| Config complexity | `named.conf` / `unbound.conf` with RPZ directives | Single `.env` file |
| Observability | Requires external log tooling | Structured logging + built-in audit log |
| Deployment | Package manager / manual | `make deploy` — single static binary via SCP |

Beyond the DNS engine, rpzd adds a full web dashboard, multi-zone management, and a distributed trust network for multi-node deployments — all in a single self-contained binary pair.

### Zone sync benchmark (measured)

The following numbers were measured against the `trustpositifkominfo` RPZ zone served by `139.255.196.202`, pulled from a server in the same region:

| Measurement | Value |
|---|---|
| Total records in zone | 17,748,271 |
| PostgreSQL table size | 9,962 MB (~10 GB) |
| Average record size (name + rtype + rdata) | 54 bytes |
| IXFR delta: 102 serials (26041700 → 26041802) | 16,360 records |
| IXFR transfer time (16K records, TCP) | **278 ms** |

**Full AXFR vs IXFR at this scale:**

| | Full AXFR | IXFR (incremental) |
|---|---|---|
| Records processed | 17,748,271 | ~16,360 per 102-serial delta |
| Wire data transferred | ~2.1 GB | ~1 MB |
| PostgreSQL batch upserts | 1,775 | 2 |
| Transfer time | ~5 minutes | **278 ms** (measured) |
| Efficiency ratio | baseline | **~1,085× faster** |

rpzd implements **both AXFR and IXFR (RFC 1995)**. On each sync cycle, rpzd first checks the SOA serial — if unchanged, the transfer is skipped entirely. If the master supports IXFR, rpzd requests only the delta since the last known serial, applying adds and deletes incrementally in a single PostgreSQL transaction. Full AXFR is used as fallback when the master does not support IXFR or when a full refresh is needed.

---

## How It Works

```
Client query
    │
    ▼
ACL check ── not allowed ──► REFUSED
    │
    ▼
RPZ in-memory index lookup
    ├── exact match ──► apply RPZ action (NXDOMAIN / NODATA / walled garden)
    ├── wildcard match ──► apply RPZ action
    └── no match
            │
            ▼
        Response cache check
            ├── cache hit ──► return cached response (TTL adjusted)
            └── cache miss
                    │
                    ▼
                Upstream resolver pool
                    │
                    ▼
                Store in cache ──► return to client
```

**Startup flow:**
1. Load bootstrap config from `.env` file
2. Connect to PostgreSQL (pgxpool)
3. Run schema migration (idempotent, advisory lock)
4. Load active CIDR ranges into ACL
5. Load all RPZ records into in-memory hashmap (~7.8M entries in ~800 MB)
6. Start DNS server (UDP + TCP on port 53)
7. Start AXFR/IXFR sync scheduler (periodic pull from RPZ master)

**Sync flow (AXFR/IXFR):**
- Scheduler runs every `sync_interval` seconds (default: 24 hours)
- SOA serial pre-check — skips transfer entirely if serial is unchanged
- If master supports IXFR: request delta since last serial, apply adds/deletes in a single PostgreSQL transaction
- If master returns full AXFR (IXFR not supported): bulk upsert into PostgreSQL
- Atomic in-memory index replacement (zero downtime during sync)
- Automatic fallback to secondary master IP if primary fails
- NOTIFY (RFC 1996): master can signal an immediate sync; rpzd processes the NOTIFY and triggers a sync outside the normal schedule

---

## Features

### Trust Network

rpzd has a built-in peer-to-peer trust network. Every node holds an Ed25519 keypair as its identity. Zone transfers are signed by the sender and verified by the receiver. Node membership is controlled by threshold voting across active peers — no node joins without quorum approval, and a compromised node is revoked by vote without touching config anywhere else.

The motivation is covered in [Why rpzd](#why-rpzd) above. The short version: TSIG is a shared secret. If it leaks, every node holding it needs manual reconfiguration. With per-node Ed25519 keys, revoking one node doesn't affect any other.

**How it works:**

```
Node A (genesis) — creates network, self-signs first ledger entry
    │
    ├── Node B wants to join → sends join request to any known peer
    │       │
    │       ├── Peers broadcast request via gossip
    │       ├── Existing nodes vote (threshold: e.g. 2 of N)
    │       └── When quorum reached → ledger entry appended → Node B active
    │
    └── Gossip loop (every 30s, 3 random peers)
            └── Pull ledger entries since local max seq → verify hash chain → apply
```

**Components:**

| Component | Description |
|---|---|
| Ed25519 keypair | Node identity, generated on first start, stored in `node.key` |
| Genesis entry | Root of trust — self-signed by the founding node, embeds consensus thresholds for the entire network |
| Hash-chain ledger | Append-only log of membership events; SHA-256 links each entry to the previous, tampering breaks the chain |
| Threshold voting | Configurable quorum per action type (defaults: join_slave=2, join_master=3, ban=3, revoke_genesis=67%) |
| Gossip | Ledger sync every 30s to 3 random peers, up to 500 entries/pull; revocation entries pushed immediately |
| AXFR batch signing | Each zone transfer signed over SHA-256(zone_id \|\| serial \|\| sorted record names) |
| Revocation | Suspend (with optional auto-reinstate) or permanent ban via vote |
| Node roles | `genesis` (root of trust), `master` (serves zones), `slave` (pulls zones) |
| Effective threshold | Quorum scales to `min(genesis_threshold, active_nodes)` — a 2-node network doesn't require 3 votes |
| Peer auth | TLS transport, identity verified via Ed25519 pubkey (TOFU — not TLS certificate) |

**Who can use this and how:**

The trust network supports two distinct deployment models:

**1. Single organization — multi-node**

An ISP, enterprise, or university running rpzd at multiple locations (data centers, PoPs, branch offices) forms a private trust network. All nodes are under the same administrative ownership, but no node is unconditionally trusted — membership is enforced cryptographically. A compromised node at one site cannot be used to inject malicious zone data into other sites.

| Use Case | Example |
|---|---|
| ISP with multiple PoPs | Jakarta, Surabaya, Medan nodes share the same RPZ blocklist |
| University campus network | Central gateway + per-faculty DNS all enforce the same policy |
| Enterprise with branch offices | HQ-managed blocklist automatically propagated to all branches |
| CDN/hosting provider | Customer-facing resolvers in multiple regions stay in sync |

**2. Multiple organizations — shared threat intelligence (consortium)**

Multiple independent organizations (e.g., a group of ISPs, a national CSIRT, a regional network security alliance) can each run their own rpzd nodes and form a shared trust network. They collectively maintain a distributed RPZ blocklist — each contributor adds domains they have identified as malicious, and all members enforce the combined list.

```
ISP-A (genesis)
    │
    ├── ISP-B joins (votes: ISP-A approves, quorum met)
    ├── ISP-C joins (votes: ISP-A + ISP-B approve)
    ├── CSIRT-National joins (votes: 2 of 3 approve)
    │
    └── All nodes now share the same RPZ ledger
         ├── ISP-A adds phishing domains from its abuse desk
         ├── ISP-B adds C2 infrastructure it observed
         ├── CSIRT-National adds domains from national threat feeds
         └── All members enforce the combined list, in real time
```

If one member's node is compromised, the others vote to revoke it — no manual reconfiguration needed anywhere else.

**Comparison with BIND9 + TSIG:**

| Capability | BIND9 + TSIG | rpzd Trust Network |
|---|---|---|
| Zone data authentication | Shared secret (TSIG) | Ed25519 per-node keypair |
| Add new peer | Manual config change on all nodes | Vote-based, propagated via gossip |
| Remove compromised peer | Manual config change on all nodes | Vote to ban, propagated via gossip |
| Multi-organization sharing | Ad-hoc, no governance | Built-in consensus and audit log |
| Tamper detection | None | Hash-chain ledger |
| Shared threat intelligence | Not supported | Native via shared ledger |
| Small network quorum | N/A | Auto-scales to available nodes |
| Peer authentication | TLS cert / IP-based | Ed25519 public key (TOFU) |

The trust network is **optional**. A single-node deployment works without any of this — `NODE_ROLE=slave` is the default, and the trust features are only activated when `NODE_BOOTSTRAP_IP` is configured or `NODE_ROLE=genesis` is set.

---

### DNS Engine

rpzd is not just an RPZ enforcer — it is a full DNS server. It handles three distinct roles simultaneously:

**1. RPZ Policy Enforcer (Forwarder)**
Queries are checked against the in-memory RPZ index first. Matching domains get an immediate policy response (NXDOMAIN, NODATA, or CNAME redirect to a walled garden) without touching the upstream resolver.

**2. Authoritative DNS Server**
rpzd can host your own DNS zones directly — no separate BIND9 or PowerDNS needed. Add a `domain` zone (e.g. `example.com`) and manage its records. rpzd will answer authoritatively for those names, returning SOA in the authority section for NXDOMAIN and NODATA responses, just like any standard authoritative server.

**3. Reverse DNS (PTR) Server**
rpzd also serves reverse lookup zones (`reverse_ptr` type, e.g. `1.168.192.in-addr.arpa`). Add your PTR records and rpzd answers `PTR` queries authoritatively. This allows you to run forward and reverse DNS for your own infrastructure from the same server.

For anything not covered by RPZ or authoritative zones, queries are forwarded to the configured upstream resolvers.

- RPZ enforcement with O(1) in-memory index (pre-allocated for 1M+ entries)
- RPZ actions: `NXDOMAIN`, `NODATA`, or CNAME redirect (walled garden)
- Authoritative zone serving for `domain` and `reverse_ptr` zone types
- NXDOMAIN and NODATA responses include SOA in the authority section (RFC 2308 — negative caching TTL from SOA MINIMUM)
- Outbound AXFR serving (act as zone master for slave nodes)
- Incremental zone transfer: **IXFR (RFC 1995)** with SOA serial pre-check — falls back to AXFR automatically
- NOTIFY support (RFC 1996): master NOTIFY triggers immediate sync outside normal schedule
- EDNS0 (RFC 6891): client payload size negotiation, DO bit propagation and cache separation
- Per-source IP response rate limiting (RRL) — token bucket, configurable rate + burst, hot-reloadable
- Upstream forwarding with three strategies: `roundrobin`, `random`, `race`
- TTL-aware LRU response cache; DO bit included in cache key (DNSSEC-aware)
- IP-based ACL (CIDR ranges) for recursion control
- Wildcard label walk for RPZ matching
- Per-query audit logging
- SIGHUP reload — index, ACL, upstream, RRL, log settings, all without restart
- TCP fallback on truncated UDP responses
- RFC-compliant error handling: FORMERR on malformed queries (zero questions, multiple questions), correct RA/AA bit placement per response type

### Zone Management
- Zone types: `rpz` (blocklist), `domain` (authoritative forward zone), `reverse_ptr` (PTR/reverse zone)
- Zone modes: `master` (serve records from DB) or `slave` (pull via AXFR from external master)
- Primary + secondary master IP per zone (high availability)
- TSIG authentication per zone
- Configurable sync interval per zone
- Manual sync trigger from dashboard

### Web Dashboard
- HTTPS only (auto-generated self-signed ECDSA P-256 certificate)
- Session-based authentication (cookie, 24-hour expiry, stored in PostgreSQL)
- CSRF protection + rate limiting on login (5 req/min per IP)
- Role-based access control: `admin` (full access) and `viewer` (read-only)
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, etc.

**Dashboard pages:**

| Page | Function |
|---|---|
| Dashboard | Stats overview + live system resources (CPU/RAM/disk, 5s refresh) |
| Zones | Zone CRUD + sync trigger |
| Zone Detail | Zone metadata + recent sync history |
| Records | View records per zone |
| Sync History | Global AXFR sync audit trail |
| Settings → General | DNS upstream, RPZ action, sync config, logging |
| Settings → DNS | DNS server parameters |
| Settings → API Tokens | Generate JWT tokens for REST API access |
| Users | User CRUD + role management |
| IP Filters | Recursive query ACL (CIDR-based, not global DNS ACL) |
| Statistics | Query log with charts |
| Trust Nodes | Distributed trust network management |

### Operational
- Config hot-reload via SIGHUP (no restart needed for most changes)
- Structured logging (`log/slog`) with runtime level/format changes
- Optional log file output with auto-generated logrotate config
- Audit log: per-query logging of client IP, domain, result, RTT
- Sync history: per-zone AXFR attempt log with records added/removed
- System stats API: CPU%, memory, disk, DNS health check

---

## Architecture

```
cmd/
├── rpzd/
│   ├── main.go          — wiring: config, DB, index, ACL, upstream, server, SIGHUP handler
│   └── logger.go        — slog multiHandler (stdout + file tee), runtime LevelVar
└── rpzd-dashboard/
    ├── main.go          — wiring: config, DB, syncer, trust, HTTP server
    └── logger.go        — slog logger for dashboard

internal/
├── dns/
│   ├── server.go        — DNS query handler (RPZ enforcement, ACL, EDNS0, NOTIFY, audit log)
│   ├── index.go         — thread-safe in-memory hashmap (RWMutex), ACL checker
│   ├── authindex.go     — authoritative zone index (domain/reverse_ptr)
│   ├── upstream.go      — upstream pool (roundrobin/random/race, TCP fallback, RTT tracking)
│   ├── cache.go         — TTL-aware LRU response cache; DO bit in key (hashicorp/golang-lru/v2)
│   └── rrl.go           — per-source IP response rate limiter (token bucket, golang.org/x/time/rate)
├── api/
│   ├── router.go        — HTTP server, routing, middleware, template renderer
│   ├── auth.go          — login/logout, session management
│   ├── middleware.go    — session/JWT check, role guard, CSRF, rate limit, security headers
│   ├── rest.go          — JSON REST API handlers (zones, records, IP filters, /me)
│   ├── apitokens.go     — dashboard UI handlers for API token management
│   ├── crypto.go        — RSA-2048 keygen, AES-256-GCM encrypt/decrypt, JWT RS256 sign/verify
│   ├── stats.go         — dashboard overview + /api/system-stats (CPU/mem/disk/DNS)
│   ├── zones.go         — zone CRUD, toggle, sync trigger, zone detail
│   ├── records.go       — record list per zone
│   ├── ipfilters.go     — ACL CIDR CRUD
│   ├── synchistory.go   — global sync history view
│   ├── settings.go      — read/save app settings, signal DNS/self for reload
│   ├── users.go         — user CRUD, role management, password change
│   ├── trust.go         — trust network node-to-node API routes
│   ├── trustui.go       — trust network dashboard UI routes
│   └── tls.go           — auto-generate self-signed TLS certificate
├── store/
│   ├── db.go            — pgxpool connection, schema migration (advisory lock)
│   ├── zone.go          — zone CRUD
│   ├── record.go        — RPZ record bulk upsert/delete, AXFR serving, cursor pagination
│   ├── settings.go      — app settings key/value store
│   ├── ipfilter.go      — CIDR ACL management
│   ├── user.go          — user CRUD + session management
│   ├── querylog.go      — DNS query log writes + reads
│   └── synchistory.go   — AXFR sync history tracking
├── syncer/
│   └── syncer.go        — AXFR client, zone sync scheduler, per-zone mutex
└── trust/
    ├── keypair.go       — Ed25519 key generation, signing, batch signing, fingerprint
    ├── genesis.go       — genesis entry creation and validation
    ├── ledger.go        — append-only hash-chain ledger (serializable tx)
    ├── consensus.go     — threshold voting (absolute + percentage thresholds)
    ├── gossip.go        — gossip loop, peer exchange, ledger pull
    ├── verifier.go      — Ed25519 signature verification for ledger entries
    ├── revocation.go    — node suspend/ban/reinstate via voting
    └── bootstrap.go     — node startup: genesis init or join existing network

assets/
├── templates/           — HTML templates (base layout + per-page, HTMX partials)
└── static/              — CSS, JS (Alpine.js, htmx, Flowbite/Tailwind)

config/
└── config.go            — .env parser, BootstrapConfig, AppSettings

db/
├── schema.sql           — PostgreSQL schema (embedded via go:embed)
└── seed.go              — default settings + initial admin user seeding
```

**Tech stack:**

| Component | Library |
|---|---|
| DNS server + AXFR client | `github.com/miekg/dns` |
| PostgreSQL driver + pool | `github.com/jackc/pgx/v5` (pgxpool) |
| Response cache | `github.com/hashicorp/golang-lru/v2` |
| HTTP framework | `github.com/gin-gonic/gin` |
| JWT (REST API) | `github.com/golang-jwt/jwt/v5` (RS256) |
| Frontend | Alpine.js + htmx + Flowbite (Tailwind) |
| Config | Pure Go `.env` parser (no external dependency) |
| Logging | `log/slog` (stdlib) |
| Cryptography | `crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa` (stdlib) |

---

## Requirements

- Go 1.25+
- PostgreSQL 14+
- Linux (systemd for production deployment)
- SSH access to production server (for `make deploy`)

> **Tested in production:** Debian 13 (Trixie)

---

## Quick Start

### 1. Configure

```bash
cp rpzd.conf.example rpzd.conf
# Edit rpzd.conf — set DATABASE_DSN at minimum
```

### 2. Build

```bash
make build
# Output: bin/rpzd  bin/rpzd-dashboard
```

### 3. First-time deploy

```bash
make install SERVER=root@your-server-ip
# Provisions PostgreSQL, generates TLS cert, writes rpzd.conf, starts services
```

### 4. Subsequent deploys

```bash
make deploy SERVER=root@your-server-ip   # upload binaries + assets
make restart SERVER=root@your-server-ip  # deploy + restart services + tail logs
```

---

## Configuration

### Bootstrap config (`rpzd.conf`)

The same `.env` file is used by both binaries (`rpzd` and `rpzd-dashboard`). It contains only the minimum values needed before the database connection is available. All other settings are managed via the dashboard and stored in the database.

| Key | Default | Description |
|---|---|---|
| `DATABASE_DSN` | *(required)* | PostgreSQL connection string |
| `DATABASE_MAX_CONNS` | `20` | Maximum DB pool connections |
| `DATABASE_MIN_CONNS` | `2` | Minimum idle DB connections |
| `DNS_ADDRESS` | `0.0.0.0:53` | DNS server listen address (UDP+TCP) |
| `HTTP_ADDRESS` | `0.0.0.0:8080` | Dashboard listen address |
| `TLS_CERT_FILE` | `./certs/server.crt` | TLS certificate path |
| `TLS_KEY_FILE` | `./certs/server.key` | TLS private key path |
| `LOG_LEVEL` | `info` | Initial log level before DB settings are loaded |
| `PID_FILE` | `/run/rpzd/rpzd.pid` | PID file path (used by dashboard to signal DNS process) |
| `ADMIN_INIT_PASSWORD` | — | Initial admin password (first run only, ignored afterwards) |
| `NODE_ROLE` | `slave` | Trust network role: `genesis`, `master`, or `slave` |
| `NODE_KEY_PATH` | `./node.key` | Ed25519 private key path |
| `NODE_BOOTSTRAP_IP` | — | `ip:port` of a known peer to join on first start |
| `NODE_ADVERTISE_ADDR` | — | Public address advertised to peers (required behind NAT) |

### App settings (stored in PostgreSQL)

Managed via the **Settings** page in the dashboard. Most changes take effect immediately via SIGHUP — no restart required.

**Sync**

| Key | Default | Hot-reload |
|---|---|---|
| `mode` | `slave` | — |
| `master_ip` | — | — |
| `master_port` | `53` | — |
| `tsig_key` | — | — |
| `tsig_secret` | — | — |
| `sync_interval` | `86400` | ✅ |

**DNS**

| Key | Default | Hot-reload |
|---|---|---|
| `dns_upstream` | `8.8.8.8,8.8.4.4` | ✅ |
| `dns_upstream_strategy` | `roundrobin` | ✅ |
| `rpz_default_action` | `nxdomain` | ✅ |
| `dns_cache_size` | `100000` | ❌ restart required |
| `dns_audit_log` | `false` | ✅ |
| `rrl_rate` | `0` (disabled) | ✅ |
| `rrl_burst` | `0` (disabled) | ✅ |

**Logging**

| Key | Default | Hot-reload |
|---|---|---|
| `log_level` | `info` | ✅ |
| `log_format` | `text` | ✅ |
| `log_file` | `false` | ✅ |
| `log_file_path` | `/var/log/rpzd/rpzd.log` | ✅ |
| `log_rotate` | `false` | — |
| `log_rotate_size` | `100M` | — |
| `log_rotate_keep` | `7` | — |

---

## REST API

rpzd exposes a JSON REST API under `/api/` for programmatic access — scripting zone management, automation pipelines, or integration with external systems.

### Authentication

The REST API uses **JWT RS256** bearer tokens. Each user has a unique RSA-2048 keypair. Tokens are signed with the user's private key and verified with their corresponding public key stored in the database. Private keys are encrypted at rest with AES-256-GCM.

**Prerequisites:** `KEY_ENCRYPTION_KEY` must be set in `rpzd.conf` (generated automatically by `make install`).

**Generate a token:**
1. Log in to the dashboard → go to **Settings → API Tokens**
2. Click **Generate Keypair** (first time only — one keypair per user)
3. Enter a token name and pick an expiry date → click **Generate Token**
4. Copy the token immediately — it is shown only once

**Use in requests:**
```http
Authorization: Bearer <token>
```

### Endpoint Reference

All endpoints are prefixed with `/api/`. Admin-only endpoints require `role=admin` in the JWT.

#### Identity

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/me` | Any | Current user identity (id, username, role) |

#### Zones

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/zones` | Any | List all zones |
| `GET` | `/api/zones/:id` | Any | Get zone by ID |
| `POST` | `/api/zones` | Admin | Create zone |
| `PUT` | `/api/zones/:id` | Admin | Update zone |
| `DELETE` | `/api/zones/:id` | Admin | Delete zone |
| `POST` | `/api/zones/:id/toggle` | Admin | Toggle enabled / disabled |
| `POST` | `/api/zones/:id/sync` | Admin | Trigger immediate AXFR/IXFR sync |

**Create / Update zone body:**
```json
{
  "name": "example-rpz",
  "zone_type": "rpz",
  "mode": "slave",
  "master_ip": "1.2.3.4",
  "master_ip_secondary": "",
  "master_port": 53,
  "tsig_key": "",
  "tsig_secret": "",
  "sync_interval": 3600
}
```

> `tsig_secret` is write-only. All zone responses return `"tsig_secret_set": true/false` instead of the secret value.

#### Records

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/zones/:id/records` | Any | List records in zone |
| `POST` | `/api/zones/:id/records` | Admin | Create record |
| `DELETE` | `/api/zones/:id/records/:rid` | Admin | Delete record |

**Create record body:**
```json
{
  "name": "malware.example.com",
  "type": "CNAME",
  "value": "rpz-passthru.",
  "ttl": 300
}
```

#### IP Filters

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/ipfilters` | Any | List IP filters |
| `POST` | `/api/ipfilters` | Admin | Add CIDR range |
| `DELETE` | `/api/ipfilters/:id` | Admin | Remove CIDR range |
| `POST` | `/api/ipfilters/:id/toggle` | Admin | Toggle enabled / disabled |

**Create IP filter body:**
```json
{
  "cidr": "10.0.0.0/8",
  "description": "Internal clients"
}
```

### Response Format

Success responses use the body directly (object or array). Empty success responses use `204 No Content`.

All errors return:
```json
{ "error": "message" }
```

HTTP status codes: `200`, `201`, `204`, `400`, `401`, `403`, `404`, `500`.

---

## Operations

### Reload without restart

```bash
systemctl reload rpzd
```

What reloads on SIGHUP to `rpzd`:
- `log_level`, `log_format`, `log_file`, `log_file_path` — atomically swapped
- `dns_audit_log` — atomically toggled
- `rpz_default_action` — atomically applied
- `rrl_rate`, `rrl_burst` — per-IP rate limiter atomically replaced (old limiter stopped gracefully)
- ACL CIDR list — reloaded from PostgreSQL
- RPZ index — full reload from PostgreSQL (atomic swap, zero downtime)
- `dns_upstream` + `dns_upstream_strategy` — upstream pool atomically swapped

What **requires a full restart**: `DNS_ADDRESS`, `DATABASE_DSN`, `dns_cache_size`, `TLS_CERT_FILE`, `TLS_KEY_FILE`

### View logs

```bash
# Live
journalctl -u rpzd -f

# Audit log only
journalctl -u rpzd -f | grep audit

# Blocked queries only
journalctl -u rpzd -f | grep result=blocked

# Last 50 lines
journalctl -u rpzd --no-pager -n 50

# Allowed vs blocked count (last 5 minutes)
journalctl -u rpzd --since '5 minutes ago' \
  | grep audit \
  | awk '{for(i=1;i<=NF;i++) if($i~/result=/) print $i}' \
  | sort | uniq -c | sort -rn
```

### Systemd services

```
rpzd.service            — DNS server (port 53)
rpzd-dashboard.service  — Web dashboard (HTTPS)
```

```bash
systemctl status rpzd rpzd-dashboard
systemctl restart rpzd
systemctl reload rpzd      # SIGHUP — reloads index, ACL, upstream, log settings
```

---

## Database Schema

Key tables:

| Table | Purpose |
|---|---|
| `rpz_zones` | Zone definitions (name, type, mode, master IP, TSIG, sync interval) |
| `rpz_records` | DNS records (zone_id, name, rtype, rdata, TTL) — indexed for bulk upsert |
| `settings` | App-wide key/value configuration |
| `users` | Dashboard users (bcrypt passwords, roles, sessions) |
| `sessions` | Cookie sessions (user_id, expires_at, IP, user agent) |
| `ip_filters` | ACL CIDR ranges for DNS recursion control |
| `sync_history` | AXFR sync attempts (status, records added/removed, error) |
| `dns_query_log` | Per-query audit log (client IP, domain, result, RTT) |
| `user_keypairs` | Per-user RSA-2048 keypairs (public key PEM + AES-256-GCM encrypted private key) |
| `api_tokens` | JWT token metadata (name, JTI, expiry, last used — JWT itself is never stored) |
| `nodes` | Trust network node registry |
| `trust_ledger` | Append-only hash-chain ledger |
| `trust_signatures` | Per-entry Ed25519 signatures |
| `trust_join_requests` | Pending join requests with vote tracking |
| `revocation_proposals` | Node suspend/ban proposals with vote tracking |

---

## Security Notes

- Dashboard is HTTPS-only. A self-signed ECDSA P-256 certificate is auto-generated if none is provided.
- Passwords are hashed with bcrypt (12 rounds).
- Sessions are stored server-side in PostgreSQL with IP and user-agent tracking.
- DNS ACL defaults to **deny all** when no CIDR is configured.
- REST API uses JWT RS256 with per-user RSA-2048 keypairs — a token cannot be forged for another user's key.
- RSA private keys are stored AES-256-GCM encrypted in the database using `KEY_ENCRYPTION_KEY`.
- JWT tokens are never stored server-side; only metadata (JTI, expiry) is kept for revocation and audit.
- TSIG secrets are write-only — API responses replace the value with `tsig_secret_set: bool`.
- Trust network messages are signed with Ed25519 and verified on receipt.
- The ledger hash chain makes tampering detectable.

---

## License

[MIT](LICENSE)
