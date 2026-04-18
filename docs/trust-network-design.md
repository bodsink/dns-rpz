# DNS-RPZ Trust Network Design

## Overview

Sistem trust antar node menggunakan model **blockchain-style distributed ledger** dengan:
- Ed25519 keypair sebagai identitas node
- Hash-chained append-only ledger (tamper-evident)
- Threshold signatures untuk consensus (bukan mining)
- Gossip protocol untuk sync state antar peer
- Tidak ada central registry server

---

## Desain Join Flow

### Step 0 — GENESIS

Node pertama dalam jaringan. Self-sign entry sebagai root of trust.

```
dns-rpz.conf:
  NODE_ROLE=genesis
```

**Genesis entry structure:**
```json
{
  "seq": 1,
  "prev_hash": "0000000000000000",
  "action": "genesis",
  "network_id": "uuid-unik-jaringan",
  "genesis_pubkey": "base64...",
  "network_config": {
    "threshold_join_slave":    2,
    "threshold_join_master":   3,
    "threshold_role_upgrade":  3,
    "threshold_suspend":       2,
    "threshold_ban":           3,
    "threshold_reinstate":     3,
    "threshold_revoke_genesis": "67%",
    "grace_period_hours":      72
  },
  "signatures": ["sig_genesis_self"],
  "created_at": "2026-04-18T00:00:00Z",
  "hash": "aabbcc..."
}
```

**Aturan:**
- Hanya boleh ada SATU genesis per jaringan
- Node hanya terima peer dengan `network_id` yang sama
- Dua genesis = dua jaringan terpisah, tidak saling kenal
- Genesis config berlaku seragam untuk seluruh jaringan — tidak bisa di-override per node

---

### Step 1 — INSTALL

Saat pertama kali deploy, app otomatis generate keypair tanpa manual command.

```
App start
    ↓
Cek: ada file node.key ?
    ↓ TIDAK                    ↓ YA
Generate Ed25519 keypair       Load keypair dari disk
Simpan ke disk (mode 0600)     Lanjut normal
Log public key + WARN backup
Lanjut normal
```

**Storage:**
```
/opt/dns-rpz/node.key    ← disimpan di direktori aplikasi
```

**Config:**
```
NODE_KEY_PATH=./node.key
```

**Behavior penting:**
| Kondisi | Yang Terjadi |
|---------|-------------|
| First start, file belum ada | Generate otomatis, log public key |
| Restart normal | Load dari file, keypair sama |
| File terhapus | Generate keypair BARU → identitas baru → harus join ulang |
| File corrupt | Error + exit, JANGAN auto-overwrite |

**Log saat pertama generate:**
```
INFO  Node identity created
INFO  Public key: base64xyz...
WARN  IMPORTANT: Backup /etc/dns-rpz/node.key
WARN  Losing this file means losing your node identity permanently
```

---

### Step 2 — BOOTSTRAP

User input satu IP node trusted (dari komunitas, forum, dll).

**Request:**
```
POST https://node-trusted.example.com/trust/join
{
  "public_key":  "base64...",
  "name":        "my-node",
  "role":        "slave",
  "network_id":  "uuid-jaringan"
}
```

**Response:**
```json
{
  "join_request_id":  "uuid-xxx",
  "node_fingerprint": "SHA256:abc123...",
  "expires_at":       "2026-04-19T10:00:00Z"
}
```

**TOFU (Trust On First Use):**

Saat kontak pertama, tampilkan fingerprint node trusted di log:
```
Connecting to node: SHA256:abc123...
Verify this fingerprint matches the node you intend to connect to.
Accept? [yes/no]:
```
Persis seperti SSH first connection. Setelah diterima, fingerprint disimpan lokal — tidak ditanya lagi.

---

### Step 3 — BROADCAST

Node yang menerima join request menyebarkan ke semua peer yang dikenalnya.

```
Node A terima join request dari Node Baru
    ↓
Simpan join request di DB (status: pending)
    ↓
Kirim ke semua peer di tabel peers lokal
POST /trust/pending { join_request_data }
    ↓
Tiap peer simpan lokal → forward ke peer mereka (gossip)
    ↓
Dalam ~30 detik: seluruh jaringan tahu ada pending request
```

**Data yang disebarkan:**
```json
{
  "type":            "join_request",
  "id":              "uuid-xxx",
  "subject_pubkey":  "base64_pubkey_node_baru",
  "subject_name":    "my-node",
  "subject_role":    "slave",
  "requested_at":    "2026-04-18T10:00:00Z",
  "requested_via":   "pubkey_node_A",
  "expires_at":      "2026-04-19T10:00:00Z",
  "signatures":      []
}
```

---

### Step 4 — VOTING

Trusted nodes yang online bisa sign approval via dashboard.

```
Dashboard tiap node:
┌─────────────────────────────────────────┐
│ Pending Join Requests                   │
│                                         │
│ [my-node] slave - 5 menit lalu          │
│ Signatures: 1/2 terkumpul               │
│                                         │
│ [APPROVE & SIGN]  [REJECT]              │
└─────────────────────────────────────────┘
```

**Signing:**
```
signature = Ed25519Sign(private_key_voter, SHA256(join_request_id + subject_pubkey + expires_at))
```

Setiap signature baru langsung di-gossip ke peers — threshold dihitung lokal tiap node secara independen.

---

### Step 5 — THRESHOLD TERPENUHI

Threshold ditentukan oleh genesis config:
- `slave join` → 2 signatures
- `master join` → 3 signatures

**Adaptive threshold** untuk jaringan kecil:
```
effective_threshold = min(genesis_config.threshold, total_active_trusted_nodes)
```

Saat threshold terpenuhi, setiap node secara independen membuat ledger entry:
```json
{
  "seq":            43,
  "prev_hash":      "a3f9b2...",
  "action":         "vouch",
  "subject_pubkey": "XYZ...",
  "subject_role":   "slave",
  "permissions":    ["can_slave"],
  "signatures": [
    {"signer": "pubkey_A", "sig": "sig_A"},
    {"signer": "pubkey_B", "sig": "sig_B"}
  ],
  "created_at":     "2026-04-18T10:05:00Z",
  "hash":           "b7c1d4..."
}
```

**Polling status oleh node baru (setiap 30 detik):**
```
GET /trust/status/{join_request_id}
← { "status": "pending",  "signatures": 1, "required": 2 }
← { "status": "approved"                                  }
← { "status": "expired"                                   }
```

**Jika expired:**
```
App log: "Join request expired. Submit a new request to retry."
→ Kembali ke Step 2
```

---

### Step 6 — GOSSIP

Ledger entry menyebar ke seluruh jaringan via gossip periodik.

**Algoritma gossip (setiap 30 detik):**
```
1. Pilih 3 peer random dari tabel peers
2. GET /trust/ledger?since_seq={local_max_seq}
3. Terima entries yang belum dimiliki
4. Verifikasi hash chain tiap entry
5. Verifikasi semua signatures
6. Jika valid → simpan ke DB lokal
7. Update last_seen peer
```

Dalam ~30 detik setelah threshold terpenuhi, seluruh jaringan mengenali node baru.

---

### Step 7 — ACTIVATE

Node baru mendeteksi status `approved` via polling, lalu:

**a. Sync ledger penuh:**
```
GET /trust/ledger?since_seq=0   ← download dari genesis
Verifikasi integritas hash chain dari entry pertama
```

**b. Jika role = slave:**
```
Ambil daftar master nodes dari ledger (action: vouch, role: master)
Mulai AXFR dari master yang aktif
```

**c. Jika role = master:**
```
Announce ke jaringan:
POST /trust/announce { "address": "ip:port", "pubkey": "..." }
Slave nodes auto-tambah sebagai sumber sync
```

---

### Step 8 — PEER DISCOVERY

Node tidak langsung tahu semua peer. Discovery bertahap:

```
Bootstrap: 1 IP dari user input / hardcoded well-known nodes / DNS SRV
    ↓
GET /peers → dapat list peer yang dikenal node itu
    ↓
Simpan ke tabel peers lokal
    ↓
Kontak beberapa → dapat lebih banyak peer
    ↓
Gossip periodik → tabel peers selalu fresh
```

**DNS SRV bootstrap (opsional):**
```
dig SRV _dns-rpz._tcp.bodsink.dev
```

---

## Desain REVOCATION

### Siapa yang Bisa Revoke?

| Tier | Actor | Scope | Threshold |
|------|-------|-------|-----------|
| 1 | Genesis node | Siapa saja, unilateral | 1 (self) |
| 2 | Majority vote trusted nodes | Siapa saja | 51% active nodes |
| 3 | Original voucher | Hanya node yang pernah dia vouch | 1 (self) — efeknya kurangi trust score |

**TIER 3 detail:**
- Menarik vouch sendiri tidak langsung revoke
- Node masih hidup jika ada voucher lain
- Jika voucher terakhir menarik vouch → node jadi "orphaned"

---

### Tipe Revocation

**SUSPEND (sementara):**
- Tidak bisa ikut voting atau vouch node lain
- Masih bisa terima AXFR (DNS service tidak terganggu)
- Ada durasi — setelah habis otomatis kembali active
- Bisa di-reinstate lebih awal via voting

**BAN (permanen):**
- Keluar sepenuhnya dari jaringan
- Public key masuk permanent blacklist
- Tidak bisa join ulang dengan keypair yang sama
- Harus generate keypair baru + join dari awal

---

### Cascade Policy

```
Node B di-BAN/SUSPEND
        ↓
Node C, D, E yang di-vouch B → status: "orphaned"
        ↓
Grace period: 72 jam (dikonfigurasi di genesis entry)
        ↓
Selama grace period:
  - Node lain bisa "adopt" (re-vouch) C, D, E
  - Cukup 1 trusted node re-vouch, tidak perlu voting penuh
        ↓
Setelah grace period tanpa adopsi:
  → Otomatis SUSPEND (bukan langsung BAN)
  → Innocent nodes tidak langsung dihukum berat
```

---

### Kecepatan Efektif

```
Vouching:    async, threshold tinggi (2-3), bisa menit/jam
Revocation:  priority gossip, threshold lebih rendah, efektif ~60 detik
```

Revocation entry diberi flag `priority: true` → peer langsung forward tanpa menunggu gossip cycle berikutnya.

---

### Ledger Entry Revocation

```json
{
  "seq":              44,
  "prev_hash":        "b7c1d4...",
  "action":           "revoke",
  "type":             "ban",
  "subject_pubkey":   "XYZ...",
  "reason":           "injecting malicious DNS records",
  "cascade_policy":   "soft",
  "grace_period_hours": 72,
  "actor_pubkey":     "genesis_pubkey",
  "signatures":       [{"signer": "genesis_pubkey", "sig": "sig_genesis"}],
  "effective_at":     "2026-04-18T10:01:00Z",
  "priority":         true,
  "hash":             "c9d2e3..."
}
```

---

### Reinstatement (Unrevoke)

**SUSPEND → bisa di-reinstate:**
```
Threshold = genesis_config.threshold_reinstate (default: 3)
Entry baru di ledger: action = "reinstate"
Riwayat suspend tetap ada — append-only, tidak dihapus
```

**BAN → TIDAK bisa di-reinstate:**
```
Public key masuk revoked_keys permanent
Keypair baru + join ulang dari Step 1
(Voucher baru akan lebih berhati-hati)
```

---

### Anti-Abuse: Revoke Genesis

Genesis sendiri bisa di-revoke oleh supermajority:

```
Threshold: 67% dari total active trusted nodes
Entry: action = "revoke_genesis"
Efek: genesis kehilangan unilateral power
      tetap exist sebagai ordinary trusted node
      trust chain yang sudah ada tetap valid
```

Jaringan tidak kolaps — semua vouch yang pernah dilakukan genesis tetap valid. Hanya kemampuan unilateral yang dicabut.

---

### Decision Tree Revocation

```
Node bermasalah terdeteksi
          ↓
Seberapa parah?
          ↓
┌─────────────────┬─────────────────────────────────┐
│ KRITIS          │ BIASA                            │
│ (inject data)   │ (spam, offline lama, dll)        │
│                 │                                  │
│ Genesis revoke  │ 2 trusted nodes vote             │
│ unilateral      │ → SUSPEND dulu                   │
│ → BAN           │ → Tidak membaik → BAN            │
│ Efektif <60s    │ Efektif ~60s                     │
└─────────────────┴─────────────────────────────────┘
          ↓
  Soft cascade ke dependents (grace period dari genesis config)
          ↓
  Priority gossip sebarkan ke semua node
          ↓
  Semua node update local trust state
          ↓
  AXFR whitelist otomatis di-update
```

---

## Keputusan Desain

### Data DNS dari Node Banned
**Keputusan: Tetap ada**

- Data DNS sudah diverifikasi saat masuk via AXFR
- Node master hanya menyampaikan data upstream RPZ, bukan menciptakan
- Menghapus = DNS protection berlubang tiba-tiba
- Yang di-ban adalah **identitas node**, bukan **konten yang dibawa**

**Pengecualian — Injeksi Record Palsu (Fully Automated):**

Deteksi dan purge dilakukan sepenuhnya otomatis menggunakan **signed AXFR batch + majority consensus** antar master:

1. **Setiap master menandatangani batch AXFR-nya:**
   ```
   axfr_batch_signature = Ed25519Sign(private_key_master, SHA256(zone + records + serial))
   ```
   Setiap record disimpan dengan metadata:
   ```sql
   source_node_id  UUID        REFERENCES nodes(id)
   synced_at       TIMESTAMPTZ
   axfr_batch_sig  TEXT        -- signature master atas seluruh batch
   ```

2. **Cross-validation otomatis antar master (setiap sync cycle):**
   ```
   Slave bandingkan signed batch dari Master A vs Master B vs Master C
   untuk zone yang sama dari upstream RPZ yang sama.

   Jika record X ada di batch Master A tapi tidak di B dan C:
     → axfr_batch_sig Master A valid secara kriptografi? (master tidak dimodif)
     → Tapi isi berbeda dari majority → Master A inject record palsu
     → Auto-purge record X tanpa voting
   ```

3. **Kriteria purge otomatis:**
   ```
   purge jika:
     total_masters_with_record < ceil(total_masters / 2)
     AND semua majority masters punya axfr_batch_sig yang konsisten
     AND record sudah melewati grace window (misal 10 menit, bukan delay AXFR)
   ```
   Grace window mencegah false positive akibat delay propagasi AXFR normal.

4. **Ledger entry otomatis saat purge:**
   ```json
   {
     "action":    "purge_injected",
     "automated": true,
     "evidence": {
       "record_hash":       "...",
       "source_node_id":    "...",
       "agreeing_masters":  ["pubkey_B", "pubkey_C"],
       "disagreeing_master": "pubkey_A"
     }
   }
   ```
   Node yang terbukti inject → otomatis masuk antrian SUSPEND (threshold tetap berlaku).

---

### Role Upgrade (Slave → Master)
**Keputusan: Diizinkan, butuh voting ulang**

- Master punya akses lebih besar → trust level berbeda
- Threshold = `genesis_config.threshold_role_upgrade` (default: 3)
- Entry baru di ledger: `action: "role_upgrade"` — riwayat tercatat
- Tidak perlu generate keypair baru

---

### Grace Period
**Keputusan: Dikonfigurasi di genesis entry**

- Disimpan di genesis entry → berlaku seragam untuk seluruh jaringan
- Tidak exposed di config file per-node
- Default value di code: 72 jam

---

### Threshold Default
| Aksi | Threshold |
|------|-----------|
| Join slave | 2 |
| Join master | 3 |
| Role upgrade | 3 |
| Suspend | 2 |
| Ban | 3 |
| Reinstate | 3 |
| Revoke genesis | 67% total trusted nodes |

Semua nilai disimpan di genesis entry. Perubahan nilai butuh supermajority vote.

---

## Database Schema

```sql
-- Identitas semua node yang pernah dikenal jaringan
CREATE TABLE nodes (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key    TEXT        UNIQUE NOT NULL,
  name          TEXT,
  role          TEXT        NOT NULL,  -- slave, master
  status        TEXT        NOT NULL,  -- active, suspended, banned, orphaned
  joined_at     TIMESTAMPTZ,
  last_seen     TIMESTAMPTZ,
  network_id    UUID        NOT NULL
);

-- Peer discovery — list node yang dikenal lokal
CREATE TABLE peers (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key    TEXT        UNIQUE NOT NULL,
  address       TEXT        NOT NULL,  -- ip:port
  last_seen     TIMESTAMPTZ,
  trust_status  TEXT        NOT NULL,  -- trusted, pending, banned
  source        TEXT,                  -- dari node mana dapat info ini
  network_id    UUID        NOT NULL
);

-- Append-only ledger — TIDAK BOLEH UPDATE/DELETE
CREATE TABLE trust_ledger (
  seq           BIGSERIAL   PRIMARY KEY,
  prev_hash     TEXT        NOT NULL,
  entry_hash    TEXT        UNIQUE NOT NULL,
  action        TEXT        NOT NULL,
  -- action values: genesis, vouch, revoke, reinstate, role_upgrade,
  --                revoke_genesis, announce
  subject_id    UUID        REFERENCES nodes(id),
  actor_id      UUID        REFERENCES nodes(id),
  payload       JSONB       NOT NULL,  -- seluruh data entry
  priority      BOOLEAN     DEFAULT false,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- Signatures per ledger entry (consensus evidence)
CREATE TABLE trust_signatures (
  entry_hash    TEXT        NOT NULL REFERENCES trust_ledger(entry_hash),
  signer_id     UUID        NOT NULL REFERENCES nodes(id),
  signature     TEXT        NOT NULL,
  signed_at     TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (entry_hash, signer_id)
);

-- Pending join requests — untuk polling status
CREATE TABLE join_requests (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key    TEXT        NOT NULL,
  name          TEXT,
  role          TEXT        NOT NULL,
  status        TEXT        NOT NULL DEFAULT 'pending',
  -- status values: pending, approved, rejected, expired
  received_via  UUID        REFERENCES nodes(id),
  signatures    INT         NOT NULL DEFAULT 0,
  required_sigs INT         NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now(),
  ledger_seq    BIGINT      REFERENCES trust_ledger(seq)
);

-- Permanent blacklist (BAN)
CREATE TABLE revoked_keys (
  public_key    TEXT        PRIMARY KEY,
  revoked_at    TIMESTAMPTZ NOT NULL,
  reason        TEXT,
  ledger_seq    BIGINT      NOT NULL REFERENCES trust_ledger(seq)
);

-- Orphaned nodes dalam grace period (cascade dari revocation)
CREATE TABLE orphaned_nodes (
  node_id       UUID        NOT NULL REFERENCES nodes(id),
  orphaned_at   TIMESTAMPTZ NOT NULL,
  grace_until   TIMESTAMPTZ NOT NULL,
  cause_seq     BIGINT      NOT NULL REFERENCES trust_ledger(seq),
  adopted_by    UUID        REFERENCES nodes(id),  -- NULL jika belum diadopsi
  adopted_at    TIMESTAMPTZ,
  PRIMARY KEY (node_id, cause_seq)
);
```

---

## Struktur Module (Go)

```
internal/
  trust/
    keypair.go      → generate/load Ed25519 keypair, TOFU fingerprint
    ledger.go       → append-only ledger, hash chain, verify integrity
    consensus.go    → threshold counting, signature collection
    gossip.go       → periodic peer sync, priority gossip untuk revocation
    verifier.go     → verify entry validity, signature validity
    genesis.go      → genesis mode, network_id, config bootstrap
```

---

## Urutan Implementasi

```
1. Schema DB (semua 7 tabel)
2. internal/trust/keypair.go    ← generate/load Ed25519
3. internal/trust/ledger.go     ← hash chain logic
4. internal/trust/gossip.go     ← peer sync
5. internal/trust/consensus.go  ← threshold + voting
6. API endpoints                ← /trust/join, /trust/sign, /trust/status, /trust/pending, /peers
7. Dashboard UI                 ← voting panel, pending requests, node list
```
