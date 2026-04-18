package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// marshalJSON is a thin wrapper around json.Marshal for use within this package.
func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

const (
	gossipInterval     = 30 * time.Second
	gossipFanout       = 3 // number of random peers to contact each cycle
	gossipHTTPTimeout  = 10 * time.Second
	maxGossipBatchSize = 500 // max entries per gossip pull
)

// Peer represents one row from the peers table.
type Peer struct {
	ID          string     `json:"id"`
	PublicKey   string     `json:"public_key"`
	Address     string     `json:"address"` // "ip:port"
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	TrustStatus string     `json:"trust_status"`
	NetworkID   string     `json:"network_id"`
}

// Gossip runs the background gossip loop: periodically selects random trusted
// peers and syncs ledger entries.  Priority entries (revocation) are pushed
// immediately without waiting for the next cycle.
type Gossip struct {
	db        *pgxpool.Pool
	ledger    *Ledger
	verifier  *Verifier
	consensus *Consensus
	localKP   *Keypair
	networkID string
	client    *http.Client
}

// NewGossip creates a Gossip worker.
func NewGossip(db *pgxpool.Pool, ledger *Ledger, verifier *Verifier, consensus *Consensus, kp *Keypair, networkID string) *Gossip {
	return &Gossip{
		db:        db,
		ledger:    ledger,
		verifier:  verifier,
		consensus: consensus,
		localKP:   kp,
		networkID: networkID,
		client: &http.Client{
			Timeout: gossipHTTPTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU — identity verified via Ed25519 pubkey, not TLS cert
			},
		},
	}
}

// Run starts the periodic gossip loop.  It blocks until ctx is cancelled.
func (g *Gossip) Run(ctx context.Context) {
	ticker := time.NewTicker(gossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.runCycle(ctx)
		}
	}
}

// PushPriorityEntry immediately gossips a high-priority entry (e.g. revocation)
// to all known trusted peers without waiting for the next gossip cycle.
func (g *Gossip) PushPriorityEntry(ctx context.Context, entry LedgerEntry) {
	peers, err := g.trustedPeers(ctx, 0) // all peers
	if err != nil {
		slog.Warn("gossip: load peers for priority push", slog.String("error", err.Error()))
		return
	}
	for _, p := range peers {
		if err := g.pushEntriesToPeer(ctx, p, []LedgerEntry{entry}); err != nil {
			slog.Warn("gossip: priority push failed",
				slog.String("peer", p.Address),
				slog.String("error", err.Error()),
			)
		}
	}
}

// runCycle executes one gossip round: pick fanout random peers and pull their
// new entries.
func (g *Gossip) runCycle(ctx context.Context) {
	peers, err := g.trustedPeers(ctx, gossipFanout)
	if err != nil {
		slog.Warn("gossip: load peers", slog.String("error", err.Error()))
		return
	}

	localSeq, err := g.ledger.MaxSeq(ctx)
	if err != nil {
		slog.Warn("gossip: read local max seq", slog.String("error", err.Error()))
		return
	}

	for _, p := range peers {
		if err := g.syncFromPeer(ctx, p, localSeq); err != nil {
			slog.Warn("gossip: sync from peer",
				slog.String("peer", p.Address),
				slog.String("error", err.Error()),
			)
		} else {
			g.updatePeerLastSeen(ctx, p.ID)
		}
	}
}

// syncFromPeer fetches new ledger entries from a peer (since sinceSeq) and
// stores valid ones locally.
func (g *Gossip) syncFromPeer(ctx context.Context, peer Peer, sinceSeq int64) error {
	url := fmt.Sprintf("https://%s/trust/ledger?since_seq=%d", peer.Address, sinceSeq)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	// Sign the request per middlewareTrustAuth protocol:
	// signing payload = METHOD\nPATH\nhex(SHA256(body))\ntimestamp
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	emptyHash := sha256.Sum256([]byte{})
	signingPayload := []byte("GET\n/trust/ledger\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsStr)
	req.Header.Set("X-Node-Pubkey", g.localKP.PublicKeyBase64())
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Network-ID", g.networkID)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(g.localKP.Sign(signingPayload)))

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var entries []LedgerEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Errorf("unmarshal entries: %w", err)
	}
	if len(entries) > maxGossipBatchSize {
		entries = entries[:maxGossipBatchSize]
	}

	for _, e := range entries {
		if err := g.storeInboundEntry(ctx, e); err != nil {
			slog.Warn("gossip: discard invalid entry",
				slog.Int64("seq", e.Seq),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

// pushEntriesToPeer sends a batch of ledger entries to a peer via HTTP POST.
func (g *Gossip) pushEntriesToPeer(ctx context.Context, peer Peer, entries []LedgerEntry) error {
	body, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s/trust/pending", peer.Address)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("peer returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// storeInboundEntry validates and persists a ledger entry received via gossip.
func (g *Gossip) storeInboundEntry(ctx context.Context, e LedgerEntry) error {
	// Recompute and verify the hash.
	computed, err := computeEntryHash(e.Seq, e.PrevHash, e.Action, e.Payload, e.CreatedAt)
	if err != nil {
		return fmt.Errorf("compute hash: %w", err)
	}
	if computed != e.EntryHash {
		return fmt.Errorf("entry_hash mismatch: seq=%d stored=%s computed=%s",
			e.Seq, e.EntryHash, computed)
	}

	// Validate payload JSON structure.
	if err := VerifyLedgerEntryPayload(e); err != nil {
		return err
	}

	// Upsert: insert if not already present (idempotent by entry_hash UNIQUE).
	// Store subject_id/actor_id as NULL to avoid FK violations: UUIDs from the
	// originating node's DB are not valid in the local DB until nodes are synced.
	// The actual identity data is in the JSON payload (subject_pubkey field).
	_, err = g.db.Exec(ctx, `
		INSERT INTO trust_ledger
			(seq, prev_hash, entry_hash, action, payload, priority, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (entry_hash) DO NOTHING`,
		e.Seq, e.PrevHash, e.EntryHash, e.Action,
		e.Payload, e.Priority, e.CreatedAt,
	)
	if err != nil {
		return err
	}

	// Keep nodes table in sync: apply state changes from vouch/revoke/reinstate/role_upgrade.
	// Errors here are non-fatal — the ledger entry is already stored.
	if applyErr := ApplyLedgerEntryToNodes(ctx, g.db, e.Action, e.Payload, g.networkID); applyErr != nil {
		slog.Warn("gossip: failed to apply entry to nodes table",
			slog.String("action", e.Action),
			slog.Int64("seq", e.Seq),
			slog.String("err", applyErr.Error()),
		)
	}
	return nil
}

// trustedPeers returns a random sample of up to n trusted peers for this network.
// If n <= 0, all trusted peers are returned.
func (g *Gossip) trustedPeers(ctx context.Context, n int) ([]Peer, error) {
	rows, err := g.db.Query(ctx, `
		SELECT id, public_key, address, last_seen, trust_status, network_id
		FROM peers
		WHERE trust_status = 'trusted' AND network_id = $1`,
		g.networkID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []Peer
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.Address, &p.LastSeen, &p.TrustStatus, &p.NetworkID); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if n <= 0 || len(peers) <= n {
		return peers, nil
	}

	// Random sample of n peers.
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
	return peers[:n], nil
}

// updatePeerLastSeen sets last_seen = now() for a peer after successful sync.
func (g *Gossip) updatePeerLastSeen(ctx context.Context, peerID string) {
	_, err := g.db.Exec(ctx,
		`UPDATE peers SET last_seen = now() WHERE id = $1`, peerID)
	if err != nil {
		slog.Warn("gossip: update last_seen", slog.String("peer_id", peerID),
			slog.String("error", err.Error()))
	}
}

// StorePeer upserts a peer into the local peers table.
// Called when a new peer is discovered via /peers exchange or bootstrap.
func StorePeer(ctx context.Context, db *pgxpool.Pool, peer Peer) error {
	_, err := db.Exec(ctx, `
		INSERT INTO peers (public_key, address, trust_status, source, network_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (public_key) DO UPDATE
		  SET address = EXCLUDED.address,
		      source  = EXCLUDED.source,
		      network_id = EXCLUDED.network_id`,
		peer.PublicKey, peer.Address, peer.TrustStatus, peer.Address, peer.NetworkID,
	)
	return err
}

// BroadcastJoinRequest gossips a new join request to all known trusted peers.
// Called asynchronously after a join request is stored locally.
func (g *Gossip) BroadcastJoinRequest(ctx context.Context, id, pubKey, name, role string, expiresAt time.Time) {
	peers, err := g.trustedPeers(ctx, 0)
	if err != nil {
		slog.Warn("gossip: load peers for join broadcast", slog.String("error", err.Error()))
		return
	}

	type broadcastPayload struct {
		Type          string    `json:"type"`
		ID            string    `json:"id"`
		SubjectPubkey string    `json:"subject_pubkey"`
		SubjectName   string    `json:"subject_name,omitempty"`
		SubjectRole   string    `json:"subject_role"`
		RequestedAt   time.Time `json:"requested_at"`
		RequestedVia  string    `json:"requested_via"`
		ExpiresAt     time.Time `json:"expires_at"`
		Signatures    []string  `json:"signatures"`
	}

	payload := broadcastPayload{
		Type:          "join_request",
		ID:            id,
		SubjectPubkey: pubKey,
		SubjectName:   name,
		SubjectRole:   role,
		RequestedAt:   time.Now().UTC(),
		RequestedVia:  g.localKP.PublicKeyBase64(),
		ExpiresAt:     expiresAt,
		Signatures:    []string{},
	}

	body, err := marshalJSON(payload)
	if err != nil {
		slog.Warn("gossip: marshal join broadcast", slog.String("error", err.Error()))
		return
	}

	for _, p := range peers {
		url := "https://" + p.Address + "/trust/pending"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Network-ID", g.networkID)
		resp, err := g.client.Do(req)
		if err != nil {
			slog.Warn("gossip: broadcast join to peer",
				slog.String("peer", p.Address),
				slog.String("error", err.Error()))
			continue
		}
		resp.Body.Close()
	}
}
