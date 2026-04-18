package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Consensus manages threshold signature counting and join-request approval logic.
// Each node evaluates threshold independently — there is no central coordinator.
type Consensus struct {
	db     *pgxpool.Pool
	ledger *Ledger
}

// NewConsensus creates a Consensus backed by the given pool and ledger.
func NewConsensus(db *pgxpool.Pool, ledger *Ledger) *Consensus {
	return &Consensus{db: db, ledger: ledger}
}

// EffectiveThreshold computes the actual threshold required given the
// genesis-configured value and the current number of active trusted nodes.
//
//	effective = min(genesis_threshold, total_active_trusted_nodes)
//
// This prevents new networks with few nodes from being permanently stuck.
func (c *Consensus) EffectiveThreshold(ctx context.Context, genesisThreshold int) (int, error) {
	var count int
	err := c.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM nodes WHERE status = 'active'`,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active nodes: %w", err)
	}
	if count < genesisThreshold {
		return count, nil
	}
	return genesisThreshold, nil
}

// EffectiveThresholdPercent computes an integer threshold from a percentage
// string (e.g. "67%") relative to the total number of active trusted nodes.
// Used for revoke_genesis which requires a supermajority.
func (c *Consensus) EffectiveThresholdPercent(ctx context.Context, pctStr string) (int, error) {
	pctStr = strings.TrimSuffix(strings.TrimSpace(pctStr), "%")
	pct, err := strconv.ParseFloat(pctStr, 64)
	if err != nil {
		return 0, fmt.Errorf("parse percentage %q: %w", pctStr, err)
	}

	var total int
	if err := c.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM nodes WHERE status = 'active'`,
	).Scan(&total); err != nil {
		return 0, fmt.Errorf("count active nodes: %w", err)
	}
	if total == 0 {
		return 1, nil
	}
	threshold := int(math.Ceil(float64(total) * pct / 100.0))
	if threshold < 1 {
		threshold = 1
	}
	return threshold, nil
}

// CountSignatures returns the number of valid signatures collected so far
// for the given ledger entry hash.
func (c *Consensus) CountSignatures(ctx context.Context, entryHash string) (int, error) {
	var n int
	err := c.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM trust_signatures WHERE entry_hash = $1`,
		entryHash,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count signatures for %s: %w", entryHash, err)
	}
	return n, nil
}

// AddSignature records a voter's signature on a ledger entry.
// It verifies the signature before storing.  Duplicate signer_id is a no-op
// (idempotent via ON CONFLICT DO NOTHING).
func (c *Consensus) AddSignature(ctx context.Context, v *Verifier, sig EntrySignature) error {
	if err := v.VerifyEntrySignature(ctx, sig); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	_, err := c.db.Exec(ctx, `
		INSERT INTO trust_signatures (entry_hash, signer_id, signature, signed_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (entry_hash, signer_id) DO NOTHING`,
		sig.EntryHash, sig.SignerID, sig.Signature, sig.SignedAt,
	)
	if err != nil {
		return fmt.Errorf("store signature: %w", err)
	}
	return nil
}

// ApproveJoinRequest checks whether a join request has reached threshold.
// If so, it appends a "vouch" entry to the ledger, updates the join_requests
// status to "approved", and inserts the new node into the nodes table.
// Returns true if threshold was just reached (and approval was committed).
func (c *Consensus) ApproveJoinRequest(
	ctx context.Context,
	kp *Keypair,
	netCfg NetworkConfig,
	requestID string,
) (bool, error) {
	// Load the join request.
	jr, err := c.loadJoinRequest(ctx, requestID)
	if err != nil {
		return false, err
	}
	if jr.Status != "pending" {
		return false, nil // already processed
	}
	if time.Now().UTC().After(jr.ExpiresAt) {
		if _, err := c.db.Exec(ctx,
			`UPDATE join_requests SET status = 'expired' WHERE id = $1`, requestID,
		); err != nil {
			return false, fmt.Errorf("expire join request: %w", err)
		}
		return false, nil
	}

	// Determine threshold for this role.
	genesisThreshold := netCfg.ThresholdJoinSlave
	if jr.Role == "master" {
		genesisThreshold = netCfg.ThresholdJoinMaster
	}
	threshold, err := c.EffectiveThreshold(ctx, genesisThreshold)
	if err != nil {
		return false, err
	}
	if jr.Signatures < threshold {
		return false, nil // not enough signatures yet
	}

	// Determine permissions based on role.
	permissions := []string{"can_slave"}
	if jr.Role == "master" {
		permissions = []string{"can_slave", "can_master"}
	}

	// Build vouch payload.
	payload, err := buildVouchPayload(jr, permissions)
	if err != nil {
		return false, fmt.Errorf("build vouch payload: %w", err)
	}

	// Append vouch entry to ledger.
	entry, err := c.ledger.Append(ctx, "vouch", nil, nil, payload, false)
	if err != nil {
		return false, fmt.Errorf("append vouch entry: %w", err)
	}

	// Insert new node.
	now := time.Now().UTC()
	if _, err := c.db.Exec(ctx, `
		INSERT INTO nodes (public_key, name, role, status, joined_at, network_id)
		VALUES ($1, $2, $3, 'active', $4, $5)
		ON CONFLICT (public_key) DO UPDATE
		  SET role = EXCLUDED.role, status = 'active', joined_at = EXCLUDED.joined_at`,
		jr.PublicKey, jr.Name, jr.Role, now, jr.NetworkID,
	); err != nil {
		return false, fmt.Errorf("insert approved node: %w", err)
	}

	// Mark join request approved.
	if _, err := c.db.Exec(ctx, `
		UPDATE join_requests SET status = 'approved', ledger_seq = $1 WHERE id = $2`,
		entry.Seq, requestID,
	); err != nil {
		return false, fmt.Errorf("update join request status: %w", err)
	}

	return true, nil
}

// joinRequest holds a row from the join_requests table.
type joinRequest struct {
	ID           string
	PublicKey    string
	Name         *string
	Role         string
	Status       string
	Signatures   int
	RequiredSigs int
	ExpiresAt    time.Time
	NetworkID    string
}

func (c *Consensus) loadJoinRequest(ctx context.Context, id string) (*joinRequest, error) {
	const q = `
		SELECT jr.id, jr.public_key, jr.name, jr.role, jr.status,
		       jr.signatures, jr.required_sigs, jr.expires_at,
		       COALESCE(n.network_id::text, '')
		FROM join_requests jr
		LEFT JOIN nodes n ON n.public_key = (
		    SELECT public_key FROM nodes WHERE status = 'active' LIMIT 1
		)
		WHERE jr.id = $1`

	jr := &joinRequest{}
	err := c.db.QueryRow(ctx, q, id).Scan(
		&jr.ID, &jr.PublicKey, &jr.Name, &jr.Role, &jr.Status,
		&jr.Signatures, &jr.RequiredSigs, &jr.ExpiresAt, &jr.NetworkID,
	)
	if err != nil {
		return nil, fmt.Errorf("load join request %s: %w", id, err)
	}
	return jr, nil
}

func buildVouchPayload(jr *joinRequest, permissions []string) ([]byte, error) {
	type vouchPayload struct {
		Action        string   `json:"action"`
		SubjectPubkey string   `json:"subject_pubkey"`
		SubjectRole   string   `json:"subject_role"`
		Permissions   []string `json:"permissions"`
	}
	p := vouchPayload{
		Action:        "vouch",
		SubjectPubkey: jr.PublicKey,
		SubjectRole:   jr.Role,
		Permissions:   permissions,
	}
	return json.Marshal(p)
}

// IncrementJoinRequestSignatures increments the signatures counter on a join
// request.  Called each time a new valid vote arrives via gossip or HTTP.
func (c *Consensus) IncrementJoinRequestSignatures(ctx context.Context, requestID string) error {
	_, err := c.db.Exec(ctx,
		`UPDATE join_requests SET signatures = signatures + 1 WHERE id = $1 AND status = 'pending'`,
		requestID,
	)
	return err
}

// ExpireStaleJoinRequests marks all pending join requests past their expires_at
// as "expired".  Should be called periodically (e.g. every minute).
func (c *Consensus) ExpireStaleJoinRequests(ctx context.Context) (int64, error) {
	tag, err := c.db.Exec(ctx, `
		UPDATE join_requests
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
