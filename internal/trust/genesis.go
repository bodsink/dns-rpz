package trust

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetworkConfig holds the consensus thresholds embedded in the genesis entry.
// These values are stored in the genesis ledger entry and apply uniformly
// to the entire network — they cannot be overridden per-node.
type NetworkConfig struct {
	ThresholdJoinSlave     int    `json:"threshold_join_slave"`
	ThresholdJoinMaster    int    `json:"threshold_join_master"`
	ThresholdRoleUpgrade   int    `json:"threshold_role_upgrade"`
	ThresholdSuspend       int    `json:"threshold_suspend"`
	ThresholdBan           int    `json:"threshold_ban"`
	ThresholdReinstate     int    `json:"threshold_reinstate"`
	ThresholdRevokeGenesis string `json:"threshold_revoke_genesis"` // e.g. "67%"
	GracePeriodHours       int    `json:"grace_period_hours"`
}

// DefaultNetworkConfig returns the network-wide threshold defaults
// used when creating a genesis entry.
func DefaultNetworkConfig() NetworkConfig {
	return NetworkConfig{
		ThresholdJoinSlave:     2,
		ThresholdJoinMaster:    3,
		ThresholdRoleUpgrade:   3,
		ThresholdSuspend:       2,
		ThresholdBan:           3,
		ThresholdReinstate:     3,
		ThresholdRevokeGenesis: "67%",
		GracePeriodHours:       72,
	}
}

// ReadNetworkConfig reads the NetworkConfig from the genesis ledger entry.
// Falls back to DefaultNetworkConfig if no genesis entry exists yet.
func ReadNetworkConfig(ctx context.Context, db *pgxpool.Pool) (NetworkConfig, error) {
	var payload []byte
	err := db.QueryRow(ctx,
		`SELECT payload FROM trust_ledger WHERE action = 'genesis' LIMIT 1`,
	).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return DefaultNetworkConfig(), nil
	}
	var gp GenesisPayload
	if err := json.Unmarshal(payload, &gp); err != nil {
		return DefaultNetworkConfig(), nil
	}
	return gp.NetworkConfig, nil
}

// GenesisPayload is the JSON payload stored inside the genesis ledger entry.
type GenesisPayload struct {
	Seq           int64         `json:"seq"`
	PrevHash      string        `json:"prev_hash"`
	Action        string        `json:"action"`
	NetworkID     string        `json:"network_id"`
	GenesisPubkey string        `json:"genesis_pubkey"`
	NetworkConfig NetworkConfig `json:"network_config"`
	Signatures    []string      `json:"signatures"`
	CreatedAt     time.Time     `json:"created_at"`
	Hash          string        `json:"hash"`
}

// BuildGenesisEntry creates and signs the genesis ledger entry for a new network.
// It assigns a fresh network_id (UUID v4) and self-signs the entry with kp.
func BuildGenesisEntry(kp *Keypair, cfg NetworkConfig) (*GenesisPayload, error) {
	networkID, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("generate network_id: %w", err)
	}
	now := time.Now().UTC()

	entry := &GenesisPayload{
		Seq:           1,
		PrevHash:      "0000000000000000",
		Action:        "genesis",
		NetworkID:     networkID,
		GenesisPubkey: kp.PublicKeyBase64(),
		NetworkConfig: cfg,
		CreatedAt:     now,
	}

	// Compute hash over canonical fields (excluding hash and signatures).
	hash, err := computeGenesisHash(entry)
	if err != nil {
		return nil, fmt.Errorf("compute genesis hash: %w", err)
	}
	entry.Hash = hash

	// Self-sign: sign the hash bytes directly.
	hashBytes, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash for signing: %w", err)
	}
	sig := base64.StdEncoding.EncodeToString(kp.Sign(hashBytes))
	entry.Signatures = []string{sig}

	return entry, nil
}

// computeGenesisHash hashes the canonical fields of the genesis entry.
// Signatures and Hash fields are excluded from the hash computation.
func computeGenesisHash(e *GenesisPayload) (string, error) {
	canonical := struct {
		Seq           int64         `json:"seq"`
		PrevHash      string        `json:"prev_hash"`
		Action        string        `json:"action"`
		NetworkID     string        `json:"network_id"`
		GenesisPubkey string        `json:"genesis_pubkey"`
		NetworkConfig NetworkConfig `json:"network_config"`
		CreatedAt     time.Time     `json:"created_at"`
	}{
		Seq:           e.Seq,
		PrevHash:      e.PrevHash,
		Action:        e.Action,
		NetworkID:     e.NetworkID,
		GenesisPubkey: e.GenesisPubkey,
		NetworkConfig: e.NetworkConfig,
		CreatedAt:     e.CreatedAt,
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}

// VerifyGenesisEntry verifies the self-signature on a genesis entry.
// Returns an error if the hash or signature does not match.
func VerifyGenesisEntry(entry *GenesisPayload) error {
	expectedHash, err := computeGenesisHash(entry)
	if err != nil {
		return fmt.Errorf("recompute genesis hash: %w", err)
	}
	if entry.Hash != expectedHash {
		return fmt.Errorf("genesis hash mismatch: stored=%s computed=%s",
			entry.Hash, expectedHash)
	}
	if len(entry.Signatures) == 0 {
		return fmt.Errorf("genesis entry has no signatures")
	}

	hashBytes, err := base64.StdEncoding.DecodeString(entry.Hash)
	if err != nil {
		return fmt.Errorf("decode genesis hash: %w", err)
	}
	ok, err := VerifySignature(entry.GenesisPubkey, hashBytes, entry.Signatures[0])
	if err != nil {
		return fmt.Errorf("verify genesis signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("genesis self-signature is invalid")
	}
	return nil
}

// newUUID generates a random UUID v4 using crypto/rand.
func newUUID() (string, error) {
	return NewUUID()
}

// NewUUID generates a random UUID v4 (exported for use by other packages).
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
