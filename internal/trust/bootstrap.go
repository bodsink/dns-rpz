package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Bootstrap ensures the trust network is properly initialized for this node.
//
// Behavior by role:
//   - "genesis": If no genesis entry exists in the ledger, creates one, inserts
//     this node as the first active trusted node, and returns the new network_id.
//     If a genesis entry already exists (restart), reads and returns its network_id.
//   - "slave" / "master": Reads the network_id from the existing genesis entry.
//     Returns an error if no genesis entry is found (node must join first).
//
// Returns the network_id that must be used for all gossip and API calls.
func Bootstrap(ctx context.Context, db *pgxpool.Pool, kp *Keypair, role string) (string, error) {
	existing, err := loadGenesisFromDB(ctx, db)
	if err != nil && !errors.Is(err, errNoGenesis) {
		return "", fmt.Errorf("read genesis from ledger: %w", err)
	}

	if existing != nil {
		// Genesis entry already present — validate it, then return its network_id.
		if verErr := VerifyGenesisEntry(existing); verErr != nil {
			return "", fmt.Errorf("genesis entry integrity check failed: %w", verErr)
		}
		slog.Info("Trust network ready",
			slog.String("network_id", existing.NetworkID),
			slog.String("role", role),
		)
		return existing.NetworkID, nil
	}

	// No genesis entry yet.
	if role != "genesis" {
		return "", fmt.Errorf(
			"no genesis entry found in the ledger; "+
				"this node (role=%q) must first contact a genesis/master node to join", role)
	}

	// --- Create genesis entry for the very first node. ---
	cfg := DefaultNetworkConfig()
	payload, err := BuildGenesisEntry(kp, cfg)
	if err != nil {
		return "", fmt.Errorf("build genesis entry: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal genesis payload: %w", err)
	}

	ledger := NewLedger(db)
	if _, err := ledger.Append(ctx, "genesis", nil, nil, payloadBytes, false); err != nil {
		return "", fmt.Errorf("store genesis entry: %w", err)
	}

	// Insert the genesis node itself into the nodes table.
	nodeID, err := newUUID()
	if err != nil {
		return "", fmt.Errorf("generate genesis node id: %w", err)
	}
	fingerprint := kp.Fingerprint()
	pubKey := kp.PublicKeyBase64()

	_, err = db.Exec(ctx, `
		INSERT INTO nodes (id, public_key, fingerprint, network_id, role, status, joined_at)
		VALUES ($1::uuid, $2, $3, $4::uuid, 'genesis', 'active', now())
		ON CONFLICT (public_key) DO UPDATE
		    SET status = 'active', network_id = EXCLUDED.network_id`,
		nodeID, pubKey, fingerprint, payload.NetworkID,
	)
	if err != nil {
		return "", fmt.Errorf("insert genesis node: %w", err)
	}

	slog.Info("Genesis node initialized",
		slog.String("node_id", nodeID),
		slog.String("network_id", payload.NetworkID),
		slog.String("public_key", pubKey),
		slog.String("fingerprint", fingerprint),
	)
	slog.Warn("IMPORTANT: This is the genesis node. Backup the key file immediately.")

	return payload.NetworkID, nil
}

// errNoGenesis is a sentinel returned when no genesis ledger entry exists.
var errNoGenesis = errors.New("no genesis entry")

// loadGenesisFromDB reads the genesis entry from the trust_ledger table.
// Returns errNoGenesis if not found.
func loadGenesisFromDB(ctx context.Context, db *pgxpool.Pool) (*GenesisPayload, error) {
	var raw json.RawMessage
	err := db.QueryRow(ctx,
		`SELECT payload FROM trust_ledger WHERE action = 'genesis' AND seq = 1`,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoGenesis
	}
	if err != nil {
		return nil, err
	}

	var gp GenesisPayload
	if err := json.Unmarshal(raw, &gp); err != nil {
		return nil, fmt.Errorf("decode genesis payload: %w", err)
	}
	return &gp, nil
}

// LoadGenesisPayload is the public accessor for reading the genesis payload.
// Returns nil, nil if no genesis entry has been created yet.
func LoadGenesisPayload(ctx context.Context, db *pgxpool.Pool) (*GenesisPayload, error) {
	gp, err := loadGenesisFromDB(ctx, db)
	if errors.Is(err, errNoGenesis) {
		return nil, nil
	}
	return gp, err
}
