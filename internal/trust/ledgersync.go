package trust

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SyncNodesFromLedger replays all entries in trust_ledger and upserts the nodes
// table to reflect the current network state.
//
// This is called once on a freshly joined node after the full ledger has been
// fetched from the bootstrap node (fetchAndStoreLedger in main.go), because the
// gossip loop hasn't started yet and the nodes table is empty at that point.
//
// It is safe to call multiple times — all upserts are idempotent (ON CONFLICT).
func SyncNodesFromLedger(ctx context.Context, db *pgxpool.Pool, networkID string) error {
	rows, err := db.Query(ctx,
		`SELECT action, payload FROM trust_ledger ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var action string
		var payload json.RawMessage
		if err := rows.Scan(&action, &payload); err != nil {
			continue
		}
		if err := ApplyLedgerEntryToNodes(ctx, db, action, payload, networkID); err != nil {
			slog.Warn("sync nodes from ledger: skip entry",
				slog.String("action", action),
				slog.String("err", err.Error()),
			)
		}
	}
	return rows.Err()
}

// ApplyLedgerEntryToNodes updates the nodes table based on a single ledger entry.
// Handles: genesis, vouch, revoke, reinstate, role_upgrade.
// All writes are ON CONFLICT idempotent — safe to call repeatedly.
func ApplyLedgerEntryToNodes(ctx context.Context, db *pgxpool.Pool, action string, payload json.RawMessage, networkID string) error {
	switch action {
	case "genesis":
		var gp struct {
			GenesisPubkey string `json:"genesis_pubkey"`
		}
		if err := json.Unmarshal(payload, &gp); err != nil || gp.GenesisPubkey == "" {
			return nil
		}
		fingerprint := FingerprintFromPubKeyBase64(gp.GenesisPubkey)
		_, err := db.Exec(ctx, `
			INSERT INTO nodes (public_key, fingerprint, network_id, role, status, joined_at)
			VALUES ($1, $2, $3::uuid, 'genesis', 'active', now())
			ON CONFLICT (public_key) DO UPDATE
			  SET status = 'active', network_id = EXCLUDED.network_id`,
			gp.GenesisPubkey, fingerprint, networkID,
		)
		return err

	case "vouch":
		var vp struct {
			SubjectPubkey string `json:"subject_pubkey"`
			SubjectRole   string `json:"subject_role"`
		}
		if err := json.Unmarshal(payload, &vp); err != nil || vp.SubjectPubkey == "" {
			return nil
		}
		if vp.SubjectRole == "" {
			vp.SubjectRole = "slave"
		}
		fingerprint := FingerprintFromPubKeyBase64(vp.SubjectPubkey)
		_, err := db.Exec(ctx, `
			INSERT INTO nodes (public_key, fingerprint, network_id, role, status, joined_at)
			VALUES ($1, $2, $3::uuid, $4, 'active', now())
			ON CONFLICT (public_key) DO UPDATE
			  SET role = EXCLUDED.role, status = 'active'`,
			vp.SubjectPubkey, fingerprint, networkID, vp.SubjectRole,
		)
		return err

	case "revoke":
		var rp struct {
			SubjectPubkey string `json:"subject_pubkey"`
			Type          string `json:"type"` // "suspend" or "ban"
		}
		if err := json.Unmarshal(payload, &rp); err != nil || rp.SubjectPubkey == "" {
			return nil
		}
		newStatus := "suspended"
		if rp.Type == "ban" {
			newStatus = "banned"
		}
		_, err := db.Exec(ctx,
			`UPDATE nodes SET status = $1 WHERE public_key = $2`,
			newStatus, rp.SubjectPubkey,
		)
		return err

	case "reinstate":
		var rp struct {
			SubjectPubkey string `json:"subject_pubkey"`
		}
		if err := json.Unmarshal(payload, &rp); err != nil || rp.SubjectPubkey == "" {
			return nil
		}
		_, err := db.Exec(ctx,
			`UPDATE nodes SET status = 'active', suspended_until = NULL WHERE public_key = $1`,
			rp.SubjectPubkey,
		)
		return err

	case "role_upgrade":
		var rp struct {
			SubjectPubkey string `json:"subject_pubkey"`
			NewRole       string `json:"new_role"`
		}
		if err := json.Unmarshal(payload, &rp); err != nil || rp.SubjectPubkey == "" || rp.NewRole == "" {
			return nil
		}
		_, err := db.Exec(ctx,
			`UPDATE nodes SET role = $1 WHERE public_key = $2`,
			rp.NewRole, rp.SubjectPubkey,
		)
		return err

	case "announce":
		// Extract the announcing node's HTTP address and store it in peers
		// so the local gossip loop can reach that node.
		var ap struct {
			PublicKey string `json:"public_key"`
			Address   string `json:"address"`
		}
		if err := json.Unmarshal(payload, &ap); err != nil || ap.Address == "" || ap.PublicKey == "" {
			return nil
		}
		return StorePeer(ctx, db, Peer{
			PublicKey:   ap.PublicKey,
			Address:     ap.Address,
			TrustStatus: "trusted",
			NetworkID:   networkID,
		})
	}

	// Other actions (announce, purge_injected, etc.) do not affect nodes table.
	return nil
}
