package trust

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LedgerEntry represents one record in the append-only trust ledger.
// The hash chain links each entry to its predecessor via prev_hash,
// making tampering detectable.
type LedgerEntry struct {
	Seq       int64           `json:"seq"`
	PrevHash  string          `json:"prev_hash"`
	EntryHash string          `json:"entry_hash"`
	Action    string          `json:"action"`
	SubjectID *string         `json:"subject_id,omitempty"`
	ActorID   *string         `json:"actor_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
	Priority  bool            `json:"priority"`
	CreatedAt time.Time       `json:"created_at"`
}

// Ledger provides append and read operations for the trust_ledger table.
// All writes are append-only; no UPDATE or DELETE is ever issued.
type Ledger struct {
	db *pgxpool.Pool
}

// NewLedger creates a Ledger backed by the given connection pool.
func NewLedger(db *pgxpool.Pool) *Ledger {
	return &Ledger{db: db}
}

// Append adds a new entry to the ledger within a serializable transaction.
// It reads the current maximum seq and its hash, verifies prev_hash matches,
// then inserts the new entry. Returns the assigned seq number.
func (l *Ledger) Append(ctx context.Context, action string,
	subjectID, actorID *string,
	payload json.RawMessage,
	priority bool,
) (*LedgerEntry, error) {
	var entry *LedgerEntry

	err := pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	}, func(tx pgx.Tx) error {
		// Get current tip of the chain.
		prevHash, currentSeq, err := l.chainTip(ctx, tx)
		if err != nil {
			return fmt.Errorf("read chain tip: %w", err)
		}

		now := time.Now().UTC()
		entryHash, err := computeEntryHash(currentSeq+1, prevHash, action, payload, now)
		if err != nil {
			return fmt.Errorf("compute entry hash: %w", err)
		}

		const q = `
			INSERT INTO trust_ledger
				(prev_hash, entry_hash, action, subject_id, actor_id, payload, priority, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING seq, prev_hash, entry_hash, action, subject_id, actor_id, payload, priority, created_at`

		row := tx.QueryRow(ctx, q,
			prevHash, entryHash, action, subjectID, actorID, payload, priority, now)

		e := &LedgerEntry{}
		if err := row.Scan(
			&e.Seq, &e.PrevHash, &e.EntryHash, &e.Action,
			&e.SubjectID, &e.ActorID, &e.Payload, &e.Priority, &e.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert ledger entry: %w", err)
		}
		entry = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// GetSince returns all entries with seq > sinceSeq, ordered by seq ascending.
// Used by gossip to fetch new entries for a peer.
func (l *Ledger) GetSince(ctx context.Context, sinceSeq int64) ([]LedgerEntry, error) {
	const q = `
		SELECT seq, prev_hash, entry_hash, action, subject_id, actor_id, payload, priority, created_at
		FROM trust_ledger
		WHERE seq > $1
		ORDER BY seq ASC`

	rows, err := l.db.Query(ctx, q, sinceSeq)
	if err != nil {
		return nil, fmt.Errorf("query ledger since %d: %w", sinceSeq, err)
	}
	defer rows.Close()

	var entries []LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(
			&e.Seq, &e.PrevHash, &e.EntryHash, &e.Action,
			&e.SubjectID, &e.ActorID, &e.Payload, &e.Priority, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ledger row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetByHash returns a single ledger entry by its entry_hash.
func (l *Ledger) GetByHash(ctx context.Context, entryHash string) (*LedgerEntry, error) {
	const q = `
		SELECT seq, prev_hash, entry_hash, action, subject_id, actor_id, payload, priority, created_at
		FROM trust_ledger
		WHERE entry_hash = $1`

	e := &LedgerEntry{}
	err := l.db.QueryRow(ctx, q, entryHash).Scan(
		&e.Seq, &e.PrevHash, &e.EntryHash, &e.Action,
		&e.SubjectID, &e.ActorID, &e.Payload, &e.Priority, &e.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get ledger entry %s: %w", entryHash, err)
	}
	return e, nil
}

// MaxSeq returns the highest seq currently in the ledger, or 0 if empty.
func (l *Ledger) MaxSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := l.db.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM trust_ledger`).Scan(&seq)
	return seq, err
}

// VerifyChain verifies the integrity of every entry starting from seq=1.
// It checks that each entry's prev_hash matches the hash of the previous entry
// and that each entry_hash matches the recomputed hash.
// Returns the number of entries verified and any error found.
func (l *Ledger) VerifyChain(ctx context.Context) (int, error) {
	rows, err := l.db.Query(ctx, `
		SELECT seq, prev_hash, entry_hash, action, payload, created_at
		FROM trust_ledger
		ORDER BY seq ASC`)
	if err != nil {
		return 0, fmt.Errorf("query ledger for verification: %w", err)
	}
	defer rows.Close()

	var prevHash = "0000000000000000"
	var count int
	for rows.Next() {
		var (
			seq       int64
			prev      string
			hash      string
			action    string
			payload   json.RawMessage
			createdAt time.Time
		)
		if err := rows.Scan(&seq, &prev, &hash, &action, &payload, &createdAt); err != nil {
			return count, fmt.Errorf("scan row %d: %w", seq, err)
		}

		// Check hash chain linkage.
		if prev != prevHash {
			return count, fmt.Errorf("seq %d: prev_hash mismatch (expected %s, got %s)",
				seq, prevHash, prev)
		}

		// Recompute and verify the entry hash.
		computed, err := computeEntryHash(seq, prev, action, payload, createdAt)
		if err != nil {
			return count, fmt.Errorf("seq %d: recompute hash: %w", seq, err)
		}
		if computed != hash {
			return count, fmt.Errorf("seq %d: entry_hash mismatch (stored=%s, computed=%s)",
				seq, hash, computed)
		}

		prevHash = hash
		count++
	}
	return count, rows.Err()
}

// chainTip reads the current max seq and its entry_hash within an open transaction.
// Returns ("0000000000000000", 0) when the ledger is empty (genesis condition).
func (l *Ledger) chainTip(ctx context.Context, tx pgx.Tx) (prevHash string, seq int64, err error) {
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(seq), 0), COALESCE(
			(SELECT entry_hash FROM trust_ledger ORDER BY seq DESC LIMIT 1),
			'0000000000000000'
		) FROM trust_ledger`).Scan(&seq, &prevHash)
	return
}

// computeEntryHash produces the canonical SHA-256 hash for a ledger entry.
// Only stable fields (seq, prev_hash, action, payload, created_at) are hashed —
// mutable operational fields like subject_id/actor_id are excluded to avoid
// hash changes when those foreign keys are resolved after the fact.
func computeEntryHash(seq int64, prevHash, action string, payload json.RawMessage, createdAt time.Time) (string, error) {
	canonical := struct {
		Seq       int64           `json:"seq"`
		PrevHash  string          `json:"prev_hash"`
		Action    string          `json:"action"`
		Payload   json.RawMessage `json:"payload"`
		CreatedAt string          `json:"created_at"` // RFC3339Nano for determinism
	}{
		Seq:       seq,
		PrevHash:  prevHash,
		Action:    action,
		Payload:   payload,
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}
