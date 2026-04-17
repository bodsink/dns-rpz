package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Record represents one row in the rpz_records table.
type Record struct {
	ID        int64
	ZoneID    int64
	Name      string
	RType     string
	RData     string
	TTL       int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LookupRecord checks if a domain name matches any RPZ record.
// Returns the matching record or nil if not found.
// This is the hot path for DNS queries — uses the idx_rpz_records_name index.
func (db *DB) LookupRecord(ctx context.Context, name string) (*Record, error) {
	var r Record
	err := db.Pool.QueryRow(ctx, `
		SELECT r.id, r.zone_id, r.name, r.rtype, r.rdata, r.ttl, r.created_at, r.updated_at
		FROM rpz_records r
		JOIN rpz_zones z ON z.id = r.zone_id
		WHERE r.name = $1 AND z.enabled = TRUE
		LIMIT 1`,
		name,
	).Scan(&r.ID, &r.ZoneID, &r.Name, &r.RType, &r.RData, &r.TTL, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, nil // not found is not an error
	}
	return &r, nil
}

// BulkUpsertSession streams records into a temporary (no-index) staging table
// via the PostgreSQL COPY binary protocol, then atomically replaces all zone
// records in rpz_records when Finish() is called.
//
// Strategy: COPY → staging (no index) → DELETE old + INSERT fresh in one tx.
// This is faster than UPSERT because:
//   - COPY to staging has zero index maintenance cost
//   - The final INSERT has no ON CONFLICT lookup per row
//   - Only one index-write pass over rpz_records (insert, not lookup+update)
//
// Usage:
//
//	sess, err := db.NewBulkUpsertSession(ctx, zoneID)
//	for _, batch := range batches { sess.AddBatch(ctx, batch) }
//	added, removed, err := sess.Finish(ctx) // or sess.Close() to abort
type BulkUpsertSession struct {
	conn   *pgxpool.Conn
	zoneID int64
	total  int
}

// NewBulkUpsertSession acquires a dedicated connection and prepares a temporary
// staging table on it (created once per connection, truncated between syncs).
func (db *DB) NewBulkUpsertSession(ctx context.Context, zoneID int64) (*BulkUpsertSession, error) {
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for bulk upsert: %w", err)
	}

	// Create once per connection; harmless if it already exists.
	_, err = conn.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS rpz_stage (
			name  TEXT    NOT NULL,
			rtype TEXT    NOT NULL,
			rdata TEXT    NOT NULL,
			ttl   INTEGER NOT NULL
		)`)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("create temp stage table: %w", err)
	}

	// Clear leftovers from any previous sync on this connection.
	if _, err = conn.Exec(ctx, `TRUNCATE rpz_stage`); err != nil {
		conn.Release()
		return nil, fmt.Errorf("truncate temp stage: %w", err)
	}

	return &BulkUpsertSession{conn: conn, zoneID: zoneID}, nil
}

// AddBatch streams a slice of records into the staging table using COPY.
// No indexes are maintained on the staging table, so this is very fast.
func (s *BulkUpsertSession) AddBatch(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	rows := make([][]any, len(records))
	for i, r := range records {
		rows[i] = []any{r.Name, r.RType, r.RData, int32(r.TTL)}
	}
	_, err := s.conn.CopyFrom(
		ctx,
		pgx.Identifier{"rpz_stage"},
		[]string{"name", "rtype", "rdata", "ttl"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("copy %d rows to stage: %w", len(records), err)
	}
	s.total += len(records)
	return nil
}

// Finish atomically replaces all zone records:
//  1. DELETE all existing records for the zone
//  2. INSERT all staged records (no ON CONFLICT — table is clean for this zone)
//
// Returns (added, removed, err). Releases the connection when done.
func (s *BulkUpsertSession) Finish(ctx context.Context) (added, removed int, err error) {
	defer s.conn.Release()

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin transaction: %w", err)
	}
	// Use Background so ROLLBACK is always sent even if ctx is canceled.
	defer tx.Rollback(context.Background()) //nolint:errcheck

	// Delete all old records for the zone and capture count.
	tag, err := tx.Exec(ctx, `DELETE FROM rpz_records WHERE zone_id = $1`, s.zoneID)
	if err != nil {
		return 0, 0, fmt.Errorf("delete zone %d records: %w", s.zoneID, err)
	}
	removed = int(tag.RowsAffected())

	// Insert all staged records — no ON CONFLICT needed (zone is now empty).
	_, err = tx.Exec(ctx, `
		INSERT INTO rpz_records (zone_id, name, rtype, rdata, ttl, updated_at)
		SELECT $1, name, rtype, rdata, ttl, NOW()
		FROM rpz_stage`,
		s.zoneID,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("insert from stage to rpz_records: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit bulk replace: %w", err)
	}
	return s.total, removed, nil
}

// Close discards the session without writing to rpz_records. Safe to call after Finish.
func (s *BulkUpsertSession) Close() {
	s.conn.Release()
}

// CountRecords returns the total number of records across all zones.
func (db *DB) CountRecords(ctx context.Context) (int64, error) {
	var n int64
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM rpz_records`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count records: %w", err)
	}
	return n, nil
}

// CountRecordsByZone returns record count per zone as a map[zoneID]count.
func (db *DB) CountRecordsByZone(ctx context.Context) (map[int64]int64, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT zone_id, COUNT(*) FROM rpz_records GROUP BY zone_id`)
	if err != nil {
		return nil, fmt.Errorf("count records by zone: %w", err)
	}
	defer rows.Close()

	result := make(map[int64]int64)
	for rows.Next() {
		var zoneID, count int64
		if err := rows.Scan(&zoneID, &count); err != nil {
			return nil, fmt.Errorf("scan count row: %w", err)
		}
		result[zoneID] = count
	}
	return result, rows.Err()
}

// LoadAllNames loads all RPZ entries for a zone into memory via streaming.
// Used at startup to build the in-memory lookup index.
func (db *DB) LoadAllNames(ctx context.Context, zoneID int64, fn func(name, rdata string) error) error {
	rows, err := db.Pool.Query(ctx,
		`SELECT name, rdata FROM rpz_records WHERE zone_id = $1`, zoneID)
	if err != nil {
		return fmt.Errorf("load names for zone %d: %w", zoneID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, rdata string
		if err := rows.Scan(&name, &rdata); err != nil {
			return fmt.Errorf("scan name: %w", err)
		}
		if err := fn(name, rdata); err != nil {
			return err
		}
	}
	return rows.Err()
}
