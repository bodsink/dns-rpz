package store

import (
	"context"
	"fmt"
	"time"
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

// BulkUpsertRecords inserts or updates records in a single transaction.
// Used during AXFR sync to efficiently load millions of records.
func (db *DB) BulkUpsertRecords(ctx context.Context, zoneID int64, records []Record) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Use context.Background() so ROLLBACK is always sent even if ctx is already canceled
	// (e.g. service shutdown during a sync). Without this, the connection stays
	// "idle in transaction" until PostgreSQL idle_in_transaction_session_timeout.
	defer tx.Rollback(context.Background()) //nolint:errcheck

	for _, r := range records {
		_, err := tx.Exec(ctx, `
			INSERT INTO rpz_records (zone_id, name, rtype, rdata, ttl, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (zone_id, name) DO UPDATE
			SET rtype=EXCLUDED.rtype, rdata=EXCLUDED.rdata, ttl=EXCLUDED.ttl, updated_at=NOW()
			WHERE rpz_records.rtype IS DISTINCT FROM EXCLUDED.rtype
			   OR rpz_records.rdata IS DISTINCT FROM EXCLUDED.rdata
			   OR rpz_records.ttl IS DISTINCT FROM EXCLUDED.ttl`,
			zoneID, r.Name, r.RType, r.RData, r.TTL,
		)
		if err != nil {
			return fmt.Errorf("upsert record %q: %w", r.Name, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bulk upsert: %w", err)
	}
	return nil
}

// DeleteRecordsNotIn removes records for a zone that are not in the given name list.
// Used after AXFR sync to clean up removed entries.
func (db *DB) DeleteRecordsNotIn(ctx context.Context, zoneID int64, names []string) (int64, error) {
	if len(names) == 0 {
		// Delete all records for the zone (full refresh with empty zone)
		tag, err := db.Pool.Exec(ctx,
			`DELETE FROM rpz_records WHERE zone_id = $1`, zoneID)
		if err != nil {
			return 0, fmt.Errorf("delete all records for zone %d: %w", zoneID, err)
		}
		return tag.RowsAffected(), nil
	}

	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM rpz_records WHERE zone_id = $1 AND name != ALL($2)`,
		zoneID, names,
	)
	if err != nil {
		return 0, fmt.Errorf("delete stale records for zone %d: %w", zoneID, err)
	}
	return tag.RowsAffected(), nil
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
