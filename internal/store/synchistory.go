package store

import (
	"context"
	"fmt"
	"time"
)

// SyncHistory represents one row in the sync_history table.
type SyncHistory struct {
	ID             int64
	ZoneID         int64
	StartedAt      time.Time
	FinishedAt     *time.Time
	Status         string
	RecordsAdded   int
	RecordsRemoved int
	ErrorMessage   string
}

// InsertSyncHistory creates a new sync history entry and returns its ID.
func (db *DB) InsertSyncHistory(ctx context.Context, zoneID int64) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO sync_history (zone_id, status)
		VALUES ($1, 'in_progress')
		RETURNING id`, zoneID,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert sync history: %w", err)
	}
	return id, nil
}

// FinishSyncHistory marks a sync history entry as completed.
func (db *DB) FinishSyncHistory(ctx context.Context, id int64, status string, added, removed int, errMsg string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE sync_history
		SET status=$1, finished_at=NOW(), records_added=$2, records_removed=$3, error_message=NULLIF($4,'')
		WHERE id=$5`,
		status, added, removed, errMsg, id,
	)
	if err != nil {
		return fmt.Errorf("finish sync history %d: %w", id, err)
	}
	return nil
}

// CleanupStaleSyncHistory marks any in_progress entries as failed.
// Called on startup to clean up rows left behind by a previous unclean shutdown.
func (db *DB) CleanupStaleSyncHistory(ctx context.Context) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `
		UPDATE sync_history
		SET status='failed', finished_at=NOW(),
		    error_message='interrupted by service restart'
		WHERE status='in_progress'`)
	if err != nil {
		return 0, fmt.Errorf("cleanup stale sync history: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListSyncHistory returns the last N sync history entries for a zone.
func (db *DB) ListSyncHistory(ctx context.Context, zoneID int64, limit int) ([]SyncHistory, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, zone_id, started_at, finished_at, status,
		       records_added, records_removed, COALESCE(error_message,'')
		FROM sync_history
		WHERE zone_id = $1
		ORDER BY started_at DESC
		LIMIT $2`,
		zoneID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list sync history: %w", err)
	}
	defer rows.Close()

	var history []SyncHistory
	for rows.Next() {
		var h SyncHistory
		if err := rows.Scan(
			&h.ID, &h.ZoneID, &h.StartedAt, &h.FinishedAt, &h.Status,
			&h.RecordsAdded, &h.RecordsRemoved, &h.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan sync history: %w", err)
		}
		history = append(history, h)
	}
	return history, rows.Err()
}
