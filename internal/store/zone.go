package store

import (
	"context"
	"fmt"
	"time"
)

// Zone represents one row in the rpz_zones table.
type Zone struct {
	ID                 int64
	Name               string
	Mode               string
	MasterIP           string
	MasterIPSecondary  string
	MasterPort         int16
	TSIGKey            string
	TSIGSecret         string
	SyncInterval       int
	Serial             int64
	LastSyncAt         *time.Time
	LastSyncStatus     string
	Enabled            bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ListZones returns all zones ordered by name.
func (db *DB) ListZones(ctx context.Context) ([]Zone, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, mode, COALESCE(master_ip::text,''), COALESCE(master_ip_secondary::text,''), master_port,
		       COALESCE(tsig_key,''), COALESCE(tsig_secret,''),
		       sync_interval, serial,
		       last_sync_at, COALESCE(last_sync_status,''),
		       enabled, created_at, updated_at
		FROM rpz_zones
		ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	defer rows.Close()

	var zones []Zone
	for rows.Next() {
		var z Zone
		if err := rows.Scan(
			&z.ID, &z.Name, &z.Mode, &z.MasterIP, &z.MasterIPSecondary, &z.MasterPort,
			&z.TSIGKey, &z.TSIGSecret,
			&z.SyncInterval, &z.Serial,
			&z.LastSyncAt, &z.LastSyncStatus,
			&z.Enabled, &z.CreatedAt, &z.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan zone: %w", err)
		}
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

// GetZoneByID returns a single zone by ID.
func (db *DB) GetZoneByID(ctx context.Context, id int64) (*Zone, error) {
	var z Zone
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, mode, COALESCE(master_ip::text,''), COALESCE(master_ip_secondary::text,''), master_port,
		       COALESCE(tsig_key,''), COALESCE(tsig_secret,''),
		       sync_interval, serial,
		       last_sync_at, COALESCE(last_sync_status,''),
		       enabled, created_at, updated_at
		FROM rpz_zones WHERE id = $1`, id,
	).Scan(
		&z.ID, &z.Name, &z.Mode, &z.MasterIP, &z.MasterIPSecondary, &z.MasterPort,
		&z.TSIGKey, &z.TSIGSecret,
		&z.SyncInterval, &z.Serial,
		&z.LastSyncAt, &z.LastSyncStatus,
		&z.Enabled, &z.CreatedAt, &z.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get zone %d: %w", id, err)
	}
	return &z, nil
}

// CreateZone inserts a new zone and returns its assigned ID.
func (db *DB) CreateZone(ctx context.Context, z *Zone) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO rpz_zones (name, mode, master_ip, master_ip_secondary, master_port, tsig_key, tsig_secret, sync_interval, enabled)
		VALUES ($1, $2, NULLIF($3,'')::inet, NULLIF($4,'')::inet, $5, NULLIF($6,''), NULLIF($7,''), $8, $9)
		RETURNING id`,
		z.Name, z.Mode, z.MasterIP, z.MasterIPSecondary, z.MasterPort, z.TSIGKey, z.TSIGSecret, z.SyncInterval, z.Enabled,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create zone %q: %w", z.Name, err)
	}
	return id, nil
}

// UpdateZone updates editable fields of a zone by ID.
func (db *DB) UpdateZone(ctx context.Context, z *Zone) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE rpz_zones
		SET mode=$1, master_ip=NULLIF($2,'')::inet, master_ip_secondary=NULLIF($3,'')::inet, master_port=$4,
		    tsig_key=NULLIF($5,''), tsig_secret=NULLIF($6,''),
		    sync_interval=$7, enabled=$8, updated_at=NOW()
		WHERE id=$9`,
		z.Mode, z.MasterIP, z.MasterIPSecondary, z.MasterPort,
		z.TSIGKey, z.TSIGSecret,
		z.SyncInterval, z.Enabled, z.ID,
	)
	if err != nil {
		return fmt.Errorf("update zone %d: %w", z.ID, err)
	}
	return nil
}

// DeleteZone deletes a zone and all its records (CASCADE).
func (db *DB) DeleteZone(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM rpz_zones WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete zone %d: %w", id, err)
	}
	return nil
}

// UpdateZoneSerial updates the SOA serial and sync status after a successful AXFR.
func (db *DB) UpdateZoneSerial(ctx context.Context, id int64, serial int64, status string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE rpz_zones
		SET serial=$1, last_sync_at=NOW(), last_sync_status=$2, updated_at=NOW()
		WHERE id=$3`,
		serial, status, id,
	)
	if err != nil {
		return fmt.Errorf("update zone serial %d: %w", id, err)
	}
	return nil
}
