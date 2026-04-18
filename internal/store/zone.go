package store

import (
	"context"
	"fmt"
	"time"
)

// Zone represents one row in the rpz_zones table.
type Zone struct {
	ID                int64
	Name              string
	ZoneType          string // domain, rpz, reverse_ptr
	Mode              string
	MasterIP          string
	MasterIPSecondary string
	MasterPort        int16
	TSIGKey           string
	TSIGSecret        string
	SyncInterval      int
	Serial            int64
	LastSyncAt        *time.Time
	LastSyncStatus    string
	Enabled           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ListZones returns all zones ordered by name.
func (db *DB) ListZones(ctx context.Context) ([]Zone, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, COALESCE(zone_type,'rpz'), mode, COALESCE(host(master_ip),''), COALESCE(host(master_ip_secondary),''), master_port,
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
			&z.ID, &z.Name, &z.ZoneType, &z.Mode, &z.MasterIP, &z.MasterIPSecondary, &z.MasterPort,
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

// GetZoneByName returns a zone by its name (FQDN), or nil if not found.
func (db *DB) GetZoneByName(ctx context.Context, name string) (*Zone, error) {
	var z Zone
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(zone_type,'rpz'), mode, COALESCE(host(master_ip),''), COALESCE(host(master_ip_secondary),''), master_port,
		       COALESCE(tsig_key,''), COALESCE(tsig_secret,''),
		       sync_interval, serial,
		       last_sync_at, COALESCE(last_sync_status,''),
		       enabled, created_at, updated_at
		FROM rpz_zones WHERE name = $1`, name,
	).Scan(
		&z.ID, &z.Name, &z.ZoneType, &z.Mode, &z.MasterIP, &z.MasterIPSecondary, &z.MasterPort,
		&z.TSIGKey, &z.TSIGSecret,
		&z.SyncInterval, &z.Serial,
		&z.LastSyncAt, &z.LastSyncStatus,
		&z.Enabled, &z.CreatedAt, &z.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get zone %q: %w", name, err)
	}
	return &z, nil
}

// GetZoneByID returns a single zone by ID.
func (db *DB) GetZoneByID(ctx context.Context, id int64) (*Zone, error) {
	var z Zone
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(zone_type,'rpz'), mode, COALESCE(host(master_ip),''), COALESCE(host(master_ip_secondary),''), master_port,
		       COALESCE(tsig_key,''), COALESCE(tsig_secret,''),
		       sync_interval, serial,
		       last_sync_at, COALESCE(last_sync_status,''),
		       enabled, created_at, updated_at
		FROM rpz_zones WHERE id = $1`, id,
	).Scan(
		&z.ID, &z.Name, &z.ZoneType, &z.Mode, &z.MasterIP, &z.MasterIPSecondary, &z.MasterPort,
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
		INSERT INTO rpz_zones (name, zone_type, mode, master_ip, master_ip_secondary, master_port, tsig_key, tsig_secret, sync_interval, enabled)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, NULLIF($5,'')::inet, $6, NULLIF($7,''), NULLIF($8,''), $9, $10)
		RETURNING id`,
		z.Name, z.ZoneType, z.Mode, z.MasterIP, z.MasterIPSecondary, z.MasterPort, z.TSIGKey, z.TSIGSecret, z.SyncInterval, z.Enabled,
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
		SET zone_type=$1, mode=$2, master_ip=NULLIF($3,'')::inet, master_ip_secondary=NULLIF($4,'')::inet, master_port=$5,
		    tsig_key=NULLIF($6,''), tsig_secret=NULLIF($7,''),
		    sync_interval=$8, enabled=$9, updated_at=NOW()
		WHERE id=$10`,
		z.ZoneType, z.Mode, z.MasterIP, z.MasterIPSecondary, z.MasterPort,
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

// UpsertZoneFromTrust inserts or updates a zone received via trust-network zone propagation.
// On conflict (same name), only updates master_ip/port/tsig/sync_interval when the
// existing zone is in 'slave' mode — manually configured zones (any other mode) are left
// untouched so operators can override master settings per node.
func (db *DB) UpsertZoneFromTrust(ctx context.Context, z *Zone) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO rpz_zones
			(name, mode, master_ip, master_ip_secondary, master_port, tsig_key, tsig_secret, sync_interval, enabled)
		VALUES ($1, 'slave', NULLIF($2,'')::inet, NULLIF($3,'')::inet, $4, NULLIF($5,''), NULLIF($6,''), $7, true)
		ON CONFLICT (name) DO UPDATE
		  SET master_ip           = EXCLUDED.master_ip,
		      master_ip_secondary = EXCLUDED.master_ip_secondary,
		      master_port         = EXCLUDED.master_port,
		      tsig_key            = EXCLUDED.tsig_key,
		      tsig_secret         = EXCLUDED.tsig_secret,
		      sync_interval       = EXCLUDED.sync_interval,
		      enabled             = true,
		      updated_at          = NOW()
		  WHERE rpz_zones.mode = 'slave'`,
		z.Name, z.MasterIP, z.MasterIPSecondary, z.MasterPort,
		z.TSIGKey, z.TSIGSecret, z.SyncInterval,
	)
	if err != nil {
		return fmt.Errorf("upsert zone from trust %q: %w", z.Name, err)
	}
	return nil
}
