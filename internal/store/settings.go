package store

import (
	"context"
	"fmt"
)

// Setting represents one row in the settings table.
type Setting struct {
	Key   string
	Value string
}

// GetSetting fetches a single setting value by key.
// Returns an empty string and no error if the key does not exist.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.Pool.QueryRow(ctx,
		`SELECT value FROM settings WHERE key = $1`, key,
	).Scan(&value)
	if err != nil {
		// pgx returns pgx.ErrNoRows if not found — treat as empty
		return "", nil
	}
	return value, nil
}

// SetSetting upserts a setting value by key.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// GetAllSettings returns all settings as a map[key]value.
func (db *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.Pool.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("query settings: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan setting row: %w", err)
		}
		result[k] = v
	}
	return result, rows.Err()
}

// LoadAppSettings loads AppSettings from the database settings table.
// Falls back to defaults for missing keys.
func (db *DB) LoadAppSettings(ctx context.Context) (*AppSettingsRow, error) {
	m, err := db.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}

	s := &AppSettingsRow{
		Mode:         stringOrDefault(m["mode"], "slave"),
		MasterIP:     m["master_ip"],
		MasterPort:   intOrDefault(m["master_port"], 53),
		TSIGKey:      m["tsig_key"],
		TSIGSecret:   m["tsig_secret"],
		SyncInterval: intOrDefault(m["sync_interval"], 86400),
	}
	return s, nil
}

// AppSettingsRow mirrors config.AppSettings but is owned by the store layer.
type AppSettingsRow struct {
	Mode         string
	MasterIP     string
	MasterPort   int
	TSIGKey      string
	TSIGSecret   string
	SyncInterval int
}

func stringOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intOrDefault(v string, def int) int {
	if v == "" {
		return def
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	if n == 0 {
		return def
	}
	return n
}
