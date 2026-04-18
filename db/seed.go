package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// DefaultZone holds the definition of a pre-configured RPZ zone.
type DefaultZone struct {
	Name               string
	Mode               string
	MasterIP           string
	MasterIPSecondary  string
	MasterPort         int
	SyncInterval       int
	Description        string
}

// defaultZones is the list of zones seeded on first run.
// Based on known public RPZ feeds (equivalent to BIND9 slave zone config).
var defaultZones = []DefaultZone{
	{
		// Trustpositif Kominfo — Indonesian government internet content filtering RPZ
		// Equivalent BIND9 config:
		//   zone "trustpositifkominfo" { type slave; masters { 139.255.196.202; 182.23.79.202; }; };
		Name:              "trustpositifkominfo",
		Mode:              "slave",
		MasterIP:          "139.255.196.202",
		MasterIPSecondary: "182.23.79.202",
		MasterPort:        53,
		SyncInterval:      86400,
		Description:       "Trustpositif Kominfo — Indonesian government RPZ feed",
	},
}

// Seed inserts default zones into the database if they do not already exist.
// Safe to call on every startup — uses INSERT ... ON CONFLICT DO NOTHING.
func Seed(ctx context.Context, pool *pgxpool.Pool) error {
	for _, z := range defaultZones {
		port := z.MasterPort
		if port == 0 {
			port = 53
		}
		interval := z.SyncInterval
		if interval == 0 {
			interval = 300
		}

		_, err := pool.Exec(ctx, `
			INSERT INTO rpz_zones (name, mode, master_ip, master_ip_secondary, master_port, sync_interval, enabled)
			VALUES ($1, $2, NULLIF($3,'')::inet, NULLIF($4,'')::inet, $5, $6, TRUE)
			ON CONFLICT (name) DO NOTHING`,
			z.Name, z.Mode, z.MasterIP, z.MasterIPSecondary, port, interval,
		)
		if err != nil {
			return fmt.Errorf("seed zone %q: %w", z.Name, err)
		}
	}
	return nil
}

// SeedAdminUser creates the default admin user if no users exist (first run).
// If initPassword is non-empty, it is used as the initial password; otherwise falls back to "admin".
// Returns (created bool, password string, err error).
// The caller SHOULD log a prominent warning when created is true.
func SeedAdminUser(ctx context.Context, pool *pgxpool.Pool, initPassword string) (created bool, usedPassword string, err error) {
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, "", fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return false, "", nil
	}

	password := initPassword
	if password == "" {
		password = "admin"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return false, "", fmt.Errorf("generate default password hash: %w", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES ('admin', $1, 'admin')
		ON CONFLICT (username) DO NOTHING`, string(hash),
	)
	if err != nil {
		return false, "", fmt.Errorf("seed admin user: %w", err)
	}
	return true, password, nil
}
