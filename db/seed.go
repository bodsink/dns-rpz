package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
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
		SyncInterval:      300,
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
