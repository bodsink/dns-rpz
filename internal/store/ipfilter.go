package store

import (
	"context"
	"fmt"
	"time"
)

// IPFilter represents one row in the ip_filters table.
type IPFilter struct {
	ID          int64
	CIDR        string
	Description string
	Enabled     bool
	CreatedAt   time.Time
}

// ListIPFilters returns all IP filters.
func (db *DB) ListIPFilters(ctx context.Context) ([]IPFilter, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, cidr::text, COALESCE(description,''), enabled, created_at
		FROM ip_filters ORDER BY cidr`)
	if err != nil {
		return nil, fmt.Errorf("list ip filters: %w", err)
	}
	defer rows.Close()

	var filters []IPFilter
	for rows.Next() {
		var f IPFilter
		if err := rows.Scan(&f.ID, &f.CIDR, &f.Description, &f.Enabled, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ip filter: %w", err)
		}
		filters = append(filters, f)
	}
	return filters, rows.Err()
}

// CreateIPFilter inserts a new IP filter entry.
func (db *DB) CreateIPFilter(ctx context.Context, cidr, description string) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO ip_filters (cidr, description)
		VALUES ($1::cidr, $2)
		RETURNING id`,
		cidr, description,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create ip filter %q: %w", cidr, err)
	}
	return id, nil
}

// DeleteIPFilter removes an IP filter by ID.
func (db *DB) DeleteIPFilter(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM ip_filters WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete ip filter %d: %w", id, err)
	}
	return nil
}

// SetIPFilterEnabled enables or disables an IP filter.
func (db *DB) SetIPFilterEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE ip_filters SET enabled = $1 WHERE id = $2`, enabled, id)
	if err != nil {
		return fmt.Errorf("set ip filter %d enabled=%v: %w", id, enabled, err)
	}
	return nil
}

// LoadEnabledCIDRs returns all enabled CIDR strings.
// Used at startup to build the in-memory allow-list for recursion.
func (db *DB) LoadEnabledCIDRs(ctx context.Context) ([]string, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT cidr::text FROM ip_filters WHERE enabled = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("load enabled cidrs: %w", err)
	}
	defer rows.Close()

	var cidrs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("scan cidr: %w", err)
		}
		cidrs = append(cidrs, c)
	}
	return cidrs, rows.Err()
}
