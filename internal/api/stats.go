package api

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/dns-rpz/internal/store"
)

// DashboardStats holds aggregate data for the overview page.
type DashboardStats struct {
	TotalZones    int
	EnabledZones  int
	TotalRecords  int64
	RecentHistory []recentSyncEntry
}

type recentSyncEntry struct {
	ZoneName       string
	Status         string
	StartedAt      string
	RecordsAdded   int
	RecordsRemoved int
}

// handleDashboard renders the main overview page.
func (s *Server) handleDashboard(c *gin.Context) {
	ctx := c.Request.Context()

	var (
		wg           sync.WaitGroup
		zones        []store.Zone
		zonesErr     error
		totalRecords int64
		recent       []recentSyncEntry
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		zones, zonesErr = s.db.ListZones(ctx)
	}()

	go func() {
		defer wg.Done()
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM rpz_records r JOIN rpz_zones z ON z.id=r.zone_id WHERE z.enabled=TRUE`,
		).Scan(&totalRecords); err != nil {
			s.logger.Warn("dashboard: failed to count records", "err", err)
		}
	}()

	go func() {
		defer wg.Done()
		rows, err := s.db.Pool.Query(ctx, `
			SELECT z.name, h.status, h.started_at, h.records_added, h.records_removed
			FROM sync_history h
			JOIN rpz_zones z ON z.id = h.zone_id
			ORDER BY h.started_at DESC
			LIMIT 10`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var e recentSyncEntry
				var t interface{}
				if err := rows.Scan(&e.ZoneName, &e.Status, &t, &e.RecordsAdded, &e.RecordsRemoved); err == nil {
					if ts, ok := t.(interface{ Format(string) string }); ok {
						e.StartedAt = ts.Format("2006-01-02 15:04:05")
					}
					recent = append(recent, e)
				}
			}
		}
	}()

	wg.Wait()

	if zonesErr != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load zones", zonesErr)
		return
	}

	totalZones := len(zones)
	enabledZones := 0
	for _, z := range zones {
		if z.Enabled {
			enabledZones++
		}
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"User":         currentUser(c),
		"CSRFToken":    csrfToken(c),
		"ActivePage":   "dashboard",
		"TotalZones":   totalZones,
		"EnabledZones": enabledZones,
		"TotalRecords": totalRecords,
		"RecentSync":   recent,
	})
}

// renderError renders the error page with a given HTTP status.
func (s *Server) renderError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		s.logger.Error(message, "err", err, "path", c.Request.URL.Path)
	}
	c.HTML(status, "error.html", gin.H{
		"Title":   http.StatusText(status),
		"Message": message,
		"User":    currentUser(c),
	})
}
