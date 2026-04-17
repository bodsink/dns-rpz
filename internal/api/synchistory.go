package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleSyncHistoryList renders the global sync history page.
func (s *Server) handleSyncHistoryList(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT h.id, z.name, h.status, h.started_at, h.finished_at,
		       h.records_added, h.records_removed, COALESCE(h.error_message,'')
		FROM sync_history h
		JOIN rpz_zones z ON z.id = h.zone_id
		ORDER BY h.started_at DESC
		LIMIT 200`)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load sync history", err)
		return
	}
	defer rows.Close()

	type entry struct {
		ID             int64
		ZoneName       string
		Status         string
		StartedAt      interface{}
		FinishedAt     interface{}
		RecordsAdded   int
		RecordsRemoved int
		ErrorMessage   string
	}

	var history []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.ZoneName, &e.Status, &e.StartedAt, &e.FinishedAt,
			&e.RecordsAdded, &e.RecordsRemoved, &e.ErrorMessage); err == nil {
			history = append(history, e)
		}
	}

	c.HTML(http.StatusOK, "sync_history.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "history",
		"History":    history,
		"Zone":       nil, // global view
	})
}
