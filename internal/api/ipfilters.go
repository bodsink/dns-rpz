package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// handleIPFilterList renders the IP filter management page.
func (s *Server) handleIPFilterList(c *gin.Context) {
	filters, err := s.db.ListIPFilters(c.Request.Context())
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load IP filters", err)
		return
	}
	c.HTML(http.StatusOK, "ipfilters.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "ipfilters",
		"Filters":    filters,
		"Saved":      c.Query("saved") == "1",
	})
}

// handleIPFilterCreate adds a new CIDR to the IP filter list.
func (s *Server) handleIPFilterCreate(c *gin.Context) {
	cidr := strings.TrimSpace(c.PostForm("cidr"))
	description := strings.TrimSpace(c.PostForm("description"))

	renderErr := func(msg string) {
		filters, _ := s.db.ListIPFilters(c.Request.Context())
		c.HTML(http.StatusBadRequest, "ipfilters.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Filters":   filters,
			"Error":     msg,
		})
	}

	if cidr == "" {
		renderErr("CIDR is required.")
		return
	}
	// Validate CIDR notation
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		renderErr("Invalid CIDR notation (e.g. 192.168.1.0/24 or 10.0.0.1/32).")
		return
	}

	if _, err := s.db.CreateIPFilter(c.Request.Context(), cidr, description); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			renderErr("This CIDR already exists.")
			return
		}
		s.renderError(c, http.StatusInternalServerError, "Failed to create IP filter", err)
		return
	}

	s.logger.Info("ip filter created", "cidr", cidr, "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/ip-filters?saved=1")
}

// handleIPFilterDelete removes an IP filter by ID.
func (s *Server) handleIPFilterDelete(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderError(c, http.StatusBadRequest, "Invalid filter ID", nil)
		return
	}
	if err := s.db.DeleteIPFilter(c.Request.Context(), id); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to delete IP filter", err)
		return
	}
	s.logger.Info("ip filter deleted", "id", id, "user", currentUser(c).Username)

	if c.GetHeader("HX-Request") == "true" {
		c.Status(http.StatusOK) // HTMX swap removes the element
		return
	}
	c.Redirect(http.StatusFound, "/ip-filters")
}

// handleIPFilterToggle enables or disables an IP filter.
func (s *Server) handleIPFilterToggle(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderError(c, http.StatusBadRequest, "Invalid filter ID", nil)
		return
	}
	enabled := c.PostForm("enabled") == "true"
	if err := s.db.SetIPFilterEnabled(c.Request.Context(), id, enabled); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to toggle IP filter", err)
		return
	}
	s.logger.Info("ip filter toggled", "id", id, "enabled", enabled, "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/ip-filters")
}
