package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// handleSettingsPage renders the application settings form.
func (s *Server) handleSettingsPage(c *gin.Context) {
	settings, err := s.db.LoadAppSettings(c.Request.Context())
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load settings", err)
		return
	}
	c.HTML(http.StatusOK, "settings.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "settings",
		"Settings":   settings,
	})
}

// handleSettingsSave processes the settings form submission.
func (s *Server) handleSettingsSave(c *gin.Context) {
	ctx := c.Request.Context()

	mode := c.PostForm("mode")
	if mode != "master" && mode != "slave" {
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Error":     "Mode must be 'master' or 'slave'.",
		})
		return
	}

	masterPort := strings.TrimSpace(c.PostForm("master_port"))
	if p, err := strconv.Atoi(masterPort); err != nil || p < 1 || p > 65535 {
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Error":     "Master port must be a number between 1 and 65535.",
		})
		return
	}

	syncInterval := strings.TrimSpace(c.PostForm("sync_interval"))
	if si, err := strconv.Atoi(syncInterval); err != nil || si < 60 {
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Error":     "Sync interval must be at least 60 seconds.",
		})
		return
	}

	kvs := map[string]string{
		"mode":          mode,
		"master_ip":     strings.TrimSpace(c.PostForm("master_ip")),
		"master_port":   masterPort,
		"tsig_key":      strings.TrimSpace(c.PostForm("tsig_key")),
		"tsig_secret":   strings.TrimSpace(c.PostForm("tsig_secret")),
		"sync_interval": syncInterval,
	}

	for k, v := range kvs {
		if err := s.db.SetSetting(ctx, k, v); err != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
			return
		}
	}

	s.logger.Info("settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?saved=1")
}
