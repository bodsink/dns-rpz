package api

import (
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

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
		"Saved":      c.Query("saved") == "1",
	})
}

// handleSettingsSave processes the settings form submission.
func (s *Server) handleSettingsSave(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Settings":  settings,
			"Error":     msg,
		})
	}

	mode := c.PostForm("mode")
	if mode != "master" && mode != "slave" {
		renderErr("Mode must be 'master' or 'slave'.")
		return
	}

	masterPort := strings.TrimSpace(c.PostForm("master_port"))
	if p, err := strconv.Atoi(masterPort); err != nil || p < 1 || p > 65535 {
		renderErr("Master port must be a number between 1 and 65535.")
		return
	}

	syncInterval := strings.TrimSpace(c.PostForm("sync_interval"))
	if si, err := strconv.Atoi(syncInterval); err != nil || si < 60 {
		renderErr("Sync interval must be at least 60 seconds.")
		return
	}

	webPort := strings.TrimSpace(c.PostForm("web_port"))
	if p, err := strconv.Atoi(webPort); err != nil || p < 1 || p > 65535 {
		renderErr("Web port must be a number between 1 and 65535.")
		return
	}

	timezone := strings.TrimSpace(c.PostForm("timezone"))
	if _, err := time.LoadLocation(timezone); err != nil {
		renderErr(fmt.Sprintf("Invalid timezone %q. Use IANA format, e.g. Asia/Jakarta, UTC, America/New_York.", timezone))
		return
	}

	kvs := map[string]string{
		"mode":          mode,
		"master_ip":     strings.TrimSpace(c.PostForm("master_ip")),
		"master_port":   masterPort,
		"tsig_key":      strings.TrimSpace(c.PostForm("tsig_key")),
		"tsig_secret":   strings.TrimSpace(c.PostForm("tsig_secret")),
		"sync_interval": syncInterval,
		"web_port":      webPort,
		"timezone":      timezone,
	}

	for k, v := range kvs {
		if err := s.db.SetSetting(ctx, k, v); err != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
			return
		}
	}

	// Apply timezone to the Linux system immediately.
	if err := ApplyTimezone(timezone); err != nil {
		s.logger.Warn("timezone apply failed (requires root/sudo)", "timezone", timezone, "err", err)
	}

	s.logger.Info("settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?saved=1")
}

// ApplyTimezone sets the system timezone via timedatectl.
// Requires the process to have sufficient privileges (root or CAP_SYS_TIME).
func ApplyTimezone(tz string) error {
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	out, err := exec.Command("timedatectl", "set-timezone", tz).CombinedOutput()
	if err != nil {
		return fmt.Errorf("timedatectl set-timezone %s: %s: %w", tz, strings.TrimSpace(string(out)), err)
	}
	return nil
}
