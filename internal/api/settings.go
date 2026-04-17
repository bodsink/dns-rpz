package api

import (
	"context"
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
		"Saved":      c.Query("saved"),
	})
}

// handleSettingsSaveSync saves Sync-related settings (mode, master, TSIG, interval).
func (s *Server) handleSettingsSaveSync(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Settings":  settings,
			"ErrorSync": msg,
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

	kvs := map[string]string{
		"mode":          mode,
		"master_ip":     strings.TrimSpace(c.PostForm("master_ip")),
		"master_port":   masterPort,
		"tsig_key":      strings.TrimSpace(c.PostForm("tsig_key")),
		"tsig_secret":   strings.TrimSpace(c.PostForm("tsig_secret")),
		"sync_interval": syncInterval,
	}
	if err := saveSettingsMap(ctx, s, kvs); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	// Signal self to reload sync interval into the scheduler without restart.
	if s.selfReload != nil {
		if err := s.selfReload(); err != nil {
			s.logger.Warn("failed to trigger sync settings reload", "err", err)
		}
	}

	s.logger.Info("sync settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?saved=sync")
}

// handleSettingsSaveDNS saves DNS Upstream settings and signals the DNS process to reload.
func (s *Server) handleSettingsSaveDNS(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Settings":  settings,
			"ErrorDNS":  msg,
		})
	}

	upstreams := strings.TrimSpace(c.PostForm("dns_upstream"))
	if upstreams == "" {
		renderErr("At least one upstream DNS server is required.")
		return
	}
	// Normalize: accept newline-separated IPs with optional port.
	// Port defaults to 53 if not specified. Store as comma-separated ip:port.
	var normalized []string
	for _, srv := range strings.FieldsFunc(upstreams, func(r rune) bool { return r == '\n' || r == '\r' }) {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !strings.Contains(srv, ":") {
			srv = srv + ":53"
		}
		normalized = append(normalized, srv)
	}
	if len(normalized) == 0 {
		renderErr("At least one valid upstream DNS server is required.")
		return
	}
	upstreams = strings.Join(normalized, ",")

	strategy := c.PostForm("dns_upstream_strategy")
	switch strategy {
	case "roundrobin", "random", "race":
	default:
		renderErr("Strategy must be one of: roundrobin, random, race.")
		return
	}

	kvs := map[string]string{
		"dns_upstream":          upstreams,
		"dns_upstream_strategy": strategy,
	}
	if err := saveSettingsMap(ctx, s, kvs); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	// Signal the DNS process to reload its upstream pool from the DB.
	if s.dnsSignal != nil {
		if err := s.dnsSignal(); err != nil {
			s.logger.Warn("failed to signal dns process for upstream reload", "err", err)
		} else {
			s.logger.Info("dns process signaled for upstream reload")
		}
	}

	s.logger.Info("dns upstream settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?saved=dns")
}

// handleSettingsSaveWeb saves Web Server settings (port).
func (s *Server) handleSettingsSaveWeb(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Settings":  settings,
			"ErrorWeb":  msg,
		})
	}

	webPort := strings.TrimSpace(c.PostForm("web_port"))
	if p, err := strconv.Atoi(webPort); err != nil || p < 1 || p > 65535 {
		renderErr("Web port must be a number between 1 and 65535.")
		return
	}

	if err := s.db.SetSetting(ctx, "web_port", webPort); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	s.logger.Info("web server settings updated", "user", currentUser(c).Username, "port", webPort)

	// Restart the web service in background so the redirect response is sent first.
	if s.restartWeb != nil {
		go func() {
			time.Sleep(800 * time.Millisecond)
			if err := s.restartWeb(); err != nil {
				s.logger.Warn("failed to restart web service", "err", err)
			}
		}()
	}

	c.Redirect(http.StatusFound, "/settings?saved=web")
}

// handleSettingsSaveSystem saves System settings (timezone).
func (s *Server) handleSettingsSaveSystem(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":        currentUser(c),
			"CSRFToken":   csrfToken(c),
			"Settings":    settings,
			"ErrorSystem": msg,
		})
	}

	timezone := strings.TrimSpace(c.PostForm("timezone"))
	if _, err := time.LoadLocation(timezone); err != nil {
		renderErr(fmt.Sprintf("Invalid timezone %q. Use IANA format, e.g. Asia/Jakarta, UTC, America/New_York.", timezone))
		return
	}

	if err := s.db.SetSetting(ctx, "timezone", timezone); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	if err := ApplyTimezone(timezone); err != nil {
		s.logger.Warn("timezone apply failed (requires root/sudo)", "timezone", timezone, "err", err)
	}

	s.logger.Info("system settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?saved=system")
}

// saveSettingsMap persists a key-value map to the settings store.
func saveSettingsMap(ctx context.Context, s *Server, kvs map[string]string) error {
	for k, v := range kvs {
		if err := s.db.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
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
