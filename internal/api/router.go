package api

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"

	"github.com/bodsink/dns-rpz/internal/store"
	"github.com/bodsink/dns-rpz/internal/syncer"
)

// Server holds all dependencies for the HTTP API server.
type Server struct {
	db     *store.DB
	syncer *syncer.ZoneSyncer
	logger *slog.Logger
	router *gin.Engine
}

// NewServer creates and configures the HTTP server with all routes and middleware.
func NewServer(db *store.DB, zoneSyncer *syncer.ZoneSyncer, logger *slog.Logger, templatesDir, staticDir string) *Server {
	gin.SetMode(gin.ReleaseMode)

	s := &Server{
		db:     db,
		syncer: zoneSyncer,
		logger: logger,
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.Use(s.middlewareSecurityHeaders())
	r.Use(s.middlewareLogger())

	// Build per-page template renderer: parses base.html + page template together
	// so each page has its own isolated {{define "content"}} — fixes LoadHTMLGlob
	// limitation where all pages share one template set and "content" gets overwritten.
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"slice": func(s string, i, j int) string {
			if i >= len(s) {
				return ""
			}
			if j > len(s) {
				j = len(s)
			}
			return s[i:j]
		},
		"sub": func(a, b int) int { return a - b },
		"add": func(a, b int) int { return a + b },
		"mul": func(a, b int) int { return a * b },
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
		"int": func(v int64) int { return int(v) },
	}
	r.HTMLRender = newRenderer(templatesDir, funcMap)

	// Static assets caching: app.css and app.js are no-cache (frequently updated),
	// library files get long-term cache (1 year, immutable).
	r.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		if p == "/static/app.css" || p == "/static/app.js" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		} else if strings.HasPrefix(p, "/static/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		c.Next()
	})
	r.Static("/static", staticDir)

	// --- Public routes ---
	r.GET("/login", s.handleLoginPage)
	r.POST("/login", s.middlewareRateLimit(), s.handleLoginSubmit)
	r.POST("/logout", s.handleLogout)

	// --- Protected routes (require valid session) ---
	auth := r.Group("/")
	auth.Use(s.middlewareRequireSession())
	{
		auth.GET("/", s.handleDashboard)

		// Zones
		auth.GET("/zones", s.handleZoneList)
		auth.GET("/zones/new", s.middlewareRequireAdmin(), s.handleZoneNew)
		auth.POST("/zones", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneCreate)
		auth.GET("/zones/:id", s.handleZoneDetail)
		auth.GET("/zones/:id/edit", s.middlewareRequireAdmin(), s.handleZoneEdit)
		auth.POST("/zones/:id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneUpdate)
		auth.POST("/zones/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneDelete)
		auth.POST("/zones/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneToggle)
		auth.POST("/zones/:id/sync", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneTriggerSync)
		auth.GET("/zones/:id/records", s.handleRecordList)
		auth.GET("/zones/:id/history", s.handleZoneSyncHistory)

		// Settings
		auth.GET("/settings", s.middlewareRequireAdmin(), s.handleSettingsPage)
		auth.POST("/settings", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSave)

		// IP Filters (ACL)
		auth.GET("/ip-filters", s.middlewareRequireAdmin(), s.handleIPFilterList)
		auth.POST("/ip-filters", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterCreate)
		auth.POST("/ip-filters/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterDelete)
		auth.POST("/ip-filters/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterToggle)

		// Users
		auth.GET("/users", s.middlewareRequireAdmin(), s.handleUserList)
		auth.GET("/users/new", s.middlewareRequireAdmin(), s.handleUserNew)
		auth.POST("/users", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserCreate)
		auth.GET("/users/:id/edit", s.middlewareRequireAdmin(), s.handleUserEdit)
		auth.POST("/users/:id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserUpdate)
		auth.POST("/users/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserDelete)
		auth.POST("/users/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserToggle)

		// Sync history (global)
		auth.GET("/sync-history", s.handleSyncHistoryList)

		// Profile (change password — available to all authenticated users)
		auth.GET("/profile", s.handleProfilePage)
		auth.POST("/profile", s.middlewareCSRF(), s.handleProfileSave)
	}

	s.router = r
	return s
}

// Start runs the HTTPS server on the given address using the provided TLS cert/key.
// Blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Start(ctx context.Context, addr string, tls *TLSConfig) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("dashboard listening (HTTPS)", "addr", addr)
		if err := srv.ListenAndServeTLS(tls.CertFile, tls.KeyFile); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return srv.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}
