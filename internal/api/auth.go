package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// handleLoginPage renders the login form.
func (s *Server) handleLoginPage(c *gin.Context) {
	// Already logged in → redirect to dashboard
	if _, err := c.Cookie(sessionCookieName); err == nil {
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

// handleLoginSubmit processes the login form submission.
func (s *Server) handleLoginSubmit(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	renderError := func(msg string) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"Error": msg,
		})
	}

	if username == "" || password == "" {
		renderError("Username and password are required.")
		return
	}

	user, err := s.db.GetUserByUsername(c.Request.Context(), username)
	if err != nil {
		s.logger.Error("login: db error", "err", err)
		renderError("An internal error occurred. Please try again.")
		return
	}

	// Constant-time check: always run bcrypt even if user not found (prevent timing attack)
	hashToCheck := "$2a$12$invalidhashusedtopreventtimingattacksonnonexistentusers"
	if user != nil {
		hashToCheck = user.PasswordHash
	}

	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(password))

	if user == nil || !user.Enabled || bcryptErr != nil {
		slog.Warn("failed login attempt", "username", username, "ip", c.ClientIP())
		renderError("Invalid username or password.")
		return
	}

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		s.logger.Error("login: failed to generate session ID", "err", err)
		renderError("An internal error occurred. Please try again.")
		return
	}

	expiresAt := time.Now().Add(sessionDuration)
	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	if err := s.db.CreateSession(c.Request.Context(), sessionID, user.ID, expiresAt, ip, ua); err != nil {
		s.logger.Error("login: failed to create session", "err", err)
		renderError("An internal error occurred. Please try again.")
		return
	}

	if err := s.db.UpdateLastLogin(c.Request.Context(), user.ID); err != nil {
		s.logger.Warn("login: failed to update last_login_at", "user", user.Username, "err", err)
	}

	setSessionCookie(c, sessionID)
	slog.Info("user logged in", "username", user.Username, "ip", ip)
	c.Redirect(http.StatusFound, "/")
}

// handleLogout destroys the session and clears the cookie.
func (s *Server) handleLogout(c *gin.Context) {
	sessionID, err := c.Cookie(sessionCookieName)
	if err == nil && sessionID != "" {
		if err := s.db.DeleteSession(c.Request.Context(), sessionID); err != nil {
			s.logger.Warn("logout: failed to delete session", "err", err)
		}
	}
	clearSessionCookie(c)
	c.Redirect(http.StatusFound, "/login")
}
