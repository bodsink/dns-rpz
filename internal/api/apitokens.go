package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// tokenDateDefaults returns min and default expiry date strings (YYYY-MM-DD).
func tokenDateDefaults() (minDate, defaultDate string) {
	now := time.Now()
	minDate = now.AddDate(0, 0, 1).Format("2006-01-02")
	defaultDate = now.AddDate(1, 0, 0).Format("2006-01-02")
	return
}

// handleAPITokensPage renders the API tokens management page for the current user.
func (s *Server) handleAPITokensPage(c *gin.Context) {
	user := currentUser(c)
	tokens, err := s.db.ListAPITokensByUser(c.Request.Context(), user.ID)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load API tokens", err)
		return
	}

	kp, err := s.db.GetUserKeypair(c.Request.Context(), user.ID)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load keypair info", err)
		return
	}

	minDate, defaultDate := tokenDateDefaults()
	c.HTML(http.StatusOK, "api_tokens.html", gin.H{
		"User":              user,
		"CSRFToken":         csrfToken(c),
		"ActivePage":        "api_tokens",
		"Tokens":            tokens,
		"HasKeypair":        kp != nil,
		"MinExpiryDate":     minDate,
		"DefaultExpiryDate": defaultDate,
	})
}

// handleAPITokenCreate generates a new JWT API token for the current user.
// If the user has no keypair yet, one is generated first.
// The full JWT is shown exactly once — it is NOT stored in the DB.
func (s *Server) handleAPITokenCreate(c *gin.Context) {
	user := currentUser(c)

	if s.keyEncKey == "" {
		s.renderError(c, http.StatusServiceUnavailable,
			"API tokens are not available: KEY_ENCRYPTION_KEY is not configured", nil)
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	expiryDate := c.PostForm("expiry_date")
	if name == "" {
		s.renderError(c, http.StatusBadRequest, "Token name is required", nil)
		return
	}
	if len(name) > 100 {
		s.renderError(c, http.StatusBadRequest, "Token name must not exceed 100 characters", nil)
		return
	}

	expiresAt, err := time.ParseInLocation("2006-01-02", expiryDate, time.Local)
	if err != nil || expiresAt.Before(time.Now()) {
		s.renderError(c, http.StatusBadRequest, "Expiry date is required and must be in the future", nil)
		return
	}
	// Set to end of chosen day
	expiresAt = time.Date(expiresAt.Year(), expiresAt.Month(), expiresAt.Day(), 23, 59, 59, 0, time.Local)

	// Ensure the user has an RSA keypair. Generate one if not.
	kp, err := s.db.GetUserKeypair(c.Request.Context(), user.ID)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load keypair", err)
		return
	}

	var privateKeyPEM []byte

	if kp == nil {
		// First-time: generate RSA-2048 keypair for this user.
		privKey, genErr := generateRSAKeypair()
		if genErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to generate RSA keypair", genErr)
			return
		}
		privPEM, pemErr := privateKeyToPEM(privKey)
		if pemErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to encode private key", pemErr)
			return
		}
		pubPEM, pubErr := publicKeyToPEM(&privKey.PublicKey)
		if pubErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to encode public key", pubErr)
			return
		}
		enc, encErr := encryptPrivateKey(privPEM, s.keyEncKey)
		if encErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to encrypt private key", encErr)
			return
		}
		if upsertErr := s.db.UpsertUserKeypair(c.Request.Context(), user.ID, string(pubPEM), enc); upsertErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to save keypair", upsertErr)
			return
		}
		privateKeyPEM = privPEM
	} else {
		// Existing keypair: decrypt the stored private key.
		privPEM, decErr := decryptPrivateKey(kp.PrivateKeyEnc, s.keyEncKey)
		if decErr != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to decrypt private key", decErr)
			return
		}
		privateKeyPEM = privPEM
	}

	// Generate a unique JTI.
	jti, err := generateJTI()
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to generate token ID", err)
		return
	}

	// Sign the JWT.
	tokenString, err := signAPIToken(privateKeyPEM, user.ID, jti, user.Role, expiresAt)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to sign token", err)
		return
	}

	// Persist token metadata (not the JWT itself).
	if _, err := s.db.CreateAPIToken(c.Request.Context(), user.ID, name, jti, expiresAt); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save token metadata", err)
		return
	}

	s.logger.Info("api token created", "user", user.Username, "token_name", name, "expires_at", expiresAt)

	// Show the token once — user must copy it now.
	tokens, _ := s.db.ListAPITokensByUser(c.Request.Context(), user.ID)
	minDate, defaultDate := tokenDateDefaults()
	c.HTML(http.StatusOK, "api_tokens.html", gin.H{
		"User":               user,
		"CSRFToken":          csrfToken(c),
		"ActivePage":         "api_tokens",
		"Tokens":             tokens,
		"HasKeypair":         true,
		"NewToken":           tokenString,
		"NewTokenName":       name,
		"MinExpiryDate":      minDate,
		"DefaultExpiryDate":  defaultDate,
	})
}

// handleAPITokenRevoke deletes a single API token (revoke).
func (s *Server) handleAPITokenRevoke(c *gin.Context) {
	user := currentUser(c)
	tokenID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.renderError(c, http.StatusBadRequest, "Invalid token ID", nil)
		return
	}

	// Verify ownership: user can only revoke their own tokens.
	token, err := s.db.GetAPITokenByID(c.Request.Context(), tokenID)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to fetch token", err)
		return
	}
	if token == nil {
		s.renderError(c, http.StatusNotFound, "Token not found", nil)
		return
	}
	if token.UserID != user.ID && user.Role != "admin" {
		s.renderError(c, http.StatusForbidden, "Cannot revoke another user's token", nil)
		return
	}

	if err := s.db.DeleteAPIToken(c.Request.Context(), tokenID); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to revoke token", err)
		return
	}

	s.logger.Info("api token revoked", "user", user.Username, "token_id", tokenID)
	c.Redirect(http.StatusFound, "/api-tokens")
}

// handleAPIKeypairRegenerate regenerates the RSA keypair for the current user.
// This invalidates ALL existing tokens for the user.
func (s *Server) handleAPIKeypairRegenerate(c *gin.Context) {
	user := currentUser(c)

	if s.keyEncKey == "" {
		s.renderError(c, http.StatusServiceUnavailable,
			"API tokens are not available: KEY_ENCRYPTION_KEY is not configured", nil)
		return
	}

	privKey, err := generateRSAKeypair()
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to generate RSA keypair", err)
		return
	}
	privPEM, err := privateKeyToPEM(privKey)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to encode private key", err)
		return
	}
	pubPEM, err := publicKeyToPEM(&privKey.PublicKey)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to encode public key", err)
		return
	}
	enc, err := encryptPrivateKey(privPEM, s.keyEncKey)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to encrypt private key", err)
		return
	}

	// Delete all existing tokens first (they are now invalid).
	if err := s.db.DeleteAllAPITokensByUser(c.Request.Context(), user.ID); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to revoke old tokens", err)
		return
	}

	if err := s.db.UpsertUserKeypair(c.Request.Context(), user.ID, string(pubPEM), enc); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save new keypair", err)
		return
	}

	s.logger.Info("api keypair regenerated", "user", user.Username)
	c.Redirect(http.StatusFound, "/api-tokens")
}
