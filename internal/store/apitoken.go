package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UserKeypair represents one row in the user_keypairs table.
type UserKeypair struct {
	UserID        int64
	PublicKeyPEM  string
	PrivateKeyEnc string // AES-256-GCM encrypted private key PEM, base64(nonce+ciphertext)
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// APIToken represents one row in the api_tokens table.
type APIToken struct {
	ID         int64
	UserID     int64
	Name       string
	JTI        string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// GetUserKeypair returns the keypair for a user, or nil if none exists.
// Returns a non-nil error only for real database errors (not for "not found").
func (db *DB) GetUserKeypair(ctx context.Context, userID int64) (*UserKeypair, error) {
	var kp UserKeypair
	err := db.Pool.QueryRow(ctx, `
		SELECT user_id, public_key_pem, private_key_enc, created_at, updated_at
		FROM user_keypairs WHERE user_id = $1`, userID,
	).Scan(&kp.UserID, &kp.PublicKeyPEM, &kp.PrivateKeyEnc, &kp.CreatedAt, &kp.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get keypair for user %d: %w", userID, err)
	}
	return &kp, nil
}

// GetPublicKeyByUserID returns the PEM-encoded public key for a user.
// Returns "", nil if no keypair exists yet.
// Returns "", error only for real database errors.
func (db *DB) GetPublicKeyByUserID(ctx context.Context, userID int64) (string, error) {
	var pubKey string
	err := db.Pool.QueryRow(ctx, `
		SELECT public_key_pem FROM user_keypairs WHERE user_id = $1`, userID,
	).Scan(&pubKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("get public key for user %d: %w", userID, err)
	}
	return pubKey, nil
}

// UpsertUserKeypair inserts or replaces the RSA keypair for a user.
func (db *DB) UpsertUserKeypair(ctx context.Context, userID int64, publicKeyPEM, privateKeyEnc string) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO user_keypairs (user_id, public_key_pem, private_key_enc)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET public_key_pem  = EXCLUDED.public_key_pem,
		    private_key_enc = EXCLUDED.private_key_enc,
		    updated_at      = NOW()`,
		userID, publicKeyPEM, privateKeyEnc,
	)
	if err != nil {
		return fmt.Errorf("upsert keypair for user %d: %w", userID, err)
	}
	return nil
}

// CreateAPIToken inserts a new API token metadata row and returns its DB ID.
func (db *DB) CreateAPIToken(ctx context.Context, userID int64, name, jti string, expiresAt time.Time) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, jti, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		userID, name, jti, expiresAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create api token: %w", err)
	}
	return id, nil
}

// ListAPITokensByUser returns all tokens for a user, most recently created first.
func (db *DB) ListAPITokensByUser(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, name, jti, expires_at, created_at, last_used_at
		FROM api_tokens WHERE user_id = $1
		ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	var tokens []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.JTI, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetAPITokenByJTI returns a token record by its JTI claim.
// Returns nil, nil if the token does not exist (i.e. has been revoked).
// Returns a non-nil error only for real database errors.
func (db *DB) GetAPITokenByJTI(ctx context.Context, jti string) (*APIToken, error) {
	var t APIToken
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, name, jti, expires_at, created_at, last_used_at
		FROM api_tokens WHERE jti = $1`, jti,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.JTI, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get api token by jti: %w", err)
	}
	return &t, nil
}

// GetAPITokenByID returns a token record by its DB ID.
// Returns nil, nil if not found.
// Returns a non-nil error only for real database errors.
func (db *DB) GetAPITokenByID(ctx context.Context, id int64) (*APIToken, error) {
	var t APIToken
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, name, jti, expires_at, created_at, last_used_at
		FROM api_tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.JTI, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get api token by id %d: %w", id, err)
	}
	return &t, nil
}

// DeleteAPIToken removes a single token by ID (revoke).
func (db *DB) DeleteAPIToken(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM api_tokens WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api token %d: %w", id, err)
	}
	return nil
}

// DeleteAllAPITokensByUser removes all tokens for a user.
// Called when the user's keypair is regenerated, which invalidates all existing tokens.
func (db *DB) DeleteAllAPITokensByUser(ctx context.Context, userID int64) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM api_tokens WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete all api tokens for user %d: %w", userID, err)
	}
	return nil
}

// TouchAPITokenLastUsed updates last_used_at to now for a given JTI.
// Errors are intentionally swallowed — this is best-effort audit metadata.
func (db *DB) TouchAPITokenLastUsed(ctx context.Context, jti string) {
	db.Pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = NOW() WHERE jti = $1`, jti) //nolint:errcheck
}
