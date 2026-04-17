package store

import (
	"context"
	"fmt"
	"time"
)

// User represents one row in the users table.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string // "admin" or "viewer"
	Enabled      bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// Session represents one row in the sessions table.
type Session struct {
	ID        string
	UserID    int64
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

// GetUserByUsername fetches a user by username.
// Returns nil, nil if not found.
func (db *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, nil // not found
	}
	return &u, nil
}

// GetUserByID fetches a user by ID.
// Returns nil, nil if not found.
func (db *DB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, nil // not found
	}
	return &u, nil
}

// ListUsers returns all users ordered by username.
func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CreateUser inserts a new user and returns its ID.
func (db *DB) CreateUser(ctx context.Context, username, passwordHash, role string) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id`,
		username, passwordHash, role,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create user %q: %w", username, err)
	}
	return id, nil
}

// UpdateUserPassword updates the password hash for a user.
func (db *DB) UpdateUserPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, id)
	if err != nil {
		return fmt.Errorf("update password for user %d: %w", id, err)
	}
	return nil
}

// SetUserEnabled enables or disables a user account.
func (db *DB) SetUserEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET enabled = $1 WHERE id = $2`, enabled, id)
	if err != nil {
		return fmt.Errorf("set user %d enabled=%v: %w", id, enabled, err)
	}
	return nil
}

// UpdateLastLogin updates the last_login_at timestamp for a user.
func (db *DB) UpdateLastLogin(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET last_login_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("update last login for user %d: %w", id, err)
	}
	return nil
}

// DeleteUser removes a user by ID.
func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user %d: %w", id, err)
	}
	return nil
}

// UserExists checks whether at least one user exists in the database.
// Used at startup to determine if the default admin seed is needed.
func (db *DB) UserExists(ctx context.Context) (bool, error) {
	var count int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	return count > 0, nil
}

// --- Session ---

// CreateSession inserts a new session row.
func (db *DB) CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time, ip, userAgent string) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, NULLIF($5,''))`,
		id, userID, expiresAt, ip, userAgent,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession fetches a valid (non-expired) session by ID.
// Returns nil, nil if not found or expired.
func (db *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	var s Session
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at, COALESCE(ip_address::text,''), COALESCE(user_agent,''), created_at
		FROM sessions
		WHERE id = $1 AND expires_at > NOW()`, id,
	).Scan(&s.ID, &s.UserID, &s.ExpiresAt, &s.IPAddress, &s.UserAgent, &s.CreatedAt)
	if err != nil {
		return nil, nil // not found or expired
	}
	return &s, nil
}

// DeleteSession removes a session by ID (logout).
func (db *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete session %q: %w", id, err)
	}
	return nil
}

// CleanupExpiredSessions removes all expired session rows.
// Should be called periodically (e.g. hourly) to keep the table lean.
func (db *DB) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= NOW()`)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
