// Package postgres is a Postgres-backed Store for auth.
package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	a "github.com/PS-safe/auth"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func (s *Store) CreateUser(ctx context.Context, u a.User) (*a.User, error) {
	if u.ID == "" || u.Email == "" || u.PasswordHash == "" {
		return nil, a.ErrInvalidInput
	}
	email := strings.ToLower(u.Email)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO users (id, email, password_hash, role)
		VALUES ($1, $2, $3, COALESCE(NULLIF($4, ''), 'user'))
		RETURNING `+userColumns, u.ID, email, u.PasswordHash, u.Role)
	out, err := scanUser(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, a.ErrEmailTaken
		}
		return nil, err
	}
	return out, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*a.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+userColumns+`
		  FROM users WHERE lower(email) = lower($1)
	`, email)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, a.ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s *Store) UserByID(ctx context.Context, id string) (*a.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+userColumns+`
		  FROM users WHERE id = $1
	`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, a.ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, sess a.Session) error {
	if sess.TokenHash == "" || sess.UserID == "" {
		return a.ErrInvalidInput
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, sess.TokenHash, sess.UserID, sess.ExpiresAt)
	return err
}

func (s *Store) SessionByTokenHash(ctx context.Context, tokenHash string) (*a.Session, *a.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT s.token_hash, s.user_id, s.expires_at, s.created_at,
		       u.id, u.email, u.password_hash, u.role, u.verified_at, u.created_at
		  FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1
	`, tokenHash)
	var sess a.Session
	var user a.User
	if err := row.Scan(
		&sess.TokenHash, &sess.UserID, &sess.ExpiresAt, &sess.CreatedAt,
		&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.VerifiedAt, &user.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, a.ErrNotFound
		}
		return nil, nil, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return nil, nil, a.ErrSessionExpired
	}
	return &sess, &user, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return a.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (s *Store) CreateEmailVerification(ctx context.Context, v a.EmailVerification) error {
	if v.TokenHash == "" || v.UserID == "" || v.Email == "" {
		return a.ErrInvalidInput
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO email_verifications (token_hash, user_id, email, expires_at)
		VALUES ($1, $2, $3, $4)
	`, v.TokenHash, v.UserID, v.Email, v.ExpiresAt)
	return err
}

// ConsumeEmailVerification runs the validation, mark-consumed, and
// mark-user-verified inside one transaction. SELECT FOR UPDATE prevents two
// concurrent clicks on the same link from both succeeding.
func (s *Store) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*a.EmailVerification, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var v a.EmailVerification
	err = tx.QueryRow(ctx, `
		SELECT token_hash, user_id, email, expires_at, consumed_at, created_at
		  FROM email_verifications
		 WHERE token_hash = $1
		 FOR UPDATE
	`, tokenHash).Scan(&v.TokenHash, &v.UserID, &v.Email, &v.ExpiresAt, &v.ConsumedAt, &v.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, a.ErrNotFound
		}
		return nil, err
	}
	if v.ConsumedAt != nil {
		return nil, a.ErrAlreadyConsumed
	}
	now := time.Now().UTC()
	if now.After(v.ExpiresAt) {
		return nil, a.ErrExpired
	}

	if _, err := tx.Exec(ctx, `
		UPDATE email_verifications SET consumed_at = $1 WHERE token_hash = $2
	`, now, tokenHash); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET verified_at = COALESCE(verified_at, $1) WHERE id = $2
	`, now, v.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	v.ConsumedAt = &now
	return &v, nil
}

func (s *Store) CreatePasswordReset(ctx context.Context, r a.PasswordReset) error {
	if r.TokenHash == "" || r.UserID == "" {
		return a.ErrInvalidInput
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO password_resets (token_hash, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, r.TokenHash, r.UserID, r.ExpiresAt)
	return err
}

// ConsumePasswordReset validates the token, sets the new password hash, and
// revokes every existing session for the user — all in one transaction.
// SELECT FOR UPDATE serializes concurrent clicks on the same reset link.
func (s *Store) ConsumePasswordReset(ctx context.Context, tokenHash, newPasswordHash string) (*a.PasswordReset, error) {
	if newPasswordHash == "" {
		return nil, a.ErrInvalidInput
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var r a.PasswordReset
	err = tx.QueryRow(ctx, `
		SELECT token_hash, user_id, expires_at, consumed_at, created_at
		  FROM password_resets
		 WHERE token_hash = $1
		 FOR UPDATE
	`, tokenHash).Scan(&r.TokenHash, &r.UserID, &r.ExpiresAt, &r.ConsumedAt, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, a.ErrNotFound
		}
		return nil, err
	}
	if r.ConsumedAt != nil {
		return nil, a.ErrAlreadyConsumed
	}
	now := time.Now().UTC()
	if now.After(r.ExpiresAt) {
		return nil, a.ErrExpired
	}

	if _, err := tx.Exec(ctx, `UPDATE password_resets SET consumed_at = $1 WHERE token_hash = $2`, now, tokenHash); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, newPasswordHash, r.UserID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, r.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	r.ConsumedAt = &now
	return &r, nil
}

// userColumns lists user fields in the order scanUser expects. Centralized so
// every SELECT/RETURNING that hydrates a User stays in sync with the scan.
const userColumns = `id, email, password_hash, role, verified_at, created_at`

func scanUser(row pgx.Row) (*a.User, error) {
	var u a.User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.VerifiedAt, &u.CreatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

type sqlStater interface{ SQLState() string }

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var s sqlStater
	if errors.As(err, &s) {
		return s.SQLState() == "23505"
	}
	return false
}
