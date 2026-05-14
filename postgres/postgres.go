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
		RETURNING id, email, password_hash, role, created_at
	`, u.ID, email, u.PasswordHash, u.Role)
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
		SELECT id, email, password_hash, role, created_at
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
		SELECT id, email, password_hash, role, created_at
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
		       u.id, u.email, u.password_hash, u.role, u.created_at
		  FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1
	`, tokenHash)
	var sess a.Session
	var user a.User
	if err := row.Scan(
		&sess.TokenHash, &sess.UserID, &sess.ExpiresAt, &sess.CreatedAt,
		&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt,
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

func scanUser(row pgx.Row) (*a.User, error) {
	var u a.User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
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
