// Package auth defines storage-agnostic interfaces and types for an
// email-and-password authentication service with opaque session tokens
// and role-based access control.
//
// Subpackages:
//
//	password  — argon2id hashing
//	session   — opaque token generation + hashing
//	rbac      — roles and permissions
//	memory    — in-process Store (tests, dev)
//	postgres  — durable Store (production)
//	middleware— net/http middleware (RequireSession, RequirePermission)
package auth

import (
	"context"
	"errors"
	"time"
)

// User is an authenticated identity.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// Session represents a logged-in user's bearer token. The TokenHash is what's
// stored; the raw Token is shown to the user exactly once at issue time.
type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store is the contract every backend must satisfy.
type Store interface {
	// CreateUser persists a new user. Email must be unique.
	CreateUser(ctx context.Context, u User) (*User, error)

	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByID(ctx context.Context, id string) (*User, error)

	// CreateSession persists a new session. TokenHash should be the sha256 of
	// the raw bearer token — the raw token is never stored.
	CreateSession(ctx context.Context, s Session) error

	// SessionByTokenHash looks up an active session (not expired) and the
	// user it belongs to in a single round trip.
	SessionByTokenHash(ctx context.Context, tokenHash string) (*Session, *User, error)

	// DeleteSession removes one session (logout).
	DeleteSession(ctx context.Context, tokenHash string) error

	// DeleteUserSessions removes all sessions for a user (logout everywhere /
	// password change cleanup).
	DeleteUserSessions(ctx context.Context, userID string) error
}

var (
	ErrNotFound       = errors.New("auth: not found")
	ErrEmailTaken     = errors.New("auth: email already registered")
	ErrInvalidInput   = errors.New("auth: invalid input")
	ErrSessionExpired = errors.New("auth: session expired")
)
