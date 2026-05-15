// Package auth defines storage-agnostic interfaces and types for an
// email-and-password authentication service with opaque session tokens
// and role-based access control.
//
// Subpackages:
//
//	password  — argon2id hashing
//	session   — opaque session-token generation + hashing
//	verify    — opaque email-verification-token generation + hashing
//	reset     — opaque password-reset-token generation + hashing
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
	// VerifiedAt is non-nil after the user proves ownership of their email.
	// Callers decide policy — block login until verified, gate features, etc.
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// Session represents a logged-in user's bearer token. The TokenHash is what's
// stored; the raw Token is shown to the user exactly once at issue time.
type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// EmailVerification is a one-shot, single-use token issued during signup (or
// on resend) and consumed when the user clicks the verification link.
//
// Like sessions, only sha256(token) is persisted; the raw token leaves the
// server exactly once, in the email body.
//
// Email captures the address the verification was issued FOR, snapshotted at
// issue time. If a user later changes email, an old verification link still
// proves ownership of the old address (which may or may not match the
// user's current email — caller's policy).
type EmailVerification struct {
	TokenHash  string
	UserID     string
	Email      string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// PasswordReset is a one-shot, single-use token issued when a user requests
// a password reset and consumed when they pick a new password. Like other
// tokens in this package, only sha256(token) is persisted.
type PasswordReset struct {
	TokenHash  string
	UserID     string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
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

	// CreateEmailVerification persists a new verification record. TokenHash
	// should be the sha256 of the raw token — the raw token is never stored.
	CreateEmailVerification(ctx context.Context, v EmailVerification) error

	// ConsumeEmailVerification atomically validates the token (exists, not
	// expired, not already consumed), marks it consumed, marks the owning
	// user verified, and returns the verification record. Returns
	// ErrNotFound, ErrExpired, or ErrAlreadyConsumed on the respective
	// failure modes — never leaves the DB in a partial state.
	ConsumeEmailVerification(ctx context.Context, tokenHash string) (*EmailVerification, error)

	// CreatePasswordReset persists a new reset record. TokenHash should be
	// sha256 of the raw token — the raw token is never stored.
	CreatePasswordReset(ctx context.Context, r PasswordReset) error

	// ConsumePasswordReset atomically validates the token, marks it
	// consumed, sets the user's password hash to newPasswordHash, and
	// revokes ALL of the user's sessions (if a reset is being run, every
	// existing session is suspect). Returns the reset record.
	ConsumePasswordReset(ctx context.Context, tokenHash, newPasswordHash string) (*PasswordReset, error)
}

var (
	ErrNotFound        = errors.New("auth: not found")
	ErrEmailTaken      = errors.New("auth: email already registered")
	ErrInvalidInput    = errors.New("auth: invalid input")
	ErrSessionExpired  = errors.New("auth: session expired")
	ErrExpired         = errors.New("auth: expired")
	ErrAlreadyConsumed = errors.New("auth: already consumed")
)
