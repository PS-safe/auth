package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	a "github.com/PS-safe/auth"
	"github.com/PS-safe/auth/memory"
	"github.com/PS-safe/auth/password"
	"github.com/PS-safe/auth/session"
)

func RunContract(t *testing.T, newStore func() a.Store) {
	t.Helper()
	ctx := context.Background()

	t.Run("signup_then_lookup", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("hunter2")
		u, err := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.UserByEmail(ctx, "A@B.COM")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != u.ID {
			t.Errorf("ID mismatch %q vs %q", got.ID, u.ID)
		}
	})

	t.Run("duplicate_email_rejected", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("x")
		_, _ = s.CreateUser(ctx, a.User{ID: "u1", Email: "dup@b.com", PasswordHash: hash, Role: "user"})
		_, err := s.CreateUser(ctx, a.User{ID: "u2", Email: "dup@b.com", PasswordHash: hash, Role: "user"})
		if !errors.Is(err, a.ErrEmailTaken) {
			t.Errorf("err = %v, want ErrEmailTaken", err)
		}
	})

	t.Run("session_roundtrip", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("x")
		u, _ := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})

		tok, _ := session.Generate()
		err := s.CreateSession(ctx, a.Session{
			TokenHash: session.Hash(tok),
			UserID:    u.ID,
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, gotUser, err := s.SessionByTokenHash(ctx, session.Hash(tok))
		if err != nil {
			t.Fatal(err)
		}
		if sess.UserID != u.ID || gotUser.Email != "a@b.com" {
			t.Errorf("unexpected session/user")
		}
	})

	t.Run("expired_session_rejected", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("x")
		u, _ := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})

		tok, _ := session.Generate()
		_ = s.CreateSession(ctx, a.Session{
			TokenHash: session.Hash(tok),
			UserID:    u.ID,
			ExpiresAt: time.Now().Add(-time.Second),
		})
		_, _, err := s.SessionByTokenHash(ctx, session.Hash(tok))
		if !errors.Is(err, a.ErrSessionExpired) {
			t.Errorf("err = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("delete_session", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("x")
		u, _ := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})
		tok, _ := session.Generate()
		_ = s.CreateSession(ctx, a.Session{TokenHash: session.Hash(tok), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})
		if err := s.DeleteSession(ctx, session.Hash(tok)); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.SessionByTokenHash(ctx, session.Hash(tok))
		if !errors.Is(err, a.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("delete_all_user_sessions", func(t *testing.T) {
		s := newStore()
		hash, _ := password.Hash("x")
		u, _ := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})
		for range 3 {
			tok, _ := session.Generate()
			_ = s.CreateSession(ctx, a.Session{TokenHash: session.Hash(tok), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})
		}
		if err := s.DeleteUserSessions(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMemoryStore(t *testing.T) {
	RunContract(t, func() a.Store { return memory.New() })
}
