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
	"github.com/PS-safe/auth/verify"
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

	newUserAndToken := func(s a.Store, ttl time.Duration) (*a.User, string) {
		t.Helper()
		hash, _ := password.Hash("x")
		u, err := s.CreateUser(ctx, a.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Role: "user"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		tok, _ := verify.Generate()
		err = s.CreateEmailVerification(ctx, a.EmailVerification{
			TokenHash: verify.Hash(tok),
			UserID:    u.ID,
			Email:     u.Email,
			ExpiresAt: time.Now().Add(ttl),
		})
		if err != nil {
			t.Fatalf("CreateEmailVerification: %v", err)
		}
		return u, tok
	}

	t.Run("verify_consume_marks_user_verified", func(t *testing.T) {
		s := newStore()
		u, tok := newUserAndToken(s, time.Hour)
		v, err := s.ConsumeEmailVerification(ctx, verify.Hash(tok))
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if v.ConsumedAt == nil {
			t.Error("returned verification has nil ConsumedAt")
		}
		got, _ := s.UserByID(ctx, u.ID)
		if got.VerifiedAt == nil {
			t.Error("user.VerifiedAt is still nil after Consume")
		}
	})

	t.Run("verify_expired_token_rejected", func(t *testing.T) {
		s := newStore()
		_, tok := newUserAndToken(s, -time.Second)
		_, err := s.ConsumeEmailVerification(ctx, verify.Hash(tok))
		if !errors.Is(err, a.ErrExpired) {
			t.Errorf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("verify_already_consumed_rejected", func(t *testing.T) {
		s := newStore()
		_, tok := newUserAndToken(s, time.Hour)
		if _, err := s.ConsumeEmailVerification(ctx, verify.Hash(tok)); err != nil {
			t.Fatalf("first Consume: %v", err)
		}
		_, err := s.ConsumeEmailVerification(ctx, verify.Hash(tok))
		if !errors.Is(err, a.ErrAlreadyConsumed) {
			t.Errorf("err = %v, want ErrAlreadyConsumed", err)
		}
	})

	t.Run("verify_unknown_token_not_found", func(t *testing.T) {
		s := newStore()
		_, err := s.ConsumeEmailVerification(ctx, verify.Hash("never-issued"))
		if !errors.Is(err, a.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestMemoryStore(t *testing.T) {
	RunContract(t, func() a.Store { return memory.New() })
}
