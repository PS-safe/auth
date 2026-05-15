// Package memory is an in-process Store for tests and dev.
package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	a "github.com/PS-safe/auth"
)

type Store struct {
	mu            sync.RWMutex
	users         map[string]*a.User              // id -> user
	usersByEmail  map[string]string               // email (lowercase) -> id
	sessions      map[string]*a.Session           // tokenHash -> session
	verifications map[string]*a.EmailVerification // tokenHash -> verification
	resets        map[string]*a.PasswordReset     // tokenHash -> reset
}

func New() *Store {
	return &Store{
		users:         make(map[string]*a.User),
		usersByEmail:  make(map[string]string),
		sessions:      make(map[string]*a.Session),
		verifications: make(map[string]*a.EmailVerification),
		resets:        make(map[string]*a.PasswordReset),
	}
}

func (s *Store) CreateUser(_ context.Context, u a.User) (*a.User, error) {
	if u.ID == "" || u.Email == "" || u.PasswordHash == "" {
		return nil, a.ErrInvalidInput
	}
	email := strings.ToLower(u.Email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.usersByEmail[email]; exists {
		return nil, a.ErrEmailTaken
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	u.Email = email
	cp := u
	s.users[u.ID] = &cp
	s.usersByEmail[email] = u.ID
	out := cp
	return &out, nil
}

func (s *Store) UserByEmail(_ context.Context, email string) (*a.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByEmail[strings.ToLower(email)]
	if !ok {
		return nil, a.ErrNotFound
	}
	u := *s.users[id]
	return &u, nil
}

func (s *Store) UserByID(_ context.Context, id string) (*a.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, a.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *Store) CreateSession(_ context.Context, sess a.Session) error {
	if sess.TokenHash == "" || sess.UserID == "" {
		return a.ErrInvalidInput
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[sess.UserID]; !ok {
		return a.ErrNotFound
	}
	cp := sess
	s.sessions[sess.TokenHash] = &cp
	return nil
}

func (s *Store) SessionByTokenHash(_ context.Context, tokenHash string) (*a.Session, *a.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[tokenHash]
	if !ok {
		return nil, nil, a.ErrNotFound
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return nil, nil, a.ErrSessionExpired
	}
	user, ok := s.users[sess.UserID]
	if !ok {
		return nil, nil, a.ErrNotFound
	}
	scp := *sess
	ucp := *user
	return &scp, &ucp, nil
}

func (s *Store) DeleteSession(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[tokenHash]; !ok {
		return a.ErrNotFound
	}
	delete(s.sessions, tokenHash)
	return nil
}

func (s *Store) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, h)
		}
	}
	return nil
}

func (s *Store) CreateEmailVerification(_ context.Context, v a.EmailVerification) error {
	if v.TokenHash == "" || v.UserID == "" || v.Email == "" {
		return a.ErrInvalidInput
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[v.UserID]; !ok {
		return a.ErrNotFound
	}
	cp := v
	s.verifications[v.TokenHash] = &cp
	return nil
}

func (s *Store) ConsumeEmailVerification(_ context.Context, tokenHash string) (*a.EmailVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.verifications[tokenHash]
	if !ok {
		return nil, a.ErrNotFound
	}
	if v.ConsumedAt != nil {
		return nil, a.ErrAlreadyConsumed
	}
	if time.Now().UTC().After(v.ExpiresAt) {
		return nil, a.ErrExpired
	}
	user, ok := s.users[v.UserID]
	if !ok {
		// User deleted between create and consume — same as not-found from
		// the verification's perspective.
		return nil, a.ErrNotFound
	}
	now := time.Now().UTC()
	v.ConsumedAt = &now
	user.VerifiedAt = &now
	cp := *v
	return &cp, nil
}

func (s *Store) CreatePasswordReset(_ context.Context, r a.PasswordReset) error {
	if r.TokenHash == "" || r.UserID == "" {
		return a.ErrInvalidInput
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[r.UserID]; !ok {
		return a.ErrNotFound
	}
	cp := r
	s.resets[r.TokenHash] = &cp
	return nil
}

func (s *Store) ConsumePasswordReset(_ context.Context, tokenHash, newPasswordHash string) (*a.PasswordReset, error) {
	if newPasswordHash == "" {
		return nil, a.ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resets[tokenHash]
	if !ok {
		return nil, a.ErrNotFound
	}
	if r.ConsumedAt != nil {
		return nil, a.ErrAlreadyConsumed
	}
	if time.Now().UTC().After(r.ExpiresAt) {
		return nil, a.ErrExpired
	}
	user, ok := s.users[r.UserID]
	if !ok {
		return nil, a.ErrNotFound
	}
	now := time.Now().UTC()
	r.ConsumedAt = &now
	user.PasswordHash = newPasswordHash
	// Reset implies the previous password may be compromised — kill every
	// existing session so the attacker can't ride one in.
	for h, sess := range s.sessions {
		if sess.UserID == user.ID {
			delete(s.sessions, h)
		}
	}
	cp := *r
	return &cp, nil
}
