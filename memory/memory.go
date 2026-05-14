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
	mu        sync.RWMutex
	users     map[string]*a.User // id -> user
	usersByEmail map[string]string // email (lowercase) -> id
	sessions  map[string]*a.Session // tokenHash -> session
}

func New() *Store {
	return &Store{
		users:        make(map[string]*a.User),
		usersByEmail: make(map[string]string),
		sessions:     make(map[string]*a.Session),
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
