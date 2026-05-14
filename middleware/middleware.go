// Package middleware adapts the auth Store to net/http session enforcement
// and role-based authorization.
package middleware

import (
	"context"
	"net/http"
	"strings"

	a "github.com/PS-safe/auth"
	"github.com/PS-safe/auth/rbac"
	"github.com/PS-safe/auth/session"
)

// CookieName is the default name for the bearer cookie. Override via WithCookieName.
const CookieName = "auth_session"

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
)

// Option configures session enforcement.
type Option func(*config)

type config struct {
	cookieName string
}

func WithCookieName(name string) Option { return func(c *config) { c.cookieName = name } }

// RequireSession extracts a bearer token from the auth_session cookie or the
// Authorization header, looks it up, and attaches the session + user to the
// request context. On failure it writes 401.
func RequireSession(store a.Store, opts ...Option) func(http.Handler) http.Handler {
	cfg := config{cookieName: CookieName}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r, cfg.cookieName)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sess, user, err := store.SessionByTokenHash(r.Context(), session.Hash(token))
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUser, user)
			ctx = context.WithValue(ctx, ctxSession, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission must wrap a handler that already passed RequireSession.
// It returns 403 if the user's role doesn't grant perm.
func RequirePermission(perm rbac.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !rbac.Has(rbac.Role(user.Role), perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UserFromContext returns the authenticated user previously attached by RequireSession.
func UserFromContext(ctx context.Context) (*a.User, bool) {
	u, ok := ctx.Value(ctxUser).(*a.User)
	return u, ok
}

func extractToken(r *http.Request, cookieName string) string {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
