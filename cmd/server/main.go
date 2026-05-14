// Command server is the demo HTTP API for the auth library.
//
//	POST /signup      {email, password}              -> 201 + Set-Cookie
//	POST /login       {email, password}              -> 200 + Set-Cookie
//	POST /logout                                     -> 204
//	GET  /me                                         -> 200 (requires session)
//	GET  /admin/users                                -> 200 (requires admin)
//	GET  /healthz
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	a "github.com/PS-safe/auth"
	"github.com/PS-safe/auth/memory"
	"github.com/PS-safe/auth/middleware"
	"github.com/PS-safe/auth/password"
	"github.com/PS-safe/auth/postgres"
	"github.com/PS-safe/auth/rbac"
	"github.com/PS-safe/auth/session"
	rl "github.com/PS-safe/ratelimit"
	rlmem "github.com/PS-safe/ratelimit/memory"
	rlmw "github.com/PS-safe/ratelimit/middleware"
)

const (
	sessionTTL = 7 * 24 * time.Hour

	// Credential endpoints (/signup, /login) share one per-IP limiter so an
	// attacker can't get double the budget by alternating between them.
	credentialRateLimit  = 5
	credentialRateWindow = time.Minute
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	store, closeStore, err := openStore(logger)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer closeStore()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	credLimiter, err := rlmem.New(rl.Config{Limit: credentialRateLimit, Window: credentialRateWindow})
	if err != nil {
		logger.Error("rate limiter", "err", err)
		os.Exit(1)
	}
	rateLimit := rlmw.Middleware(credLimiter)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.Handle("POST /signup", rateLimit(signupHandler(store, logger)))
	mux.Handle("POST /login", rateLimit(loginHandler(store, logger)))
	mux.HandleFunc("POST /logout", logoutHandler(store))

	auth := middleware.RequireSession(store)
	mux.Handle("GET /me", auth(http.HandlerFunc(meHandler)))
	mux.Handle("GET /admin/users", auth(middleware.RequirePermission(rbac.PermReadUsers)(adminUsersHandler())))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	logger.Info("listening", "addr", addr, "backend", backendName())

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server", "err", err)
		os.Exit(1)
	}
}

func openStore(logger *slog.Logger) (a.Store, func(), error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Warn("DATABASE_URL not set; using memory store (volatile)")
		return memory.New(), func() {}, nil
	}
	pool, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		return nil, nil, err
	}
	return postgres.New(pool), pool.Close, nil
}

func backendName() string {
	if os.Getenv("DATABASE_URL") == "" {
		return "memory"
	}
	return "postgres"
}

type credsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func signupHandler(store a.Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req credsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) || len(req.Password) < 8 {
			http.Error(w, "email or password invalid", http.StatusBadRequest)
			return
		}
		hash, err := password.Hash(req.Password)
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		user := a.User{
			ID:           randomID("usr_"),
			Email:        req.Email,
			PasswordHash: hash,
			Role:         string(rbac.RoleUser),
		}
		created, err := store.CreateUser(r.Context(), user)
		if err != nil {
			if errors.Is(err, a.ErrEmailTaken) {
				http.Error(w, "email already registered", http.StatusConflict)
				return
			}
			logger.Error("create user", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		if err := startSession(w, store, created.ID); err != nil {
			logger.Error("start session", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		writeUser(w, http.StatusCreated, created)
	}
}

func loginHandler(store a.Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req credsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		user, err := store.UserByEmail(r.Context(), strings.TrimSpace(strings.ToLower(req.Email)))
		if err != nil {
			// Same response for "no such user" vs "wrong password" to avoid
			// confirming whether an email is registered.
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if !password.Verify(req.Password, user.PasswordHash) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if err := startSession(w, store, user.ID); err != nil {
			logger.Error("start session", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		writeUser(w, http.StatusOK, user)
	}
}

func logoutHandler(store a.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(middleware.CookieName); err == nil && c.Value != "" {
			_ = store.DeleteSession(r.Context(), session.Hash(c.Value))
		}
		clearCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := middleware.UserFromContext(r.Context())
	writeUser(w, http.StatusOK, user)
}

func adminUsersHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[],"note":"admin-only endpoint reached"}`))
	})
}

func startSession(w http.ResponseWriter, store a.Store, userID string) error {
	tok, err := session.Generate()
	if err != nil {
		return err
	}
	exp := time.Now().UTC().Add(sessionTTL)
	if err := store.CreateSession(context.Background(), a.Session{
		TokenHash: session.Hash(tok),
		UserID:    userID,
		ExpiresAt: exp,
	}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.CookieName,
		Value:    tok,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeUser(w http.ResponseWriter, status int, u *a.User) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"role":       u.Role,
		"created_at": u.CreatedAt,
	})
}

func validEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	at := strings.IndexByte(s, '@')
	dot := strings.LastIndexByte(s, '.')
	return at > 0 && dot > at+1 && dot < len(s)-1
}

func randomID(prefix string) string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return prefix + hex.EncodeToString(buf)
}
