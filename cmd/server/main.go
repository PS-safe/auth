// Command server is the demo HTTP API for the auth library.
//
//	POST /signup           {email, password}            -> 201 + Set-Cookie + verification email
//	POST /login            {email, password}            -> 200 + Set-Cookie
//	POST /logout                                        -> 204
//	GET  /me                                            -> 200 (requires session)
//	GET  /verify?token=... (link clicked from email)    -> 200 plain text
//	POST /verify/resend                                 -> 204 (requires session)
//	POST /reset/request    {email}                      -> 204 always (anti-enumeration)
//	POST /reset/confirm    {token, new_password}        -> 200 user (sessions revoked)
//	GET  /admin/users                                   -> 200 (requires admin)
//	GET  /healthz
//
// Compose example: this server wires github.com/PS-safe/auth together with
// github.com/PS-safe/ratelimit (per-IP credential limit) and
// github.com/PS-safe/mailer (verification email delivery).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
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
	"github.com/PS-safe/auth/reset"
	"github.com/PS-safe/auth/verify"
	"github.com/PS-safe/mailer"
	mbrevo "github.com/PS-safe/mailer/brevo"
	mmem "github.com/PS-safe/mailer/memory"
	msmtp "github.com/PS-safe/mailer/smtp"
	rl "github.com/PS-safe/ratelimit"
	rlmem "github.com/PS-safe/ratelimit/memory"
	rlmw "github.com/PS-safe/ratelimit/middleware"
)

const (
	sessionTTL = 7 * 24 * time.Hour
	verifyTTL  = 24 * time.Hour
	resetTTL   = 1 * time.Hour

	// Credential-adjacent endpoints (/signup, /login, /reset/request) share
	// one per-IP limiter so an attacker can't get extra budget by switching
	// between them. /reset/confirm is intentionally NOT in this bucket — a
	// shared bucket would let token brute-forcing self-DoS legitimate
	// logins, and brute-forcing a 256-bit token is computationally
	// infeasible anyway.
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

	sender, err := openMailer(logger)
	if err != nil {
		logger.Error("open mailer", "err", err)
		os.Exit(1)
	}
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.Handle("POST /signup", rateLimit(signupHandler(store, sender, baseURL, logger)))
	mux.Handle("POST /login", rateLimit(loginHandler(store, logger)))
	mux.HandleFunc("POST /logout", logoutHandler(store))
	mux.HandleFunc("GET /verify", verifyHandler(store, logger))
	mux.Handle("POST /reset/request", rateLimit(resetRequestHandler(store, sender, baseURL, logger)))
	mux.HandleFunc("POST /reset/confirm", resetConfirmHandler(store, logger))

	auth := middleware.RequireSession(store)
	mux.Handle("GET /me", auth(http.HandlerFunc(meHandler)))
	mux.Handle("POST /verify/resend", auth(verifyResendHandler(store, sender, baseURL, logger)))
	mux.Handle("GET /admin/users", auth(middleware.RequirePermission(rbac.PermReadUsers)(adminUsersHandler())))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	logger.Info("listening", "addr", addr, "store", backendName(), "mailer", mailerBackendName())

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

// openMailer picks a mailer backend from MAILER_BACKEND. memory captures
// messages in-process (the default; emails don't actually go anywhere).
// Switch to smtp or brevo and set the matching env vars to send for real.
func openMailer(logger *slog.Logger) (mailer.Sender, error) {
	backend := os.Getenv("MAILER_BACKEND")
	switch backend {
	case "", "memory":
		logger.Warn("MAILER_BACKEND not set; using memory mailer (emails are captured, not sent)")
		return mmem.New(), nil
	case "brevo":
		key := os.Getenv("BREVO_API_KEY")
		if key == "" {
			return nil, errors.New("brevo mailer needs BREVO_API_KEY")
		}
		return mbrevo.New(key), nil
	case "smtp":
		host := os.Getenv("SMTP_HOST")
		if host == "" {
			return nil, errors.New("smtp mailer needs SMTP_HOST")
		}
		port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
		if err != nil {
			return nil, errors.New("SMTP_PORT must be a number")
		}
		return msmtp.New(host, port, os.Getenv("SMTP_USERNAME"), os.Getenv("SMTP_PASSWORD")), nil
	default:
		return nil, errors.New("unknown MAILER_BACKEND " + backend + " (want memory, smtp, or brevo)")
	}
}

func mailerBackendName() string {
	if b := os.Getenv("MAILER_BACKEND"); b != "" {
		return b
	}
	return "memory"
}

type credsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func signupHandler(store a.Store, sender mailer.Sender, baseURL string, logger *slog.Logger) http.HandlerFunc {
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
		// Verification email is best-effort: a transient mailer failure
		// shouldn't block account creation. Caller can retry via resend.
		if err := issueVerification(r.Context(), store, sender, baseURL, created); err != nil {
			logger.Error("issue verification email", "user_id", created.ID, "err", err)
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

func verifyHandler(store a.Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		v, err := store.ConsumeEmailVerification(r.Context(), verify.Hash(token))
		switch {
		case errors.Is(err, a.ErrNotFound):
			http.Error(w, "verification link not found", http.StatusNotFound)
			return
		case errors.Is(err, a.ErrExpired):
			http.Error(w, "verification link expired — request a new one", http.StatusGone)
			return
		case errors.Is(err, a.ErrAlreadyConsumed):
			http.Error(w, "this link has already been used", http.StatusGone)
			return
		case err != nil:
			logger.Error("consume verification", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "Email verified for %s.\n", v.Email)
	}
}

func verifyResendHandler(store a.Store, sender mailer.Sender, baseURL string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := middleware.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user.VerifiedAt != nil {
			http.Error(w, "email is already verified", http.StatusBadRequest)
			return
		}
		if err := issueVerification(r.Context(), store, sender, baseURL, user); err != nil {
			logger.Error("issue verification email", "user_id", user.ID, "err", err)
			http.Error(w, "could not send verification email", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

type emailRequest struct {
	Email string `json:"email"`
}

type resetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// resetRequestHandler issues a password-reset token and emails it. It ALWAYS
// returns 204 — replying differently for "email registered" vs "email
// unknown" would leak which addresses have accounts. The work below the
// user-not-found branch is intentionally skipped; production code that
// cares about timing-based enumeration would add a constant-time fallback.
func resetRequestHandler(store a.Store, sender mailer.Sender, baseURL string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req emailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Still return 204 — no need to leak that the request body was
			// even readable.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if email == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		user, err := store.UserByEmail(r.Context(), email)
		if err != nil {
			// Unknown email — don't tell the client.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := issueReset(r.Context(), store, sender, baseURL, user); err != nil {
			logger.Error("issue password reset", "user_id", user.ID, "err", err)
			// Still 204 — failure leaks no more than "email exists" would.
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func resetConfirmHandler(store a.Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req resetConfirmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Token == "" || len(req.NewPassword) < 8 {
			http.Error(w, "token or new_password invalid", http.StatusBadRequest)
			return
		}
		newHash, err := password.Hash(req.NewPassword)
		if err != nil {
			logger.Error("hash new password", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		rec, err := store.ConsumePasswordReset(r.Context(), reset.Hash(req.Token), newHash)
		switch {
		case errors.Is(err, a.ErrNotFound):
			http.Error(w, "reset link not found", http.StatusNotFound)
			return
		case errors.Is(err, a.ErrExpired):
			http.Error(w, "reset link expired — request a new one", http.StatusGone)
			return
		case errors.Is(err, a.ErrAlreadyConsumed):
			http.Error(w, "this link has already been used", http.StatusGone)
			return
		case err != nil:
			logger.Error("consume password reset", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		user, err := store.UserByID(r.Context(), rec.UserID)
		if err != nil {
			logger.Error("lookup user after reset", "user_id", rec.UserID, "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		writeUser(w, http.StatusOK, user)
	}
}

func issueReset(ctx context.Context, store a.Store, sender mailer.Sender, baseURL string, user *a.User) error {
	tok, err := reset.Generate()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	err = store.CreatePasswordReset(ctx, a.PasswordReset{
		TokenHash: reset.Hash(tok),
		UserID:    user.ID,
		ExpiresAt: now.Add(resetTTL),
		CreatedAt: now,
	})
	if err != nil {
		return err
	}
	// The link points at where the user's frontend hosts the reset form. The
	// API endpoint itself is POST /reset/confirm; this URL is what goes in
	// the email body, not necessarily a URL this server serves.
	link := baseURL + "/reset?token=" + url.QueryEscape(tok)
	from := mailer.Address{Name: os.Getenv("MAIL_FROM_NAME"), Email: os.Getenv("MAIL_FROM")}
	if from.Email == "" {
		from.Email = "no-reply@auth.local"
	}
	msg := mailer.Message{
		From:    from,
		To:      []mailer.Address{{Email: user.Email}},
		Subject: "Reset your password",
		Text: "Use the link below to choose a new password. It expires in 1 hour. " +
			"If you didn't ask for this, you can ignore this email.\n\n" + link + "\n",
		HTML: `<p>Use the link below to choose a new password. It expires in 1 hour.</p>` +
			`<p>If you didn't ask for this, you can ignore this email.</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>`,
	}
	return sender.Send(ctx, msg)
}

// issueVerification persists a fresh verification token for user and emails
// them the link. Returns the first error from either step; the caller logs
// (the library doesn't).
func issueVerification(ctx context.Context, store a.Store, sender mailer.Sender, baseURL string, user *a.User) error {
	tok, err := verify.Generate()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	err = store.CreateEmailVerification(ctx, a.EmailVerification{
		TokenHash: verify.Hash(tok),
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: now.Add(verifyTTL),
		CreatedAt: now,
	})
	if err != nil {
		return err
	}
	link := baseURL + "/verify?token=" + url.QueryEscape(tok)
	from := mailer.Address{Name: os.Getenv("MAIL_FROM_NAME"), Email: os.Getenv("MAIL_FROM")}
	if from.Email == "" {
		// Memory backend doesn't actually send; give it a placeholder so
		// Validate passes and the message is still captured for inspection.
		from.Email = "no-reply@auth.local"
	}
	msg := mailer.Message{
		From:    from,
		To:      []mailer.Address{{Email: user.Email}},
		Subject: "Verify your email",
		Text: "Click the link below to verify your email address. " +
			"It expires in 24 hours.\n\n" + link + "\n",
		HTML: `<p>Click the link below to verify your email address. It expires in 24 hours.</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>`,
	}
	return sender.Send(ctx, msg)
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
		"id":          u.ID,
		"email":       u.Email,
		"role":        u.Role,
		"verified_at": u.VerifiedAt,
		"created_at":  u.CreatedAt,
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
