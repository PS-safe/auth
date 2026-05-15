# auth

A small, drop-into-anything email-and-password auth library for Go.

```go
import (
    a "github.com/PS-safe/auth"
    "github.com/PS-safe/auth/memory"
    "github.com/PS-safe/auth/password"
    "github.com/PS-safe/auth/session"
    "github.com/PS-safe/auth/middleware"
    "github.com/PS-safe/auth/rbac"
)

store := memory.New()

// Signup
hash, _ := password.Hash("hunter2")
user, _ := store.CreateUser(ctx, a.User{
    ID: "usr_…", Email: "a@b.com", PasswordHash: hash, Role: "user",
})

// Login
got, _ := store.UserByEmail(ctx, "a@b.com")
if password.Verify("hunter2", got.PasswordHash) { /* ok */ }

// Session
tok, _ := session.Generate()
_ = store.CreateSession(ctx, a.Session{
    TokenHash: session.Hash(tok),
    UserID: got.ID,
    ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
})
// Return `tok` to the client (cookie or Bearer); only `session.Hash(tok)` lives in the DB.

// Protect routes
mux := http.NewServeMux()
mux.Handle("GET /me", middleware.RequireSession(store)(http.HandlerFunc(meHandler)))
mux.Handle("GET /admin", middleware.RequireSession(store)(
    middleware.RequirePermission(rbac.PermReadAdmin)(http.HandlerFunc(adminHandler)),
))
```

## What it gets right

- **argon2id, not bcrypt.** Modern, memory-hard, recommended default for new systems.
- **Opaque session tokens.** Server stores only `sha256(token)`. A full DB dump can't be used to impersonate users.
- **Constant-time password compare.** `crypto/subtle` under the hood.
- **JOIN in `SessionByTokenHash`.** One Postgres round trip resolves session + user — middleware doesn't do N+1.
- **Generic 401s.** `/login` returns the same error for "no such user" vs "wrong password" to avoid enumeration.
- **RBAC built in.** Static role-permission map; tiny, obvious, and easy to extend when needed.
- **Cookies are `HttpOnly`, `Secure`, `SameSite=Lax`** by default in `cmd/server`.
- **Credential endpoints are rate-limited.** `/signup` and `/login` share one per-IP sliding-window limiter (5/min) via [`github.com/PS-safe/ratelimit`](https://github.com/PS-safe/ratelimit) — basic defense against credential stuffing and signup abuse.
- **Email verification, atomically.** Signup issues an opaque verification token (sha256 in the DB, raw in the email) via [`github.com/PS-safe/mailer`](https://github.com/PS-safe/mailer). `ConsumeEmailVerification` validates + marks consumed + sets `users.verified_at` in one transaction — two clicks on the same link can't both succeed.
- **Password reset that revokes existing sessions.** `ConsumePasswordReset` validates the token, sets the new password hash, and `DELETE`s every session for that user — all in one transaction. If the old password was compromised, no attacker session survives the reset.
- **Anti-enumeration on `/reset/request`.** Always returns 204, whether the email is registered or not, so the endpoint can't be used to probe which addresses have accounts.

## Status

**v0** — Store interface, memory + Postgres backends, password + session packages, RBAC, middleware, runnable HTTP server. Contract tests cover memory.

## API

```go
type Store interface {
    CreateUser(ctx, User) (*User, error)
    UserByEmail(ctx, email) (*User, error)
    UserByID(ctx, id) (*User, error)

    CreateSession(ctx, Session) error
    SessionByTokenHash(ctx, hash) (*Session, *User, error)
    DeleteSession(ctx, hash) error
    DeleteUserSessions(ctx, userID) error

    CreateEmailVerification(ctx, EmailVerification) error
    ConsumeEmailVerification(ctx, tokenHash) (*EmailVerification, error)

    CreatePasswordReset(ctx, PasswordReset) error
    ConsumePasswordReset(ctx, tokenHash, newPasswordHash) (*PasswordReset, error)
}
```

## HTTP API (cmd/server)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/signup` | `{email, password}` → 201 + `Set-Cookie` + sends verification email |
| `POST` | `/login`  | `{email, password}` → 200 + `Set-Cookie` |
| `POST` | `/logout` | revoke current session |
| `GET`  | `/me`     | current user (requires session) |
| `GET`  | `/verify?token=...` | consume verification link from email |
| `POST` | `/verify/resend`    | re-send verification email (requires session) |
| `POST` | `/reset/request`    | `{email}` → 204 always (anti-enumeration); emails a reset link if email is registered |
| `POST` | `/reset/confirm`    | `{token, new_password}` → 200 user, all prior sessions revoked |
| `GET`  | `/admin/users` | admin-only (requires `users:read`) |

The `cmd/server` demo lets users log in without verifying — `User.VerifiedAt`
is exposed so callers can apply their own policy (block features, force a
nag bar, etc.) per app.

## Configuration (env)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | no | (in-memory) | Postgres DSN; if unset, uses volatile in-memory store |
| `PORT` | no | `8080` | HTTP listen port |
| `BASE_URL` | no | `http://localhost:8080` | used to build the verification link |
| `MAILER_BACKEND` | no | `memory` | `memory` (captures, no real send), `smtp`, or `brevo` |
| `MAIL_FROM` / `MAIL_FROM_NAME` | for real sends | — | sender address |
| `BREVO_API_KEY` | brevo | — | Brevo API key |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` | smtp | — | SMTP server |

## Local dev

```bash
go test ./...
go run ./cmd/server
```

## Roadmap

- [ ] Refresh tokens (long-lived opaque) on top of short-lived access tokens
- [ ] OAuth providers (Google, GitHub) behind a uniform interface
- [ ] WebAuthn / passkeys
- [ ] testcontainers-go integration tests against real Postgres

## License

MIT
