// Package session generates and hashes opaque bearer tokens for use as
// session identifiers.
//
// Pattern: server generates a 32-byte random token and returns it to the
// client exactly once. The store keeps only the sha256 hash. Even with full
// DB read access, an attacker cannot reuse a session token — sha256 cannot
// be reversed in any practical sense.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// TokenBytes is the random-token length in bytes; 32 = 256 bits of entropy.
const TokenBytes = 32

// Generate returns a fresh URL-safe random token suitable for a session ID.
func Generate() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Hash returns a deterministic sha256 hex digest of a token. Store this in
// the database; never store the raw token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
