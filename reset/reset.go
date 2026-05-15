// Package reset generates and hashes opaque tokens for one-shot password
// reset.
//
// Same shape as the session and verify packages: 32 random bytes go to the
// user (in the reset email); only sha256(token) is persisted. A full DB
// read can't replay a reset link.
package reset

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// TokenBytes is the random-token length in bytes; 32 = 256 bits of entropy.
const TokenBytes = 32

// Generate returns a fresh URL-safe random token for a reset link query
// parameter.
func Generate() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Hash returns a deterministic sha256 hex digest of token. Store this in
// the database; never store the raw token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
