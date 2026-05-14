// Package password hashes and verifies passwords with argon2id.
//
// Encoded format (PHC-style):
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
//
// Parameters chosen for ~50-100ms hash time on a modern CPU. Tune via the
// exported defaults if your hardware budget differs.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default parameters. Memory in KB; iterations; parallelism; hash length; salt length.
const (
	DefaultMemoryKB    uint32 = 64 * 1024
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 2
	DefaultHashLength  uint32 = 32
	DefaultSaltLength  uint32 = 16
)

// Hash returns a PHC-encoded argon2id digest of plaintext.
func Hash(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("password: empty")
	}
	salt := make([]byte, DefaultSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(
		[]byte(plaintext),
		salt,
		DefaultIterations,
		DefaultMemoryKB,
		DefaultParallelism,
		DefaultHashLength,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		DefaultMemoryKB,
		DefaultIterations,
		DefaultParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// Verify constant-time compares plaintext against an encoded argon2id hash.
// Returns false on malformed input — callers should not distinguish "wrong
// password" from "malformed hash" to avoid information leakage.
func Verify(plaintext, encoded string) bool {
	parts := strings.Split(encoded, "$")
	// Layout: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iters uint32
	var parallel uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iters, &parallel); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plaintext), salt, iters, memory, parallel, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
