// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// A239: the hash Cassandra's HASHED PASSWORD takes is a $2a$ bcrypt hash at
// the requested cost that matches only its own password; an out-of-range cost,
// an empty password and one past bcrypt's 72 bytes are refused.
func TestHashBcryptMatchesOnlyItsPassword(t *testing.T) {
	hash, err := HashBcrypt([]byte("Lease0password0A"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(hash), "$2a$10$") || len(hash) != 60 {
		t.Fatalf("hash = %q", hash)
	}
	if bytes.Contains(hash, []byte("Lease0password0A")) {
		t.Fatal("the hash carries the password")
	}
	if !VerifyBcrypt(hash, []byte("Lease0password0A")) || VerifyBcrypt(hash, []byte("Lease0password0B")) {
		t.Fatal("the hash does not match exactly its own password")
	}
	again, err := HashBcrypt([]byte("Lease0password0A"), 10)
	if err != nil || bytes.Equal(again, hash) {
		t.Fatalf("a second hash reused the salt: %v", err)
	}
	for name, attempt := range map[string]func() error{
		"cost 3":   func() error { _, err := HashBcrypt([]byte("x"), 3); return err },
		"cost 32":  func() error { _, err := HashBcrypt([]byte("x"), 32); return err },
		"empty":    func() error { _, err := HashBcrypt(nil, 10); return err },
		"73 bytes": func() error { _, err := HashBcrypt(bytes.Repeat([]byte("a"), 73), 4); return err },
	} {
		if attempt() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
