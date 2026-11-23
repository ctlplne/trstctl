// SPDX-License-Identifier: BUSL-1.1
package journalkey_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/journalkey"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// CR-045: recovery opens only an explicitly provisioned, versioned local key.
// The same version survives restart, while a missing or retired version cannot
// validate a producer commitment from a different key.
func TestIngressJournalKeyIsExplicitVersionedCustodyCR045(t *testing.T) {
	first := filepath.Join(t.TempDir(), "journal-v1.key")
	second := filepath.Join(t.TempDir(), "journal-v2.key")
	for _, path := range []string{first, second} {
		if err := journalkey.Provision(path); err != nil {
			t.Fatal(err)
		}
		private, err := secretfile.IsPrivate(path)
		if err != nil || !private {
			t.Fatalf("journal key custody private=%v err=%v", private, err)
		}
		// POSIX mode bits are an additional check where they describe file
		// authority. Windows custody is enforced by the protected NTFS DACL.
		if runtime.GOOS != "windows" {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("journal key file mode=%v err=%v", info, err)
			}
		}
		if err := journalkey.Provision(path); err == nil {
			t.Fatal("provision replaced an existing journal key")
		}
	}
	keys := journalkey.Files{ActiveID: "plain-v2", Paths: map[string]string{
		"plain-v1": first, "plain-v2": second,
	}}
	message := []byte("plain-normalized-producer-view")
	var activeMAC, olderMAC []byte
	if err := keys.WithActiveKey(func(id string, key []byte) error {
		if id != "plain-v2" || len(key) != 32 {
			t.Fatalf("active key id=%q length=%d", id, len(key))
		}
		activeMAC = crypto.HMACSHA256(key, message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := keys.WithKey("plain-v1", func(key []byte) error {
		olderMAC = crypto.HMACSHA256(key, message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(activeMAC, olderMAC) {
		t.Fatal("distinct journal key versions produced the same MAC")
	}
	if err := keys.WithKey("plain-v2", func(key []byte) error {
		if !crypto.ConstantTimeEqual(activeMAC, crypto.HMACSHA256(key, message)) {
			t.Fatal("restart did not recover the same active key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	delete(keys.Paths, "plain-v1")
	if err := keys.WithKey("plain-v1", func([]byte) error {
		t.Fatal("retired journal key was borrowed")
		return nil
	}); err == nil {
		t.Fatal("retired journal key did not fail closed")
	}
}

func TestIngressJournalRecoveryNeverCreatesMissingKeyCR045(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.key")
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": path}}
	if err := keys.WithActiveKey(func(string, []byte) error {
		t.Fatal("recovery borrowed an absent key")
		return nil
	}); err == nil {
		t.Fatal("recovery created or accepted an absent key")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing recovery key path changed: %v", err)
	}
	short := filepath.Join(t.TempDir(), "short.key")
	if err := secretfile.Create(short, bytes.Repeat([]byte{0x31}, 31)); err != nil {
		t.Fatal(err)
	}
	keys.Paths["plain-v1"] = short
	if err := keys.WithActiveKey(func(string, []byte) error {
		t.Fatal("short recovery key was borrowed")
		return nil
	}); err == nil {
		t.Fatal("short recovery key was accepted")
	}
}
