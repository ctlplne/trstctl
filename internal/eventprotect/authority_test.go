// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type immediateKeyLocker struct{}

func (immediateKeyLocker) WithKeyLock(ctx context.Context, _ KeyRef, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(ctx)
}

func keyAuthorityFixture(t *testing.T) (*FileAuthority, FileAuthorityConfig, KeyRef) {
	t.Helper()
	base := t.TempDir()
	data := filepath.Join(base, "ordinary-data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := FileAuthorityConfig{Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{data}, Locker: immediateKeyLocker{}}
	authority, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	return authority, cfg, KeyRef{TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
}

func TestFileAuthorityRetainsKeyAcrossRestartWithoutExportingIt(t *testing.T) {
	authority, cfg, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	plain, aad, domain := []byte("A233 independently held key control"), []byte("source context"), []byte("a233/custody/control")
	var ciphertext []byte
	var escaped seal.KeyWrapper
	if err := authority.WithKey(t.Context(), ref, func(key seal.KeyWrapper) error {
		escaped = key
		var err error
		ciphertext, err = seal.SealDomain(key, plain, aad, domain)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if opened, err := seal.OpenDomain(escaped, ciphertext, aad, domain); err == nil || len(opened) != 0 {
		secret.Wipe(opened)
		t.Fatal("key escaped its callback lifetime")
	}
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.WithKey(t.Context(), ref, func(key seal.KeyWrapper) error {
		opened, err := seal.OpenDomain(key, ciphertext, aad, domain)
		defer secret.Wipe(opened)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatal("restart or repeated provisioning changed the key")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFileAuthorityMissingMaterialNeverRegenerates(t *testing.T) {
	authority, cfg, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	// Exact fixture identity only. Leave the public custody record intact to
	// model lost material after provisioning, not a request for a new key.
	if err := os.Remove(filepath.Join(cfg.Directory, ref.TenantID, ref.ID+".key")); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := authority.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrKey) || called {
		t.Fatalf("missing key material reached a callback or lacked a custody error: %v", err)
	}
	if err := authority.Provision(t.Context(), ref); !errors.Is(err, ErrKey) {
		t.Fatalf("missing key was regenerated after its custody record existed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, ref.TenantID, ref.ID+".key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing key was recreated")
	}
}

func TestFileAuthorityRejectsOrdinaryBackupOverlap(t *testing.T) {
	for _, relative := range []string{"ordinary-data", "ordinary-data/event-keys", "."} {
		t.Run(relative, func(t *testing.T) {
			base := t.TempDir()
			data := filepath.Join(base, "ordinary-data")
			if err := os.Mkdir(data, 0o700); err != nil {
				t.Fatal(err)
			}
			authority, err := NewFileAuthority(FileAuthorityConfig{Directory: filepath.Join(base, relative), BackupRoots: []string{data}, Locker: immediateKeyLocker{}})
			if authority != nil {
				_ = authority.Close()
			}
			if err == nil {
				t.Fatal("key custody overlaps the ordinary data backup tree")
			}
		})
	}
}

func TestFileAuthorityRejectsForeignAndMalformedReferences(t *testing.T) {
	authority, _, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []KeyRef{
		{TenantID: "2c14fe81-1956-4e9d-a174-e27a38e8e979", ID: ref.ID},
		{TenantID: ref.TenantID, ID: "../outside"},
		{TenantID: "../outside", ID: ref.ID},
	} {
		called := false
		if err := authority.WithKey(t.Context(), changed, func(seal.KeyWrapper) error { called = true; return nil }); err == nil || called {
			t.Fatal("foreign/malformed key reference reached the callback")
		}
	}
}
