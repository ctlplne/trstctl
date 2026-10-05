// SPDX-License-Identifier: BUSL-1.1

package samltest

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPersistentIdentitySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "idp.pem")
	firstKey, firstCert, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider")
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == nil || firstCert == nil {
		t.Fatal("missing signing material")
	}
	secondKey, secondCert, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider")
	if err != nil {
		t.Fatal(err)
	}
	if secondKey == nil || !firstCert.Equal(secondCert) {
		t.Fatal("IdP identity rotated across a restart")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestPersistentIdentityFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "idp.pem")
	if err := os.WriteFile(path, []byte("malformed identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider"); err == nil {
		t.Fatal("malformed identity was silently replaced")
	}
	malformed, err := os.ReadFile(path) // #nosec G304 -- test-owned temporary identity file
	if err != nil || string(malformed) != "malformed identity" {
		t.Fatal("malformed identity changed")
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberately unsafe test fixture must be refused
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider"); err == nil {
		t.Fatal("over-permissive identity was accepted")
	}
	if _, _, err := LoadOrCreateIdentityProviderMaterial(filepath.Join(root, "missing.pem"), ""); err == nil {
		t.Fatal("empty identity name was accepted")
	}
}

func TestPersistentIdentityCannotBeReusedForAnotherActor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idp.pem")
	if _, _, err := LoadOrCreateIdentityProviderMaterial(path, "lab-tenant"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider"); err == nil {
		t.Fatal("another IdP actor reused this signing key")
	}
}

func TestPersistentIdentityConcurrentFirstStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "idp.pem")
	type result struct {
		serial string
		err    error
	}
	results := make([]result, 3)
	var wait sync.WaitGroup
	for i := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, cert, err := LoadOrCreateIdentityProviderMaterial(path, "lab-provider")
			results[index].err = err
			if err == nil {
				results[index].serial = cert.SerialNumber.String()
			}
		}(i)
	}
	wait.Wait()
	for i, got := range results {
		if got.err != nil || got.serial != results[0].serial {
			t.Fatalf("first start %d = %+v; first result = %+v", i, got, results[0])
		}
	}
}
