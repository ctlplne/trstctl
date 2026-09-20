// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// The key is generated through internal/crypto rather than crypto/ed25519
// directly: AN-3 admits no exception for tests, and a test that reaches around
// the boundary is exactly how a second crypto path gets established.
func writeAuthorityPEM(t *testing.T, dir string) []byte {
	t.Helper()
	_, pubPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BreakGlassAuthorityFile), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := crypto.ParseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestLoadBreakGlassAuthority covers the three states an operator can leave
// the custody dir in: unconfigured (downgrades stay refused), configured with
// a real key, and half-configured (must fail loudly rather than look
// configured while behaving as if it were not).
func TestLoadBreakGlassAuthority(t *testing.T) {
	if der, err := LoadBreakGlassAuthority(""); der != nil || err != nil {
		t.Fatalf("no custody dir: der=%v err=%v, want nil/nil", der, err)
	}

	dir := t.TempDir()
	if der, err := LoadBreakGlassAuthority(dir); der != nil || err != nil {
		t.Fatalf("absent file: der=%v err=%v, want nil/nil (unconfigured is the ordinary case)", der, err)
	}

	want := writeAuthorityPEM(t, dir)
	got, err := LoadBreakGlassAuthority(dir)
	if err != nil {
		t.Fatalf("configured authority: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("loaded authority key does not match the provisioned key")
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, BreakGlassAuthorityFile), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBreakGlassAuthority(bad); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Fatalf("half-configured authority err=%v, want a loud break-glass parse failure", err)
	}
}

// TestProductionMinterBuildsWithAndWithoutBreakGlass proves the wiring is
// opt-in: the minter constructs either way, so an unconfigured deployment
// keeps its fail-closed downgrade refusal instead of failing to start.
func TestProductionMinterBuildsWithAndWithoutBreakGlass(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewProductionMinter(Config{SignerID: "s", FloorDir: dir}); err != nil {
		t.Fatalf("unconfigured break-glass must still build a minter: %v", err)
	}
	der := writeAuthorityPEM(t, dir)
	if _, err := NewProductionMinter(Config{SignerID: "s", FloorDir: dir, BreakGlassAuthorityPubDER: der}); err != nil {
		t.Fatalf("configured break-glass must build a minter: %v", err)
	}
}
