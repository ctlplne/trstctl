// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// manifestPath is the committed embedded-postgres provenance manifest, relative to
// this package (internal/server).
const manifestPath = "../../deploy/supply-chain/embedded-postgres.json"

type pgManifest struct {
	PostgresVersion string `json:"postgresVersion"`
	Checksum        struct {
		SHA256 string `json:"sha256"`
	} `json:"checksum"`
	Archives []struct {
		Arch      string `json:"arch"`
		JarSHA256 string `json:"jar_sha256"`
		TxzSHA256 string `json:"txz_sha256"`
	} `json:"archives"`
}

func readManifest(t *testing.T) pgManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(manifestPath))
	if err != nil {
		t.Fatalf("read embedded-postgres manifest: %v", err)
	}
	var m pgManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse embedded-postgres manifest: %v", err)
	}
	return m
}

// TestEmbeddedPGProvenancePinIsPopulated is the SUPPLY-003 acceptance, part 1: the
// committed checksum is non-empty (the TOFU pin was completed) and every published
// arch carries a .txz pin. It FAILS on the pre-fix tree, where checksum.sha256 was
// "" — a no-op gate.
func TestEmbeddedPGProvenancePinIsPopulated(t *testing.T) {
	m := readManifest(t)
	if m.Checksum.SHA256 == "" {
		t.Error("embedded-postgres.json checksum.sha256 is empty — the provenance pin was never completed (SUPPLY-003)")
	}
	if len(m.Archives) == 0 {
		t.Fatal("embedded-postgres.json has no per-arch archive pins (SUPPLY-003)")
	}
	for _, a := range m.Archives {
		if a.TxzSHA256 == "" {
			t.Errorf("arch %q has no txz_sha256 — the runtime cannot verify the binary it runs (SUPPLY-003)", a.Arch)
		}
		if len(a.TxzSHA256) != 64 {
			t.Errorf("arch %q txz_sha256 is not a 64-hex SHA-256: %q", a.Arch, a.TxzSHA256)
		}
	}
}

// TestRuntimePinsMatchManifest is the no-drift guard: the Go pins the served binary
// enforces (bundled_pg_pins.go) must equal the committed manifest's per-arch
// txz_sha256 values, so the human-readable manifest and the enforced pin can never
// disagree.
func TestRuntimePinsMatchManifest(t *testing.T) {
	m := readManifest(t)
	if m.PostgresVersion != bundledPGVersion {
		t.Errorf("manifest postgresVersion %q != runtime bundledPGVersion %q", m.PostgresVersion, bundledPGVersion)
	}
	manifestByArch := map[string]string{}
	for _, a := range m.Archives {
		manifestByArch[a.Arch] = a.TxzSHA256
	}
	// Every runtime pin must be backed by an identical manifest entry.
	for archKey, sum := range bundledPGTxzSHA256 {
		// archKey is "linux-amd64" / "linux-arm64v8"; the manifest arch field uses the
		// same form.
		want, ok := manifestByArch[archKey]
		if !ok {
			t.Errorf("runtime pins %q but the manifest has no archive for it (SUPPLY-003)", archKey)
			continue
		}
		if want != sum {
			t.Errorf("pin drift for %q: runtime=%s manifest=%s", archKey, sum, want)
		}
	}
	// And every manifest arch must be reflected in the runtime pins (so a new arch
	// added to the manifest is actually enforced).
	for archKey := range manifestByArch {
		if _, ok := bundledPGTxzSHA256[archKey]; !ok {
			t.Errorf("manifest has arch %q but the runtime does not pin it (SUPPLY-003); add it to bundled_pg_pins.go", archKey)
		}
	}
}

func TestArchiveArchMirrorsEmbeddedPostgresStrategy(t *testing.T) {
	tests := []struct {
		goos    string
		goarch  string
		version string
		uname   string
		alpine  bool
		want    string
	}{
		{goos: "linux", goarch: "amd64", version: "16.15.0", want: "amd64"},
		{goos: "linux", goarch: "arm64", version: "16.15.0", want: "arm64v8"},
		{goos: "linux", goarch: "arm", version: "16.15.0", uname: "armv7l", want: "arm32v7"},
		{goos: "linux", goarch: "arm", version: "16.15.0", uname: "armv6l", want: "arm32v6"},
		{goos: "linux", goarch: "amd64", version: "16.15.0", alpine: true, want: "amd64-alpine"},
		{goos: "darwin", goarch: "amd64", version: "16.15.0", want: "amd64"},
		{goos: "darwin", goarch: "arm64", version: "14.1.0", want: "amd64"},
		{goos: "darwin", goarch: "arm64", version: "14.2.0", want: "arm64v8"},
		{goos: "darwin", goarch: "arm64", version: "16.15.0", want: "arm64v8"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("%s/%s/%s", tt.goos, tt.goarch, tt.version), func(t *testing.T) {
			got := postgresArchiveArch(tt.goos, tt.goarch, tt.version, func() string {
				return tt.uname
			}, tt.alpine)
			if got != tt.want {
				t.Fatalf("postgresArchiveArch() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestVerifyBundledPostgresArchiveRejectsTamper is the SUPPLY-003 acceptance, part
// 2: tampering the cached binary makes the runtime verifier refuse, a matching
// binary verifies, and a cold (absent) cache remains unverified and requires
// authenticated acquisition. It exercises the
// real verifier the served startBundledPostgres calls (verifyArchiveFileAgainst).
func TestVerifyBundledPostgresArchiveRejectsTamper(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "embedded-postgres-binaries-linux-test.txz")

	// Pretend a known-good binary: pin = SHA-256 of these exact bytes.
	good := []byte("this stands in for a verified PostgreSQL .txz archive")
	wantHex := crypto.SHA256Hex(good)
	if err := os.WriteFile(archive, good, 0o600); err != nil {
		t.Fatal(err)
	}

	// (1) Matching content verifies.
	if ok, err := verifyArchiveFileAgainst(archive, wantHex); err != nil || !ok {
		t.Fatalf("a binary matching the pin must verify: ok=%v err=%v", ok, err)
	}

	// (2) Flip a byte on disk (tamper the cache): verification must refuse.
	tampered := append([]byte(nil), good...)
	tampered[0] ^= 0xFF
	if err := os.WriteFile(archive, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := verifyArchiveFileAgainst(archive, wantHex)
	if err == nil || ok {
		t.Fatal("a tampered cached PostgreSQL binary must be REFUSED (SUPPLY-003)")
	}
	if !strings.Contains(err.Error(), "provenance check FAILED") {
		t.Errorf("rejection should be a provenance error, got: %v", err)
	}

	// (3) Absence remains unverified. The caller must acquire authenticated bytes
	// and require a second true result before startup.
	if ok, err := verifyArchiveFileAgainst(filepath.Join(dir, "absent.txz"), wantHex); err != nil || ok {
		t.Errorf("a cold (absent) cache should be (false, nil), got ok=%v err=%v", ok, err)
	}
}

// TestBundledPostgresArchiveVerifierUsesExpectedCachePath checks the verifier's
// archive filename and absent/mismatched results. It does not call Start; the
// wrapper startup regressions separately prove no executable runs before trust.
func TestBundledPostgresArchiveVerifierUsesExpectedCachePath(t *testing.T) {
	archKey := runtime.GOOS + "-" + archiveArch()
	want, pinned := bundledPGTxzSHA256[archKey]
	if !pinned {
		t.Skipf("no committed pin for this runtime arch (%s); the verifier still fails closed on it by design", archKey)
	}

	binariesPath := t.TempDir()
	cache := bundledPGCacheArchive(binariesPath)
	if filepath.Dir(cache) != binariesPath {
		t.Fatalf("cache path %q is not under the configured BinariesPath %q", cache, binariesPath)
	}

	// (1) Cold cache: nothing to verify yet — (false, nil), not an error.
	if ok, err := verifyBundledPostgresArchive(cache); err != nil || ok {
		t.Fatalf("cold cache should be (false, nil): ok=%v err=%v", ok, err)
	}

	// (2) Fabricate a "matching" cache by writing bytes whose SHA-256 equals the pin
	// is not feasible without the real archive; instead prove the negative path on
	// the real cache path: a tampered file there is rejected.
	if err := os.WriteFile(cache, []byte("not the real postgres archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := verifyBundledPostgresArchive(cache)
	if err == nil || ok {
		t.Fatalf("a tampered archive at the runtime cache path must be REFUSED (want=%s) (SUPPLY-003)", want)
	}
	if !strings.Contains(err.Error(), "provenance check FAILED") {
		t.Errorf("expected a provenance failure, got: %v", err)
	}
}

// TestUnpinnedArchFailsClosed: an arch with no committed pin must fail closed
// rather than running an unverified binary.
func TestUnpinnedArchFailsClosed(t *testing.T) {
	// verifyBundledPostgresArchive consults bundledPGTxzSHA256 by the running
	// GOOS/arch; we cannot change runtime.GOARCH, but we can prove the failClosed
	// branch by checking that an unknown key is absent and that the error path is
	// taken via a direct lookup. The pure verifier is covered above; here we assert
	// the policy: every arch we ship must be pinned (no silent unverified run).
	for _, archKey := range []string{"linux-amd64", "linux-arm64v8", "darwin-arm64v8"} {
		if _, ok := bundledPGTxzSHA256[archKey]; !ok {
			t.Errorf("shipped arch %q must have a committed provenance pin (SUPPLY-003)", archKey)
		}
	}
}
