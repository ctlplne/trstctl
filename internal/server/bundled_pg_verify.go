package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// archiveArch reproduces the embedded-postgres library's per-arch naming for the
// cached binary archive, so we can locate the exact `.txz` it downloads and run
// (SUPPLY-003). On linux the library renames arm64->arm64v8 (and arm->arm32vN),
// and appends `-alpine` on Alpine; on every other GOOS it uses GOARCH verbatim.
// We mirror that here (instead of importing the library's unexported strategy) so
// the cache path we verify is byte-identical to the one it uses.
func archiveArch() string {
	arch := runtime.GOARCH
	if runtime.GOOS == "linux" {
		switch {
		case arch == "arm64":
			arch = "arm64v8"
		case arch == "arm":
			machine := unameMachine()
			switch {
			case strings.HasPrefix(machine, "armv7"):
				arch = "arm32v7"
			case strings.HasPrefix(machine, "armv6"):
				arch = "arm32v6"
			}
		}
		if isAlpine() {
			arch += "-alpine"
		}
	}
	return arch
}

func unameMachine() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func isAlpine() bool {
	_, err := os.Stat("/etc/alpine-release")
	return err == nil
}

// bundledPGCacheArchive returns the path the embedded-postgres library caches the
// PostgreSQL `.txz` at under binariesPath, for the running OS/arch and the pinned
// version.
func bundledPGCacheArchive(binariesPath string) string {
	name := fmt.Sprintf("embedded-postgres-binaries-%s-%s-%s.txz", runtime.GOOS, archiveArch(), bundledPGVersion)
	return filepath.Join(binariesPath, name)
}

// verifyBundledPostgresArchive verifies the cached PostgreSQL `.txz` at path
// against the committed provenance pin (SUPPLY-003). It returns:
//   - (true, nil)  when the cache exists and its SHA-256 matches the pin;
//   - (false, nil) when the cache is not present yet (cold cache — nothing to
//     verify pre-download; the post-download check gates that case);
//   - (false, err) when the cache exists but does NOT match the pin (tampered or
//     wrong binary), or when this arch has no committed pin (so an unpinned arch
//     fails closed rather than running an unverified binary).
//
// Hashing routes through the crypto boundary (AN-3); the signer is not involved.
func verifyBundledPostgresArchive(path string) (verified bool, err error) {
	key := runtime.GOOS + "-" + archiveArch()
	want, pinned := bundledPGTxzSHA256[key]
	if !pinned {
		return false, fmt.Errorf("bundled postgres: no committed provenance pin for %s/%s (SUPPLY-003); "+
			"refusing to run an unverified PostgreSQL binary — pin its .txz SHA-256 in internal/server/bundled_pg_pins.go and deploy/supply-chain/embedded-postgres.json, "+
			"or use TRSTCTL_POSTGRES_MODE=external", runtime.GOOS, archiveArch())
	}
	return verifyArchiveFileAgainst(path, want)
}

// verifyArchiveFileAgainst is the pure provenance check: it hashes the file at
// path (via the crypto boundary, AN-3) and compares it to wantHex. A missing file
// is (false, nil) — a cold cache, nothing to verify yet; a present-but-mismatched
// file is a fail-closed error. Split out so it is unit-testable with controlled
// bytes without touching the global pin map.
func verifyArchiveFileAgainst(path, wantHex string) (verified bool, err error) {
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return false, nil // cold cache: not an error, just nothing to verify yet
		}
		return false, fmt.Errorf("bundled postgres: read cached binary archive: %w", rerr)
	}
	got := crypto.SHA256Hex(data)
	if got != wantHex {
		return false, fmt.Errorf("bundled postgres: provenance check FAILED for %s — the cached PostgreSQL binary does not match the committed pin "+
			"(want %s, got %s); the binary may be tampered or corrupt. Refusing to start it (SUPPLY-003). "+
			"Delete the cache to re-fetch, or use TRSTCTL_POSTGRES_MODE=external", filepath.Base(path), wantHex, got)
	}
	return true, nil
}
