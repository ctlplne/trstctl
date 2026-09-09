// SPDX-License-Identifier: MPL-2.0

package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// archiveArch reproduces the embedded-postgres library's per-arch naming for the
// cached binary archive, so we can locate the exact `.txz` it downloads and run
// (SUPPLY-003). We mirror that unexported strategy here instead of importing it,
// because this verifier must fail closed before the third-party binary starts.
func archiveArch() string {
	return postgresArchiveArch(runtime.GOOS, runtime.GOARCH, bundledPGVersion, unameMachine, isAlpine())
}

func postgresArchiveArch(goos, goarch, postgresVersion string, linuxMachineName func() string, alpine bool) string {
	arch := goarch
	if goos == "linux" {
		switch arch {
		case "arm64":
			arch = "arm64v8"
		case "arm":
			machine := linuxMachineName()
			switch {
			case strings.HasPrefix(machine, "armv7"):
				arch = "arm32v7"
			case strings.HasPrefix(machine, "armv6"):
				arch = "arm32v6"
			}
		}
		if alpine {
			arch += "-alpine"
		}
	}

	if goos == "darwin" && arch == "arm64" {
		if postgresAtLeast(postgresVersion, 14, 2) {
			arch = "arm64v8"
		} else {
			arch = "amd64"
		}
	}
	return arch
}

func postgresAtLeast(version string, wantMajor, wantMinor int) bool {
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
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
//     verify yet; callers must acquire and require true before startup);
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
	verified, err = embeddedpostgres.VerifyArchiveFile(path, wantHex)
	if err != nil {
		return false, fmt.Errorf("bundled postgres: verify cached archive %s: %w", filepath.Base(path), err)
	}
	return verified, nil
}
