// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package tlsprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Owner decision 2026-11-02 (item 2g a, b), proven on windows-latest: the
// native probe's OpenSSL is a drive-letter path to a regular .exe; a script
// and a UNC or device path to the same program are refused.
func TestWindowsNativeProbeAcceptsOnlyALocalExe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOpenSSLExecutable(exe); err != nil {
		t.Fatalf("a local .exe was refused: %v", err)
	}
	script := filepath.Join(t.TempDir(), "openssl.cmd")
	if err := os.WriteFile(script, []byte("exit 0\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(exe)
	for name, path := range map[string]string{
		"script": script,
		"UNC":    `\\localhost\` + strings.TrimSuffix(volume, ":") + `$` + exe[len(volume):],
		"device": `\\?\` + exe,
	} {
		if err := ValidateOpenSSLExecutable(path); err == nil {
			t.Errorf("%s path %q was accepted", name, path)
		}
	}
}
