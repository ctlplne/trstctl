// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Owner decision 2026-11-02 (item 2g a, b), proven on windows-latest: a local
// action's command is a drive-letter path to a regular .exe. A script cmd.exe
// or a script host would run, and a UNC or device path to the same program,
// are refused before any action runs.
func TestWindowsLocalActionsAcceptOnlyALocalExe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := NewLocalOps(LocalOpsConfig{AllowedRoots: []string{dir}, Actions: []LocalAction{{LogicalName: "reload", Command: exe}}}); err != nil {
		t.Fatalf("this test's own .exe was refused: %v", err)
	}
	refused := map[string]string{}
	for _, ext := range []string{".bat", ".cmd", ".ps1", ".com"} {
		script := filepath.Join(dir, "reload"+ext)
		if err := os.WriteFile(script, []byte("exit 0\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused[ext] = script
	}
	volume := filepath.VolumeName(exe)
	refused["UNC"] = `\\localhost\` + strings.TrimSuffix(volume, ":") + `$` + exe[len(volume):]
	refused["device"] = `\\?\` + exe
	refused["relative"] = filepath.Base(exe)
	for name, command := range refused {
		if _, err := NewLocalOps(LocalOpsConfig{AllowedRoots: []string{dir}, Actions: []LocalAction{{LogicalName: "reload", Command: command}}}); err == nil {
			t.Errorf("%s command %q was accepted", name, command)
		}
	}
}
