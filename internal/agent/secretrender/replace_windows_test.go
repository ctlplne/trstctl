// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A238: on Windows a rendered file an application holds open (without delete
// sharing, as the C runtime opens files) can't be replaced until it closes it;
// the replace waits briefly instead of failing the render, and the new file is
// read-only like the one it replaced.
func TestReplaceWaitsForAReaderToCloseTheRenderedFileA238(t *testing.T) {
	dir := t.TempDir()
	path, tmp := filepath.Join(dir, "htpasswd"), filepath.Join(dir, ".htpasswd.next")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("new\n"), 0o440); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err == nil || !replaceBusy(err) {
		t.Fatalf("replacing a file held open = %v, want the busy error this path handles", err)
	}
	if err := os.Chmod(path, 0o440); err != nil { // #nosec G302 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	timer := time.AfterFunc(100*time.Millisecond, func() { _ = windows.CloseHandle(reader) })
	defer timer.Stop()
	if err := replaceFile(tmp, path, 0o440); err != nil {
		t.Fatalf("replace while a reader held the file for 100ms: %v", err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil || string(raw) != "new\n" {
		t.Fatalf("file %q, %v", raw, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("the replaced file is not read-only: %v %v", info, err)
	}
}
