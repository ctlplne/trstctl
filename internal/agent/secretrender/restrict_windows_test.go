// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileDACL reads a file's DACL: whether it is protected from inheritance and
// the SIDs it grants (as strings, sorted).
func fileDACL(t *testing.T, path string) (bool, []string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL: %v", err)
	}
	var sids []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- the ACE's trailing SID, as the Windows API lays it out (CWE-242)
		sids = append(sids, sid.String())
	}
	sort.Strings(sids)
	return control&windows.SE_DACL_PROTECTED != 0, sids
}

// A238-L10: a rendered file used to inherit its directory's DACL, so whoever
// the directory let read could read the secret whatever the mode said. It now
// carries a protected DACL from its mode: the agent's user and SYSTEM always,
// Authenticated Users only when the other bits allow reading.
func TestWindowsRenderedFileHasAnExplicitProtectedDACLA238L10(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	authenticated, _ := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	dir := t.TempDir()

	private := filepath.Join(dir, "private.txt")
	if err := writeAtomic(private, []byte("value"), 0o400, nil); err != nil {
		t.Fatal(err)
	}
	protected, sids := fileDACL(t, private)
	want := []string{system.String(), user.User.Sid.String()}
	sort.Strings(want)
	if !protected || len(sids) != len(want) || sids[0] != want[0] || sids[1] != want[1] {
		t.Fatalf("0400 file DACL = protected %v, SIDs %v; want protected with only %v (it inherits the directory's readers otherwise)", protected, sids, want)
	}
	if data, err := os.ReadFile(private); err != nil || string(data) != "value" { // #nosec G304 -- the test's own file (CWE-22)
		t.Fatalf("the agent cannot read its own rendered file: %v", err)
	}

	shared := filepath.Join(dir, "shared.txt")
	if err := writeAtomic(shared, []byte("value"), 0o444, nil); err != nil {
		t.Fatal(err)
	}
	protected, sids = fileDACL(t, shared)
	found := false
	for _, sid := range sids {
		found = found || sid == authenticated.String()
	}
	if !protected || !found {
		t.Fatalf("0444 file DACL = protected %v, SIDs %v; want protected and readable by Authenticated Users", protected, sids)
	}
	// A rewrite keeps the explicit DACL (the new file is restricted before the
	// replace, not after).
	if err := writeAtomic(private, []byte("value 2"), 0o400, nil); err != nil {
		t.Fatal(err)
	}
	if protected, sids = fileDACL(t, private); !protected || len(sids) != 2 {
		t.Fatalf("rewritten 0400 file DACL = protected %v, SIDs %v", protected, sids)
	}
}
