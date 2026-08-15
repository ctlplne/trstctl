// SPDX-License-Identifier: MPL-2.0

package sshtrust

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// TestUnreadableFileIsNotTreatedAsAbsent is the regression guard for the rollback
// that deleted the host's SSH configuration.
//
// read() had two branches that did the same thing: os.ErrNotExist and every other
// error both returned (nil, false). `existed` is what restore() switches on, and
// its false branch calls FS.Remove — so a file that exists but cannot be read
// (EACCES, EIO, a race with another writer) was recorded as absent, and the
// rollback meant to put the host back deleted /etc/ssh/sshd_config and the
// trusted CA keys file instead. Losing SSH access to the host is precisely what
// the rollback path exists to prevent.
func TestUnreadableFileIsNotTreatedAsAbsent(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: cfgPath, Err: errors.New("permission denied")}

	for _, tc := range []struct{ name, path string }{
		{"sshd_config unreadable", cfgPath},
		{"trusted CA keys unreadable", trustPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newMemFS()
			// Both files EXIST with real content an operator would not want deleted.
			fs.files[cfgPath] = []byte("PermitRootLogin no\n")
			fs.files[trustPath] = []byte("ssh-ed25519 AAAApre-existing existing-ca\n")
			fs.failRead(tc.path, denied)

			a := newApplier(t, fs, &fakeReloader{}, &auditsink.Recorder{})
			_, err := a.AddCATrust(context.Background(), []byte(caLine))
			if err == nil {
				t.Fatal("AddCATrust proceeded despite being unable to read the file it would need " +
					"to restore; a later rollback would delete it rather than put it back")
			}

			// Nothing may have been destroyed, and nothing half-applied.
			for _, p := range []string{cfgPath, trustPath} {
				if _, still := fs.files[p]; !still {
					t.Errorf("%s was deleted after a read failure; the host lost its SSH configuration", p)
				}
			}
			if string(fs.files[trustPath]) != "ssh-ed25519 AAAApre-existing existing-ca\n" {
				t.Errorf("existing trust was modified despite the failure: %q", fs.files[trustPath])
			}
		})
	}
}

// TestRemoveCATrustAlsoRefusesUnreadableBackups covers the other entry point,
// which read the same two files the same way.
func TestRemoveCATrustAlsoRefusesUnreadableBackups(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: trustPath, Err: errors.New("input/output error")}
	memfs := newMemFS()
	memfs.files[cfgPath] = []byte("TrustedUserCAKeys " + trustPath + "\n")
	memfs.files[trustPath] = []byte(caLine + "\n")
	memfs.failRead(trustPath, denied)

	a := newApplier(t, memfs, &fakeReloader{}, &auditsink.Recorder{})
	a.cfg.AllowUnconfirmedRemoval = true
	if err := a.RemoveCATrust(context.Background(), []byte(caLine), true); err == nil {
		t.Fatal("RemoveCATrust proceeded on an unreadable trust file")
	}
	if _, still := memfs.files[trustPath]; !still {
		t.Error("the trust file was deleted after a read failure")
	}
}

// TestAbsentFileIsStillTreatedAsAbsent keeps the legitimate case working: a file
// that genuinely does not exist must still be reported absent, so rollback
// removes what the applier itself created rather than restoring a phantom.
func TestAbsentFileIsStillTreatedAsAbsent(t *testing.T) {
	memfs := newMemFS()
	a := newApplier(t, memfs, &fakeReloader{}, &auditsink.Recorder{})

	data, existed, err := a.read("/no/such/file")
	if err != nil {
		t.Fatalf("a genuinely absent file reported an error: %v", err)
	}
	if existed || data != nil {
		t.Fatalf("absent file reported existed=%v data=%q", existed, data)
	}

	// And the happy path still works end to end from nothing.
	changed, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err != nil || !changed {
		t.Fatalf("AddCATrust from a clean host: changed=%v err=%v", changed, err)
	}
}
