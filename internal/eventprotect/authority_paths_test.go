// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileAuthorityRejectsDanglingBackupAliasToFutureCustody(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "future-keys")
	alias := filepath.Join(base, "ordinary-backup-source")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	authority, err := NewFileAuthority(FileAuthorityConfig{Directory: directory, BackupRoots: []string{alias}, Locker: immediateKeyLocker{}})
	if authority != nil {
		_ = authority.Close()
	}
	if err == nil {
		t.Fatal("dangling backup symlink concealed future key-custody overlap")
	}
}

func TestFileAuthorityRejectsFilesystemAliasesOfCustody(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "Keys")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "keys")
	left, leftErr := os.Stat(directory)
	right, rightErr := os.Stat(alias)
	if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
		t.Skip("this filesystem does not alias the case-variant path")
	}
	authority, err := NewFileAuthority(FileAuthorityConfig{Directory: directory, BackupRoots: []string{filepath.Join(alias, "future-backup")}, Locker: immediateKeyLocker{}})
	if authority != nil {
		_ = authority.Close()
	}
	if err == nil {
		t.Fatal("filesystem identity alias concealed custody/backup overlap")
	}
}
