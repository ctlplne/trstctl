// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Part 4: operators point trust.weak_key_blocklist_files (or
// TRSTCTL_TRUST_WEAK_KEY_BLOCKLIST_FILES) at Debian's openssl-blacklist files;
// a missing, empty or malformed list fails validation instead of checking
// nothing.
func TestWeakKeyBlocklistFilesLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "blacklist.RSA-2048")
	if err := os.WriteFile(good, []byte("# Debian openssl-blacklist format\n0000117ed71b2acc12ae\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "blacklist.RSA-1024")
	if err := os.WriteFile(bad, []byte("not-a-fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	c.applyEnv(func(k string) string {
		return map[string]string{"TRSTCTL_TRUST_WEAK_KEY_BLOCKLIST_FILES": good}[k]
	})
	if len(c.Trust.WeakKeyBlocklistFiles) != 1 || c.Trust.WeakKeyBlocklistFiles[0] != good {
		t.Fatalf("env = %+v", c.Trust)
	}
	lists, err := LoadWeakKeyBlocklists(c.Trust)
	if err != nil || len(lists) != 1 || lists[0].Name != "blacklist.RSA-2048" || lists[0].Len() != 1 {
		t.Fatalf("lists = %+v %v", lists, err)
	}
	if errs := validateTrust(c); len(errs) != 0 {
		t.Fatalf("a good list failed validation: %v", errs)
	}
	for _, files := range [][]string{{bad}, {filepath.Join(dir, "missing")}} {
		c.Trust.WeakKeyBlocklistFiles = files
		errs := validateTrust(c)
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), "trust.weak_key_blocklist_files") {
			t.Fatalf("files %v: errors %v", files, errs)
		}
	}
}
