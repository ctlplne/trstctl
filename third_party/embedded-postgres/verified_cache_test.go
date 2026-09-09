// SPDX-License-Identifier: MIT
//go:build unix

package embeddedpostgres

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifiedCacheAcceptsOwnedStickyAnchor(t *testing.T) {
	anchor := t.TempDir()
	root, err := os.OpenRoot(anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Controlled positive fixture for an ordinary shared temporary directory.
	if err := root.Chmod(".", os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenVerifiedCache(anchor, "archives", "identity")
	if err != nil {
		t.Fatalf("owned sticky anchor rejected: %v", err)
	}
	if cache.Path() != filepath.Join(anchor, "archives", "identity") {
		t.Errorf("unexpected cache path: %s", cache.Path())
	}
	for _, name := range []string{"archives", "archives/identity"} {
		info, err := root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
			t.Errorf("cache child is not private: %s: %v", name, err)
		}
	}
	if err := cache.Close(); err != nil {
		t.Errorf("close verified cache: %v", err)
	}
}
