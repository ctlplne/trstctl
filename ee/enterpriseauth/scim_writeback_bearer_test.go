// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"path/filepath"
	"sync"
	"testing"
)

// A207-L1: the writeback bearer reloads a rotated file, keeps the last good
// bearer over an unreadable or empty rewrite, and never hands a request bytes
// a reload is wiping.
func TestSCIMWritebackBearerReloadsAndKeepsTheLastGoodA207L1(t *testing.T) {
	saved := scimTokenRecheck
	scimTokenRecheck = 0
	t.Cleanup(func() { scimTokenRecheck = saved })
	path := filepath.Join(t.TempDir(), "writeback.token")
	if err := writeSecretFile(path, []byte("bearer-one")); err != nil {
		t.Fatal(err)
	}
	b, err := newSCIMWritebackBearer(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.destroy)
	current := func() string {
		var got string
		if err := b.use(func(bearer []byte) error { got = string(bearer); return nil }); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := current(); got != "bearer-one" {
		t.Fatalf("loaded %q", got)
	}
	if err := writeSecretFile(path, []byte("bearer-two-longer\n")); err != nil {
		t.Fatal(err)
	}
	if got := current(); got != "bearer-two-longer" {
		t.Fatalf("after rotation %q", got)
	}
	if err := writeSecretFile(path, []byte(" \n")); err != nil {
		t.Fatal(err)
	}
	if got := current(); got != "bearer-two-longer" {
		t.Fatalf("after an empty rewrite %q; want the last good bearer", got)
	}
	if _, err := newSCIMWritebackBearer(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing file was accepted")
	}

	// Rotations racing requests: every request sees a whole bearer.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = b.use(func(bearer []byte) error {
					if s := string(bearer); s != "bearer-a-aaaaaaaa" && s != "bearer-b-bbbbbbbb" && s != "bearer-two-longer" {
						t.Errorf("a request saw %q", s)
					}
					return nil
				})
			}
		}()
	}
	for i := 0; i < 50; i++ {
		v := "bearer-a-aaaaaaaa"
		if i%2 == 1 {
			v = "bearer-b-bbbbbbbb"
		}
		if err := writeSecretFile(path, []byte(v)); err != nil {
			t.Fatal(err)
		}
		_ = b.use(func([]byte) error { return nil })
	}
	wg.Wait()
}
