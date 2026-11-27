// SPDX-License-Identifier: BUSL-1.1

package eventauth_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/eventauth"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestProvisionKeepsOneKeyAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event-auth.key")
	if err := eventauth.Provision(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path) // #nosec G304 -- test-owned protected key path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(first)
	if len(first) != 32 {
		t.Fatalf("event authentication key length = %d", len(first))
	}
	if err := eventauth.Provision(path); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path) // #nosec G304 -- same test-owned key path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(again)
	if !bytes.Equal(first, again) {
		t.Fatal("restart replaced the event authentication key")
	}
	file := eventauth.File{Path: path}
	tag, err := file.Sign([]byte("canonical envelope"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Verify([]byte("canonical envelope"), tag); err != nil {
		t.Fatal(err)
	}
	if err := file.Verify([]byte("modified envelope"), tag); !errors.Is(err, eventauth.ErrAuthentication) {
		t.Fatalf("modified envelope verification = %v", err)
	}
	if err := file.Verify([]byte("canonical envelope"), nil); !errors.Is(err, eventauth.ErrAuthentication) {
		t.Fatalf("missing tag verification = %v", err)
	}
}
