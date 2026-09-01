// SPDX-License-Identifier: MPL-2.0

//go:build windows

package secretfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func TestWindowsPrivateCustodyUsesDACLAndRejectsEveryone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := secretfile.Create(path, []byte("secret")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	private, err := secretfile.IsPrivate(path)
	if err != nil {
		t.Fatalf("IsPrivate: %v", err)
	}
	if !private {
		t.Fatal("new secret does not have an owner/system/administrator-only DACL")
	}
	setEveryoneFullControl(t, path)
	if _, err := secretfile.Load(path); err == nil {
		t.Fatal("Load accepted a secret file writable by Everyone")
	}
}

func TestWindowsPublicCustodyAllowsReadButRejectsBroadMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.crt")
	if err := os.WriteFile(path, []byte("public certificate"), 0o644); err != nil { // #nosec G306 -- public fixture contents (CWE-276)
		t.Fatal(err)
	}
	if err := secretfile.SecurePublicFile(path); err != nil {
		t.Fatalf("SecurePublicFile: %v", err)
	}
	tamperSafe, err := secretfile.PublicFileTamperSafe(path)
	if err != nil {
		t.Fatalf("PublicFileTamperSafe: %v", err)
	}
	if !tamperSafe {
		t.Fatal("public certificate DACL is not tamper-safe")
	}
	setEveryoneFullControl(t, path)
	tamperSafe, err = secretfile.PublicFileTamperSafe(path)
	if err != nil {
		t.Fatalf("PublicFileTamperSafe after broadening: %v", err)
	}
	if tamperSafe {
		t.Fatal("public certificate writable by Everyone was reported tamper-safe")
	}
}

func setEveryoneFullControl(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("build deliberately unsafe DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("install deliberately unsafe DACL: %v", err)
	}
}
