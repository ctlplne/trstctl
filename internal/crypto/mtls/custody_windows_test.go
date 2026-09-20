// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package mtls_test

import (
	"testing"

	"golang.org/x/sys/windows"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func assertPrivateStateCustody(t *testing.T, path string) {
	t.Helper()
	private, err := secretfile.IsPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !private {
		t.Fatal("persistent internal TLS state DACL is not private")
	}
}

func assertPublicTrustCustody(t *testing.T, path string) {
	t.Helper()
	tamperSafe, err := secretfile.PublicFileTamperSafe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !tamperSafe {
		t.Fatal("published trust DACL permits untrusted mutation")
	}
}

func makePrivateStateUnsafe(t *testing.T, path string) {
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
