// SPDX-License-Identifier: BUSL-1.1

package kmsconn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
)

func TestLockCredentialBytesWipesWholeWhitespaceWrappedFileBuffer(t *testing.T) {
	fileBuffer := []byte(" \tmanaged-key-secret\r\n")
	credential, destroy, err := lockCredentialBytes("test credential", fileBuffer, true)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	if !bytes.Equal(credential, []byte("managed-key-secret")) {
		t.Fatalf("credential = %q, want trimmed payload", credential)
	}
	for index, value := range fileBuffer {
		if value != 0 {
			t.Fatalf("original file buffer byte %d was not wiped", index)
		}
	}
}

func TestReadCredentialFileReadsThroughParentDirectoryHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("managed-key-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := readCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte("managed-key-token")) {
		t.Fatalf("readCredentialFile() = %q, want the file contents", raw)
	}
}

func TestReadCredentialFileFollowsIndirectionInsideTheDirectory(t *testing.T) {
	// Kubernetes projected secret volumes publish token -> ..data/token, with
	// ..data itself a symlink to a timestamped sibling. Both hops stay inside the
	// mount directory, so credential loading must keep working there.
	dir := t.TempDir()
	generation := filepath.Join(dir, "..2026_08_02_00_00_00")
	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generation, "token"), []byte("projected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_08_02_00_00_00", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	raw, err := readCredentialFile(filepath.Join(dir, "token"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte("projected")) {
		t.Fatalf("readCredentialFile() = %q, want the projected secret", raw)
	}
}

func TestReadCredentialFileRefusesSymlinkOutOfTheDirectory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, []byte("not-the-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	raw, err := readCredentialFile(path)
	if err == nil {
		t.Fatalf("readCredentialFile() = %q, want refusal of an escaping symlink", raw)
	}
	if bytes.Contains(raw, []byte("not-the-credential")) {
		t.Fatal("readCredentialFile returned bytes from outside the credential directory")
	}
}

func TestCredentialFileRequiresAPathAndContentWhenRequired(t *testing.T) {
	if _, _, err := CredentialFile("pin", "", true); err == nil {
		t.Fatal("a required credential without a file was accepted")
	}
	if value, destroy, err := CredentialFile("session", "", false); err != nil || value != nil {
		t.Fatalf("an optional credential without a file = %q, %v", value, err)
	} else {
		destroy()
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CredentialFile("pin", empty, true); err == nil {
		t.Fatal("a required credential from an empty file was accepted")
	}
}

func TestEgressRequiresHTTPSExceptExplicitLoopback(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		allow    bool
		ok       bool
	}{
		{name: "HTTPS", endpoint: "https://kms.example.test", ok: true},
		{name: "public HTTP", endpoint: "http://198.51.100.10:8080", allow: true},
		{name: "private HTTP", endpoint: "http://10.1.2.3:8080", allow: true},
		{name: "private grant alone", endpoint: "http://127.0.0.1:8080"},
		{name: "explicit loopback", endpoint: "http://127.0.0.1:8080", allow: true, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EgressClient([]string{"10.0.0.0/8", "127.0.0.0/8"}, tt.endpoint, tt.allow)
			if (err == nil) != tt.ok {
				t.Fatalf("EgressClient() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestExplicitLoopbackClientConnects(t *testing.T) {
	const endpoint = "http://127.0.0.1:0"
	client, err := EgressClient(nil, endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(endpoint); err == nil || errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("loopback dial error = %v, want connection failure after passing transport policy", err)
	}
}

func TestValidateEndpointsNeedsALoopbackEndpointForTheLoopbackGrant(t *testing.T) {
	if err := ValidateEndpoints("aws managed-key", true, "https://kms.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("allow_insecure_loopback without a loopback endpoint was accepted")
	}
	if err := ValidateEndpoints("aws managed-key", false, "http://127.0.0.1:4566"); err == nil {
		t.Fatal("plain HTTP without the loopback grant was accepted")
	}
	if err := ValidateEndpoints("aws managed-key", true, "http://127.0.0.1:4566", ""); err != nil {
		t.Fatalf("an explicit loopback endpoint = %v", err)
	}
}
