// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestWipeConfigSecretsCoversEveryInlineAuthorityField(t *testing.T) {
	values := [][]byte{
		[]byte("aws-secret"), []byte("aws-session"), []byte("azure-token"),
		[]byte("gcp-token"), []byte("pkcs-pin"), []byte("tpm-owner"),
		[]byte("tpm-key"), []byte("yubi-pin"),
	}
	cfg := managedKeyConfig{
		AWS:      awsConfig{SecretAccessKey: values[0], SessionToken: values[1]},
		Azure:    cloudTokenConfig{BearerToken: values[2]},
		GCP:      gcpConfig{BearerToken: values[3]},
		PKCS11:   pkcs11Config{UserPIN: values[4]},
		TPM2:     tpm2Config{OwnerAuth: values[5], KeyAuth: values[6]},
		YubiHSM2: pkcs11Config{UserPIN: values[7]},
	}
	wipeConfigSecrets(&cfg)
	for field, value := range values {
		for index, b := range value {
			if b != 0 {
				t.Fatalf("inline authority field %d byte %d was not wiped", field, index)
			}
		}
	}
	if cfg.AWS.SecretAccessKey != nil || cfg.AWS.SessionToken != nil ||
		cfg.Azure.BearerToken != nil || cfg.GCP.BearerToken != nil ||
		cfg.PKCS11.UserPIN != nil || cfg.TPM2.OwnerAuth != nil ||
		cfg.TPM2.KeyAuth != nil || cfg.YubiHSM2.UserPIN != nil {
		t.Fatal("wiped inline authority fields retained slice references")
	}
}

func TestProviderOptionRejectsInlineSecretConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.json")
	raw := []byte(`{"enabled":true,"provider":"aws","aws":{"region":"us-test-1","access_key_id":"dod","secret_access_key":"aW5saW5l"}}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ProviderOption(path, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "inline secrets are forbidden") {
		t.Fatalf("ProviderOption error = %v, want inline-secret refusal", err)
	}
}

func TestManagedKeySignerEgressRequiresHTTPSExceptExplicitLoopback(t *testing.T) {
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
			_, err := egressClient([]string{"10.0.0.0/8", "127.0.0.0/8"}, tt.endpoint, tt.allow)
			if (err == nil) != tt.ok {
				t.Fatalf("egressClient() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestManagedKeySignerExplicitLoopbackClientConnects(t *testing.T) {
	const endpoint = "http://127.0.0.1:0"
	client, err := egressClient(nil, endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(endpoint); err == nil || errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("loopback dial error = %v, want connection failure after passing transport policy", err)
	}
}
