// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestCredentialLoadsFileReferencedByConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin")
	if err := os.WriteFile(path, []byte(" 1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, destroy, err := credential("pkcs11 user PIN", nil, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	if !bytes.Equal(value, []byte("1234")) {
		t.Fatalf("credential() = %q, want the trimmed file payload", value)
	}
}

// A123: the signer-local tenant KEK file is strict. An inline PIN, an unknown
// field, a second document, a missing token, an empty or repeated wrapper
// table are refused before any module is loaded; a well-formed file reaches
// the module, here a path that does not exist.
func TestTenantKEKOptionRefusesMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinFile, []byte("987654\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := `"pkcs11":{"module_path":"` + filepath.Join(dir, "no-such-module.so") + `","token_label":"trstctl","user_pin_file":"` + pinFile + `"}`
	wrappers := `"wrappers":[{"id":"hsm-a","key_label":"tenant-kek-a"}]`
	write := func(body string) string {
		t.Helper()
		path := filepath.Join(dir, "tenant-kek.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, body := range map[string]string{
		"inline PIN":       `{"pkcs11":{"module_path":"/m.so","token_label":"t","user_pin":"OTg3NjU0"},` + wrappers + `}`,
		"unknown field":    `{` + token + `,` + wrappers + `,"cache_keys":true}`,
		"second document":  `{` + token + `,` + wrappers + `}{}`,
		"no module":        `{"pkcs11":{"token_label":"t","user_pin_file":"` + pinFile + `"},` + wrappers + `}`,
		"no wrappers":      `{` + token + `,"wrappers":[]}`,
		"repeated wrapper": `{` + token + `,"wrappers":[{"id":"hsm-a","key_label":"a"},{"id":"hsm-a","key_label":"b"}]}`,
	} {
		if _, err := TenantKEKOption(write(body)); err == nil {
			t.Errorf("%s: the tenant KEK config was accepted", name)
		} else if strings.Contains(err.Error(), "no-such-module") {
			t.Errorf("%s: refused only at module load: %v", name, err)
		}
	}
	_, err := TenantKEKOption(write(`{` + token + `,` + wrappers + `}`))
	if err == nil || !strings.Contains(err.Error(), "module") {
		t.Fatalf("a well-formed config with a missing module = %v, want a module load failure", err)
	}
}
