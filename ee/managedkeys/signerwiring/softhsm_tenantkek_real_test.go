// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build pkcs11cgo && cgo

package signerwiring_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/managedkeys/signerwiring"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/signing"
)

// The container harness provisions these with pkcs11-tool, as an operator would.
const (
	softHSMTenantKEKLabel   = "trstctl-tenant-kek-a"
	softHSMExtractableLabel = "trstctl-tenant-kek-extractable"
)

func softHSMTenantKEKConfig(t *testing.T, label string) string {
	t.Helper()
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" || os.Getenv("TRSTCTL_SOFTHSM_AES_KEYS") != "1" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, TRSTCTL_SOFTHSM_USER_PIN and provisioned AES keys are required")
	}
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "user-pin")
	if err := os.WriteFile(pinFile, []byte(userPIN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "tenant-kek.json")
	body := `{"pkcs11":{"module_path":"` + modulePath + `","token_label":"` + tokenLabel + `","user_pin_file":"` + pinFile + `"},` +
		`"wrappers":[{"id":"hsm-a","key_label":"` + label + `"}]}`
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return config
}

// serveTenantKEK runs a signer with the tenant KEK custody from config on a
// fresh socket and returns a client; stop shuts it down.
func serveTenantKEK(t *testing.T, config string) (client *signing.Client, stop func()) {
	t.Helper()
	option, err := signerwiring.TenantKEKOption(config)
	if err != nil {
		t.Fatalf("tenant KEK custody from the signer config: %v", err)
	}
	socket := filepath.Join(t.TempDir(), "signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(option), signing.ServeOptions{})
	}()
	client, err = signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial the signer: %v", err)
	}
	return client, func() {
		_ = client.Close()
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("signer: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the signer did not stop")
		}
	}
}

// A123 against SoftHSM: the signer creates a tenant domain KEK wrapped by the
// operator's HSM AES key and returns only the wrapped form; it wraps and
// unwraps data keys through it; a wrong binding or an unknown wrapper fails in
// its class; after a signer restart the same wrapped KEK still opens; and a
// configuration naming an extractable or missing HSM key stops startup.
func TestSoftHSMSignerKeepsTenantDomainKEKs(t *testing.T) {
	config := softHSMTenantKEKConfig(t, softHSMTenantKEKLabel)
	ctx := context.Background()
	binding := []byte("tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;domain=11111111-1111-4111-8111-111111111111;generation=1")

	client, stop := serveTenantKEK(t, config)
	wrapped, err := client.CreateTenantDomainKEK(ctx, "hsm-a", binding)
	if err != nil || !bytes.HasPrefix(wrapped, []byte("TDH1")) {
		t.Fatalf("create a tenant domain KEK = %v", err)
	}
	if err := client.OpenTenantDomainKEK(ctx, "hsm-a", wrapped, binding); err != nil {
		t.Fatalf("open the domain KEK: %v", err)
	}
	if err := client.OpenTenantDomainKEK(ctx, "hsm-a", wrapped, []byte("tenant=b;domain=d;generation=1")); !errors.Is(err, tenantwrap.ErrUnwrap) {
		t.Fatalf("open under another binding = %v, want an unwrap failure", err)
	}
	if _, err := client.CreateTenantDomainKEK(ctx, "hsm-z", binding); !errors.Is(err, signing.ErrTenantKEKWrapperUnknown) {
		t.Fatalf("create under an unknown wrapper = %v", err)
	}
	dek, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := client.WrapTenantDataKey(ctx, "hsm-a", wrapped, binding, dek)
	if err != nil {
		t.Fatalf("wrap a data key: %v", err)
	}
	stop()

	client, stop = serveTenantKEK(t, config)
	defer stop()
	back, err := client.UnwrapTenantDataKey(ctx, "hsm-a", wrapped, binding, wrappedDEK)
	if err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap after a signer restart = %v", err)
	}

	for _, label := range []string{softHSMExtractableLabel, "trstctl-no-such-key"} {
		if _, err := signerwiring.TenantKEKOption(softHSMTenantKEKConfig(t, label)); err == nil {
			t.Fatalf("a tenant KEK config naming %s started", label)
		}
	}
	t.Log("SOFTHSM_TENANT_KEK_OK")
}
