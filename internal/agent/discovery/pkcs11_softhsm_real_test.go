// SPDX-License-Identifier: BUSL-1.1

//go:build cgo

package discovery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSoftHSMAgentInventoryReadsTokenCertificates runs inside the SoftHSM
// container (see pkcs11_softhsm_container_test.go): it writes a certificate and
// a key pair onto a real token with pkcs11-tool, then proves the agent's
// PKCS#11 source reports the certificate, says nothing about the key, works
// without a PIN for a public certificate object, and fails rather than reading
// empty when the PIN is wrong.
func TestSoftHSMAgentInventoryReadsTokenCertificates(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skipf("pkcs11-tool is required to seed the token: %v", err)
	}

	der := pkcs11TestCertDER(t, "inventory-leaf.test")
	certPath := filepath.Join(t.TempDir(), "inventory-leaf.der")
	if err := os.WriteFile(certPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	seed := func(args ...string) {
		t.Helper()
		base := []string{"--module", modulePath, "--token-label", tokenLabel, "--login", "--pin", userPIN}
		out, err := exec.Command("pkcs11-tool", append(base, args...)...).CombinedOutput() // #nosec G204 G702 -- fixed test-harness invocation of the OpenSC tool; the module path, token label and PIN come from the container harness environment, not from a request (CWE-78)
		if err != nil {
			t.Fatalf("pkcs11-tool %v: %v\n%s", args, err, out)
		}
	}
	seed("--write-object", certPath, "--type", "cert", "--label", "inventory-leaf")
	seed("--keypairgen", "--key-type", "EC:prime256v1", "--label", "inventory-key")

	ctx := context.Background()
	withPIN := NewPKCS11CertSource(PKCS11Config{ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN)})
	found, err := withPIN.Discover(ctx)
	if err != nil {
		t.Fatalf("discover with PIN: %v", err)
	}
	assertOnlyTheCertificate(t, found, tokenLabel)

	// A public certificate object is readable without a login, which is how a
	// fleet inventories tokens whose PIN it should not hold.
	noPIN := NewPKCS11CertSource(PKCS11Config{ModulePath: modulePath, TokenLabel: tokenLabel})
	found, err = noPIN.Discover(ctx)
	if err != nil {
		t.Fatalf("discover without PIN: %v", err)
	}
	assertOnlyTheCertificate(t, found, tokenLabel)

	wrongPIN := NewPKCS11CertSource(PKCS11Config{ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte("000000")})
	if found, err := wrongPIN.Discover(ctx); err == nil {
		t.Fatalf("a wrong PIN must fail the token, not read it as %d findings", len(found))
	}

	other := NewPKCS11CertSource(PKCS11Config{ModulePath: modulePath, TokenLabel: "no-such-token"})
	if found, err := other.Discover(ctx); err != nil || len(found) != 0 {
		t.Fatalf("a token label that matches nothing reads as empty without error: found=%d err=%v", len(found), err)
	}
	t.Log("SOFTHSM_AGENT_INVENTORY_OK")
}

func assertOnlyTheCertificate(t *testing.T, found []Found, tokenLabel string) {
	t.Helper()
	if len(found) != 1 {
		t.Fatalf("expected exactly the seeded certificate, got %d findings: %+v", len(found), found)
	}
	f := found[0]
	if f.Source != SourcePKCS11 || !strings.Contains(f.Location, tokenLabel) || !strings.Contains(f.Location, "inventory-leaf") {
		t.Fatalf("finding must be located by token and object label: %+v", f)
	}
	if !strings.Contains(f.Cert.Subject, "inventory-leaf.test") {
		t.Fatalf("finding must carry the certificate's metadata: %+v", f.Cert)
	}
	for k, v := range f.Metadata {
		if strings.Contains(strings.ToLower(k), "key") || strings.Contains(v, "inventory-key") {
			t.Fatalf("a PKCS#11 inventory finding must say nothing about key objects: %s=%s", k, v)
		}
	}
}
