// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestServedSSHCertificateLeaseVerifiesAndIsRevokedOnTheKRLA239L11 is A239-L11
// over the served API with the stock ssh-keygen. An ssh-certificate provider
// issues a lease: a fresh Ed25519 private key and an OpenSSH user certificate
// for the role's principal, signed by the served SSH CA (ssh-keygen -L names
// the principal, the lease's key ID and the CA's fingerprint; the private key's
// fingerprint is the certified key's). The served KRL passes it; renewing it is
// refused (a certificate can't be extended); revoking the lease puts its key ID
// on the served KRL, which ssh-keygen -Q then reports revoked. A role whose
// principal protocols.ssh_user_principals doesn't list gets no certificate.
func TestServedSSHCertificateLeaseVerifiesAndIsRevokedOnTheKRLA239L11(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("the stock ssh-keygen is not installed here")
	}
	// The provider as an operator writes it.
	var configs []config.DynamicSecretProviderConfig
	if err := json.Unmarshal([]byte(`[{"tenant_id": "`+servedTestTenant+`", "id": "ssh-deploy", "type": "ssh-certificate", "max_ttl": "1h",
	  "allowed_roles": ["deploy-shell", "root-shell"],
	  "ssh_roles": {"deploy-shell": {"principals": ["deploy"], "extensions": {"permit-pty": ""}},
	                "root-shell": {"principals": ["root"]}}}]`), &configs); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{
		SSH:               config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SSHUserPrincipals: []string{"deploy"},
	}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239-L11 SSH certificate lease tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	dir := t.TempDir()
	keygen := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command(sshKeygen, args...).CombinedOutput() // #nosec G204 G702 -- test executes a fixed local tool on its own temp files (CWE-78)
		return string(out), err
	}
	fetch := func(path, file string) string {
		t.Helper()
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		out := filepath.Join(dir, file)
		if err := os.WriteFile(out, body, 0o644); err != nil { // #nosec G306 -- public CA/KRL fixture in a test tempdir (CWE-276)
			t.Fatal(err)
		}
		return out
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l11-lease-1",
		map[string]any{"provider": "ssh-deploy", "role": "deploy-shell", "ttl_seconds": 600})
	if status != http.StatusCreated {
		t.Fatalf("issue an SSH certificate lease: HTTP %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		PrivateKey  string   `json:"private_key"`
		Certificate string   `json:"certificate"`
		KeyID       string   `json:"key_id"`
		Principals  []string `json:"principals"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.PrivateKey == "" || credential.Certificate == "" {
		t.Fatalf("the lease's credential: %v", err)
	}
	if credential.KeyID != "trstctl-"+lease.ID || len(credential.Principals) != 1 || credential.Principals[0] != "deploy" {
		t.Fatalf("the lease's certificate is %s for %v", credential.KeyID, credential.Principals)
	}
	keyPath, certPath := filepath.Join(dir, "id_ed25519"), filepath.Join(dir, "id_ed25519-cert.pub")
	if err := os.WriteFile(keyPath, []byte(credential.PrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(credential.Certificate), 0o644); err != nil { // #nosec G306 -- a public certificate in a test tempdir (CWE-276)
		t.Fatal(err)
	}

	// ssh-keygen reads the certificate: the principal, the key ID, the CA.
	listing, err := keygen("-L", "-f", certPath)
	if err != nil {
		t.Fatalf("ssh-keygen -L: %v\n%s", err, listing)
	}
	caPath := fetch("/ssh/ca", "ca.pub")
	caPrint, err := keygen("-l", "-f", caPath)
	if err != nil {
		t.Fatalf("ssh-keygen -l the CA: %v\n%s", err, caPrint)
	}
	keyPrint, err := keygen("-l", "-f", keyPath)
	if err != nil {
		t.Fatalf("ssh-keygen -l the lease's private key: %v\n%s", err, keyPrint)
	}
	fingerprint := regexp.MustCompile(`SHA256:[A-Za-z0-9+/]+`)
	caFP, keyFP := fingerprint.FindString(caPrint), fingerprint.FindString(keyPrint)
	for _, want := range []string{"ssh-ed25519-cert-v01@openssh.com user certificate", `Key ID: "` + credential.KeyID + `"`,
		"Signing CA: ", caFP, "Public key: ED25519-CERT " + keyFP, "deploy", "permit-pty"} {
		if want == "" || !strings.Contains(listing, want) {
			t.Fatalf("ssh-keygen -L lacks %q:\n%s\n(CA %s, key %s)", want, listing, caPrint, keyPrint)
		}
	}
	// ssh-keygen -Q ends each line with ": ok" or ": REVOKED".
	if out, err := keygen("-Q", "-f", fetch("/ssh/krl", "before.krl"), certPath); err != nil || !strings.HasSuffix(strings.TrimSpace(out), ": ok") {
		t.Fatalf("the served KRL before revocation: %v %s", err, out)
	}

	// A certificate's validity is signed into it: no renewal.
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("SSH certificate can't be extended")) {
		t.Fatalf("renewing an SSH certificate lease: HTTP %d %s", status, body)
	}

	// Revoking the lease puts its key ID on the served KRL.
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: HTTP %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: HTTP %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, err := keygen("-Q", "-f", fetch("/ssh/krl", "after.krl"), certPath)
	if err == nil || !strings.HasSuffix(strings.TrimSpace(out), ": REVOKED") {
		t.Fatalf("ssh-keygen -Q after the lease's revocation: %v %s", err, out)
	}

	// A principal the CA may not certify gets no certificate.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l11-lease-root",
		map[string]any{"provider": "ssh-deploy", "role": "root-shell", "ttl_seconds": 600})
	var refused dynamicLeaseView
	if err := json.Unmarshal(body, &refused); err != nil || refused.Credential != "" {
		t.Fatalf("a lease for an unlisted principal: HTTP %d %s", status, body)
	}
	if refused.ID != "" {
		for deadline := time.Now().Add(60 * time.Second); refused.State != "failed"; {
			if time.Now().After(deadline) {
				t.Fatalf("the lease for an unlisted principal reads %+v, want failed", refused)
			}
			time.Sleep(200 * time.Millisecond)
			_, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+refused.ID, tok, nil)
			_ = json.Unmarshal(body, &refused)
			if refused.Credential != "" {
				t.Fatalf("the lease for an unlisted principal got a certificate: %s", body)
			}
		}
	} else if status < 400 {
		t.Fatalf("a lease for an unlisted principal: HTTP %d %s", status, body)
	}
	t.Logf("A239L11_SSH_LEASE_OK key_id=%s ca=%s", credential.KeyID, caFP)
}
