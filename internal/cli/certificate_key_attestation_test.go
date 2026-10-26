// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// A131: verify-key-attestation re-checks the evidence 'certificates
// key-attestation' prints, on this machine, against the roots the operator
// names; untrusted roots, an edited binding, and another certificate fail.
func TestCertificatesVerifyKeyAttestationRechecksTheClaimOffline(t *testing.T) {
	dir := t.TempDir()
	verifiedAt := time.Now().UTC().Truncate(time.Second)
	identity, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := deviceattest.CSRPublicKeySHA256(identity.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte(`{"version":1,"order_id":"order-cli","csr_key_sha256":"` + base64.RawURLEncoding.EncodeToString(keyDigest) + `"}`)
	credential, err := identity.CredentialJSON(crypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.NewBuiltin("verify-key-attestation test CA")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authority.Issue(context.Background(), ca.IssueRequest{
		CSR: identity.CSRDER(), DNSNames: []string{"host-01.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	evidenceFile := func(name string, binding []byte) string {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"fingerprint": "fp-cli", "format": "tpm-webauthn", "credential": credential, "binding": binding,
			"verified_at": verifiedAt, "certificate_pem": string(issued.CertificatePEM),
		})
		if err != nil {
			t.Fatal(err)
		}
		return write(name, raw)
	}
	good := evidenceFile("evidence.json", binding)
	roots := write("roots.pem", identity.RootPEM())

	var stdout, stderr bytes.Buffer
	if code := runCertificateVerifyKeyAttestation([]string{"--evidence", good, "--roots", roots}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "verified: certificate fp-cli holds a device-bound key") {
		t.Fatalf("verify = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	other, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	otherIssued, err := authority.Issue(context.Background(), ca.IssueRequest{
		CSR: other.CSRDER(), DNSNames: []string{"host-01.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"untrusted roots":     {"--evidence", good, "--roots", write("other-roots.pem", other.RootPEM())},
		"edited binding":      {"--evidence", evidenceFile("edited.json", bytes.Replace(binding, []byte("order-cli"), []byte("order-two"), 1)), "--roots", roots},
		"another certificate": {"--evidence", good, "--roots", roots, "--certificate", write("other.pem", otherIssued.CertificatePEM)},
	} {
		stderr.Reset()
		if code := runCertificateVerifyKeyAttestation(args, &stdout, &stderr); code != 1 {
			t.Fatalf("%s = %d stderr=%s, want a refusal", name, code, stderr.String())
		}
	}
}
