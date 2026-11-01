// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// P9 against the stock Notation CLI (owner decision 2026-11-01, outside input
// c): the notation-trstctl plugin built from clients/signing is installed into
// an isolated Notation home, `notation sign` signs an image in a local
// registry with a key that never leaves trstctl's signer, and `notation
// verify` accepts it under a strict trust policy rooted at the CA that issued
// the key's certificate; a principal that may not sign is refused. Run by
// runners/p9-notation-lab-proof.sh, which starts registry:2 and pushes a
// sample image; skipped otherwise.
func TestNotationSignsAndVerifiesThroughTrstctlP9(t *testing.T) {
	notation, image := os.Getenv("TRSTCTL_P9_LAB_NOTATION"), os.Getenv("TRSTCTL_P9_LAB_NOTATION_IMAGE")
	if notation == "" || image == "" {
		t.Skip("run runners/p9-notation-lab-proof.sh (the Notation CLI and registry:2 with a sample image)")
	}
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signingKey.Destroy)
	ca := newP9CA(t)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer", RequestedEKUs: []string{"codeSigning"}}, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{ca.issue(t, csr, "codeSigning"), ca.rootDER}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys:            codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": testOperationDigestSigner{DigestSigner: signingKey}}},
			KeyCertificates: map[string][][]byte{codeSigningKeyIdentity(servedTestTenant, "release-key"): chain},
		}
	})
	startServedExternalCADispatcher(t, h)
	signer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	reader := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-reader", []string{string(authz.KeysRead)})
	plugin := buildP9NotationPlugin(t)

	home := t.TempDir()
	work := t.TempDir()
	rootFile := filepath.Join(work, "root.pem")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.rootDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	repository := image[:strings.LastIndex(image, "@")]
	policy := `{"version":"1.0","trustPolicies":[{"name":"trstctl-p9","registryScopes":["` + repository +
		`"],"signatureVerification":{"level":"strict"},"trustStores":["ca:trstctl-p9"],"trustedIdentities":["*"]}]}`
	policyFile := filepath.Join(work, "trustpolicy.json")
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil { // #nosec G703 -- the lab trust policy in the test's own temp directory (CWE-22)
		t.Fatal(err)
	}
	run := func(token string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, notation, args...) // #nosec G204 G702 -- the lab runner names the verified Notation binary (CWE-78)
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
			"TRSTCTL_URL="+h.ts.URL, "TRSTCTL_TOKEN="+token, "TRSTCTL_TOKEN_FILE=", "TRSTCTL_CA_FILE=", "TRSTCTL_APPROVAL_WAIT=0")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	for _, step := range [][]string{
		{"plugin", "install", "--file", plugin},
		{"plugin", "list"},
		{"key", "add", "release", "--plugin", "trstctl", "--id", "release-key", "--default"},
		{"cert", "add", "--type", "ca", "--store", "trstctl-p9", rootFile},
		{"policy", "import", "--force", policyFile},
	} {
		if out, err := run(signer, step...); err != nil {
			t.Fatalf("notation %s: %v\n%s", strings.Join(step, " "), err, out)
		}
	}
	out, err := run(signer, "sign", "--insecure-registry", "--key", "release", image)
	if err != nil || !strings.Contains(out, "Successfully signed") {
		t.Fatalf("stock notation sign through trstctl: %v\n%s", err, out)
	}
	t.Logf("notation sign: %s", strings.TrimSpace(out))
	out, err = run(signer, "verify", "--insecure-registry", image)
	if err != nil || !strings.Contains(out, "Successfully verified signature") {
		t.Fatalf("stock notation verify: %v\n%s", err, out)
	}
	t.Logf("notation verify: %s", strings.TrimSpace(out))
	if out, err := run(reader, "sign", "--insecure-registry", "--key", "release", image); err == nil || !strings.Contains(out, "ACCESS_DENIED") && !strings.Contains(out, "HTTP 403") {
		t.Fatalf("a principal without keys:write signed through Notation: %v\n%s", err, out)
	}
}
