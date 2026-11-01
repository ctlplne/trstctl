// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// Q3: a saved CBOM export verifies offline against the pinned audit evidence
// keys and yields exactly the signed BOM; a changed BOM, another key or
// another evidence kind does not verify.
func TestCBOMVerifyCycloneDXOffline(t *testing.T) {
	dir := t.TempDir()
	key, err := jose.GenerateRSASigningKey("q3-cli")
	if err != nil {
		t.Fatal(err)
	}
	bom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3f2f1c1e-7c1a-5b7e-9a1d-3e2c1b0a9f8e","version":1,"components":[{"type":"cryptographic-asset","bom-ref":"a1","name":"RSA-2048"}]}`)
	signed, err := key.SignArtifact(jose.ArtifactCBOMCycloneDX, bom)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) string {
		t.Helper()
		var data []byte
		switch x := v.(type) {
		case []byte:
			data = x
		default:
			data, err = json.MarshalIndent(x, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// The CLI saves the response pretty-printed; verification compares the
	// document, not the formatting.
	export := write("export.json", map[string]any{"spec_version": "1.6", "components": 1, "bom": json.RawMessage(bom), "signed_bom": signed, "public_jwks": json.RawMessage(jwks)})
	pinned := write("audit.jwks.json", jwks)
	out := filepath.Join(dir, "cbom.cdx.json")
	var stdout, stderr bytes.Buffer
	if code := runCBOMVerifyCycloneDX([]string{"--export", export, "--audit-jwks", pinned, "--bom-out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify = %d: %s", code, stderr.String())
	}
	written, err := os.ReadFile(out) // #nosec G304 -- a file this test wrote under t.TempDir (CWE-22)
	if err != nil || !bytes.Equal(written, bom) || !strings.Contains(stdout.String(), "CycloneDX 1.6 CBOM urn:uuid:") {
		t.Fatalf("verified output %q / %s (%v)", written, stdout.String(), err)
	}

	changed := bytes.Replace(bom, []byte("RSA-2048"), []byte("RSA-4096"), 1)
	tampered := write("tampered.json", map[string]any{"bom": json.RawMessage(changed), "signed_bom": signed})
	other, err := jose.GenerateRSASigningKey("q3-other")
	if err != nil {
		t.Fatal(err)
	}
	otherJWKS, err := other.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := key.SignArtifact(jose.ArtifactCryptoReadiness, bom)
	if err != nil {
		t.Fatal(err)
	}
	wrongKind := write("wrong-kind.json", map[string]any{"bom": json.RawMessage(bom), "signed_bom": readiness})
	for name, args := range map[string][]string{
		"changed bom":   {"--export", tampered, "--audit-jwks", pinned},
		"another key":   {"--export", export, "--audit-jwks", write("other.jwks.json", otherJWKS)},
		"another kind":  {"--export", wrongKind, "--audit-jwks", pinned},
		"missing flags": {"--export", export},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runCBOMVerifyCycloneDX(args, &stdout, &stderr); code == 0 {
			t.Fatalf("%s verified: %s", name, stdout.String())
		}
	}
}
