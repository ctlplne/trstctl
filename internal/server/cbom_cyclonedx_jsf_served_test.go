// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// Q3-L1 Done-when: the served CycloneDX export's BOM carries its own enveloped
// JSF signature (jsf-0.82: RS256, the audit evidence key's ID and public key,
// and the value over the BOM's RFC 8785 form). The BOM alone verifies with the
// keys from /api/v1/audit/verification-keys, also after reformatting; a
// changed BOM fails; the JWS beside it still covers exactly the BOM, signature
// included.
func TestServedCBOMCarriesItsOwnJSFSignatureQ3L1(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withCBOMLoopbackEgress, func(d *Deps) { d.AuditSigningKey = signingKey })
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read", "audit:read", "egress:private")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", tok, "q3l1-cbom-scan", map[string]any{
		"tls_endpoints": []string{u.Host}, "allow_private_endpoint": true,
		"private_egress_cidrs": []string{"127.0.0.1/32"},
	}); status != http.StatusCreated {
		t.Fatalf("scan = %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/export/cyclonedx", tok, nil)
	var export struct {
		BOM       json.RawMessage `json:"bom"`
		SignedBOM string          `json:"signed_bom"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &export) != nil {
		t.Fatalf("export = %d %s", status, body)
	}
	var bom struct {
		Components []json.RawMessage `json:"components"`
		Signature  *struct {
			Algorithm string `json:"algorithm"`
			KeyID     string `json:"keyId"`
			PublicKey *struct {
				Kty string `json:"kty"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"publicKey"`
			Value string `json:"value"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(export.BOM, &bom); err != nil || len(bom.Components) == 0 || bom.Signature == nil {
		t.Fatalf("the BOM carries no signature: %s (%v)", export.BOM, err)
	}
	if s := bom.Signature; s.Algorithm != "RS256" || s.KeyID != "audit-export" || s.PublicKey == nil || s.PublicKey.Kty != "RSA" ||
		s.PublicKey.N == "" || s.PublicKey.E == "" || s.Value == "" {
		t.Fatalf("the BOM's signature = %+v", *s)
	}

	status, jwks := secretsReq(t, h, http.MethodGet, "/api/v1/audit/verification-keys", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("verification keys = %d %s", status, jwks)
	}
	keys, err := jose.ParseJWKSet(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := keys.VerifyJSF(export.BOM); err != nil || kid != "audit-export" {
		t.Fatalf("verify the BOM's own signature = %q %v", kid, err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, export.BOM, "", "    "); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyJSF(pretty.Bytes()); err != nil {
		t.Fatalf("verify the reformatted BOM: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(export.BOM, &doc); err != nil {
		t.Fatal(err)
	}
	doc["components"] = doc["components"].([]any)[1:]
	dropped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyJSF(dropped); err == nil {
		t.Fatal("a BOM missing a component verified")
	}

	payload, err := keys.VerifyArtifact(export.SignedBOM, jose.ArtifactCBOMCycloneDX)
	if err != nil {
		t.Fatalf("verify the JWS beside the BOM: %v", err)
	}
	var signedDoc, carried any
	if json.Unmarshal(payload, &signedDoc) != nil || json.Unmarshal(export.BOM, &carried) != nil || !reflect.DeepEqual(signedDoc, carried) {
		t.Fatal("the JWS does not cover the BOM, embedded signature included")
	}
	// A lab run hands the served BOM and the published keys to an independent
	// JSF verifier.
	if dir := os.Getenv("TRSTCTL_Q3L1_EVIDENCE_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "served-bom.json"), export.BOM, 0o600); err != nil { // #nosec G703 -- the lab run's own evidence directory (CWE-22)
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "served-jwks.json"), jwks, 0o600); err != nil { // #nosec G703 -- the lab run's own evidence directory (CWE-22)
			t.Fatal(err)
		}
	}
	t.Logf("Q3L1_JSF_OK components=%d kid=%s value_len=%d", len(bom.Components), bom.Signature.KeyID, len(bom.Signature.Value))
}
