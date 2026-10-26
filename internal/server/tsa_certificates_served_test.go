// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tsa"
)

// A145 on the assembled control plane: the TSA certificate minted at boot is in
// the CA ledger, so the CA's OCSP responder answers for it; rotating with a
// reason moves the TSA onto a fresh signer-held key and certificate, persists
// it, and revokes the outgoing certificate on the published CRL; and the audit
// verifier then refuses the timestamps signed under the compromised
// certificate while accepting those signed after the rotation.
func TestServedTSACertificateRotationAndRevocation(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tsa.crt")
	h := newOperatingServedHarness(t, config.Protocols{
		TSA:         config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		TSACertFile: certFile,
	})
	ctx := context.Background()
	block, _ := pem.Decode(h.caPEM)
	if block == nil {
		t.Fatal("served CA PEM")
	}
	caDER := block.Bytes
	reader := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"certs:read"})
	admin := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"issuers:write", "certs:read"})

	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/protocols/tsa/certificates", reader, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d: %s", code, body)
	}
	var list api.TSACertificateList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].State != "active" || list.CRL != "/crl/"+servedTestTenant+".crl" {
		t.Fatalf("boot certificates = %+v", list)
	}
	firstSerial := list.Items[0].Serial
	evidence, err := h.srv.TSAStatusEvidence(ctx, [][]byte{h.srv.protocols.tsa.Certificate()})
	if err != nil || len(evidence) != 1 {
		t.Fatalf("status evidence = %+v, %v", evidence, err)
	}
	if status, err := crypto.ParseOCSPResponse(evidence[0].OCSP, caDER); err != nil || status.Status != crypto.OCSPGood || status.Serial != firstSerial {
		t.Fatalf("the CA's OCSP answer for the boot TSA certificate = %+v, %v", status, err)
	}
	before, err := h.srv.protocols.tsa.Timestamp(ctx, crypto.SHA256Sum([]byte("before rotation")))
	if err != nil {
		t.Fatal(err)
	}

	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/rotate", reader, "rotate-denied", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("rotation without issuers:write = %d: %s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/rotate", admin, "rotate-bad", map[string]any{"revoke_previous_reason": "lostIt"}); code != http.StatusBadRequest {
		t.Fatalf("rotation with an unknown reason = %d: %s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/rotate", admin, "rotate-1", map[string]any{"revoke_previous_reason": "keyCompromise"})
	if code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", code, body)
	}
	var rotation api.TSARotation
	if err := json.Unmarshal(body, &rotation); err != nil {
		t.Fatal(err)
	}
	if rotation.Current.State != "active" || rotation.Previous.Serial != firstSerial || rotation.Previous.State != "revoked" || rotation.Previous.Reason != "keyCompromise" {
		t.Fatalf("rotation = %+v", rotation)
	}
	persisted, err := os.ReadFile(certFile) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil || !bytes.Equal(persisted, crypto.EncodeCertificatePEM(h.srv.protocols.tsa.Certificate())) {
		t.Fatalf("the rotated certificate was not persisted: %v", err)
	}
	after, err := h.srv.protocols.tsa.Timestamp(ctx, crypto.SHA256Sum([]byte("after rotation")))
	if err != nil || bytes.Equal(after.TSACertDER, before.TSACertDER) {
		t.Fatalf("a timestamp after rotation = %v", err)
	}
	if err := tsa.Verify(after, crypto.SHA256Sum([]byte("after rotation")), caDER); err != nil {
		t.Fatalf("the rotated TSA's timestamp does not verify: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/crl/"+servedTestTenant+".crl", nil)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, _ := readAllClose(resp)
	crl, err := crypto.ParseCRL(crlDER, caDER)
	if err != nil || !slices.Contains(crl.RevokedSerials, firstSerial) {
		t.Fatalf("the published CRL does not list the revoked TSA certificate: %v (%v)", crl.RevokedSerials, err)
	}

	evidence, err = h.srv.TSAStatusEvidence(ctx, [][]byte{before.TSACertDER, after.TSACertDER})
	if err != nil || len(evidence) != 2 {
		t.Fatalf("status evidence for both certificates = %+v, %v", evidence, err)
	}
	validation := &auditanchor.Validation{}
	for _, e := range evidence {
		validation.TSAStatus = append(validation.TSAStatus, auditanchor.TSAStatusEvidence{Serial: e.Serial, OCSP: e.OCSP})
	}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{before, after}, validation, caDER, auditanchor.TSARevocationPolicy{Require: true}); err == nil || !strings.Contains(err.Error(), "keyCompromise") {
		t.Fatalf("a timestamp under the compromised certificate = %v", err)
	}
	if result, err := auditanchor.VerifyTSARevocation([]tsa.Token{after}, validation, caDER, auditanchor.TSARevocationPolicy{Require: true, CRLDER: crlDER}); err != nil || result[0].Status != "good" {
		t.Fatalf("a timestamp under the new certificate = %+v, %v", result, err)
	}

	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/"+rotation.Current.Serial+"/revoke", admin, "revoke-active", map[string]any{"reason": "superseded"}); code != http.StatusBadRequest {
		t.Fatalf("revoking the active certificate = %d: %s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/abc123/revoke", admin, "revoke-unknown", map[string]any{"reason": "superseded"}); code != http.StatusNotFound {
		t.Fatalf("revoking an unknown certificate = %d: %s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/protocols/tsa/certificates/"+firstSerial+"/revoke", admin, "revoke-again", map[string]any{"reason": "superseded"})
	var again api.TSACertificate
	if code != http.StatusOK || json.Unmarshal(body, &again) != nil || again.Reason != "keyCompromise" {
		t.Fatalf("revoking an already revoked certificate keeps its first reason = %d: %s", code, body)
	}

	other := seedAPITokenWithScopes(t, h.store, "22222222-2222-2222-2222-222222222222", []string{"certs:read"})
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/protocols/tsa/certificates", other, "", nil); code != http.StatusNotFound && code != http.StatusForbidden {
		t.Fatalf("another tenant's view of the TSA = %d", code)
	}
}
