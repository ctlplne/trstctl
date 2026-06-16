package projections_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/server"
)

// TestServedOCSPAndCRLReflectRevocation is the EXC-REVOKE-01 acceptance test: it
// stands up the assembled control plane with a real out-of-process signer, issues
// a real certificate via the served transition path, and proves the SERVED
// revocation infrastructure works end to end:
//
//   - the OCSP responder returns "good" for the issued serial BEFORE revocation,
//   - after a served revoke it returns "revoked" (with the revocation time/reason),
//   - the generated CRL lists the serial within its freshness window, and
//   - both the OCSP response and the CRL VERIFY against the issuing CA — proving
//     they were signed correctly by the CA key, which lives in the signer (AN-4).
//
// Before EXC-REVOKE-01 there was no served OCSP responder, no served CRL, and no
// freshness scheduler (revocation.New was never called from the binary), so this
// test could not be written against the served path at all.
func TestServedOCSPAndCRLReflectRevocation(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// The served revocation surface must be active (an issuing CA is provisioned).
	if !asm.RevocationServed() {
		t.Fatal("revocation is not served by the assembled control plane (EXC-REVOKE-01 not wired)")
	}
	// The CA key must live in the out-of-process signer, so OCSP/CRL signing crosses
	// the boundary rather than materializing the CA key here (AN-4).
	if !asm.OutOfProcessSigning() {
		t.Fatal("assembled CA signing is not out of process (AN-4)")
	}

	caDER := decodePEM(t, asm.CACertPEM())

	// certs:issue is required to drive a privileged issue/revoke transition (the
	// RA-separation gate, EXC-WIRE-03); the requester scope alone cannot self-issue.
	token := mintToken(t, st, "owners:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"ocsp.svc","owner_id":"`+ownerID+`"}`)

	// Issue via the served path and drain so the real ca.issue handler mints a leaf
	// (through the signer) and records its serial in ca_issued_certs.
	transition(t, ts, token, identityID, "issued")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (issue): %v", err)
	}
	serial, _ := list(t, ts, token, "/api/v1/certificates")[0]["serial"].(string)
	if serial == "" {
		t.Fatal("issued certificate has no serial; it was not really minted")
	}

	reqDER, err := crypto.BuildOCSPRequestForSerial(caDER, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}

	// (a-good) Before revocation the served OCSP responder answers "good", and the
	// response VERIFIES against the issuing CA (so it was signed by the signer-held
	// CA key, not a stray key).
	goodDER, err := asm.OCSPResponse(context.Background(), tenantA, reqDER)
	if err != nil {
		t.Fatalf("OCSPResponse (pre-revoke): %v", err)
	}
	good, err := crypto.ParseOCSPResponse(goodDER, caDER)
	if err != nil {
		t.Fatalf("served OCSP response does not verify against the CA (pre-revoke): %v", err)
	}
	if good.Status != crypto.OCSPGood {
		t.Fatalf("OCSP status before revoke = %q, want %q", good.Status, crypto.OCSPGood)
	}
	if good.Serial != serial {
		t.Fatalf("OCSP response serial = %q, want %q", good.Serial, serial)
	}
	if !good.NextUpdate.After(time.Now()) {
		t.Fatalf("OCSP nextUpdate = %v, want future (cacheable)", good.NextUpdate)
	}

	// Revoke via the served path and drain so the served revocation handler records
	// the serial revoked in ca_issued_certs.
	transition(t, ts, token, identityID, "revoked")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (revoke): %v", err)
	}

	// (a-revoked) After revocation the served OCSP responder answers "revoked", and
	// the response still verifies against the CA.
	revDER, err := asm.OCSPResponse(context.Background(), tenantA, reqDER)
	if err != nil {
		t.Fatalf("OCSPResponse (post-revoke): %v", err)
	}
	rev, err := crypto.ParseOCSPResponse(revDER, caDER)
	if err != nil {
		t.Fatalf("served OCSP response does not verify against the CA (post-revoke): %v", err)
	}
	if rev.Status != crypto.OCSPRevoked {
		t.Fatalf("OCSP status after revoke = %q, want %q "+
			"(a revoked cert must report revoked via the served responder)", rev.Status, crypto.OCSPRevoked)
	}
	if rev.RevokedAt.IsZero() {
		t.Fatal("revoked OCSP response carries no revocation time")
	}

	// (b) The generated CRL lists the serial, within its freshness window, and
	// VERIFIES against the issuing CA.
	crlDER, err := asm.GenerateCRL(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	info, err := crypto.ParseCRL(crlDER, caDER)
	if err != nil {
		t.Fatalf("served CRL does not verify against the CA: %v", err)
	}
	if !info.NextUpdate.After(time.Now()) {
		t.Fatalf("CRL nextUpdate = %v, want future (within the freshness window)", info.NextUpdate)
	}
	if !info.ThisUpdate.Before(info.NextUpdate) {
		t.Fatalf("CRL thisUpdate %v not before nextUpdate %v", info.ThisUpdate, info.NextUpdate)
	}
	found := false
	for _, s := range info.RevokedSerials {
		if s == serial {
			found = true
		}
	}
	if !found {
		t.Fatalf("CRL revoked serials = %v, want to contain the revoked serial %s", info.RevokedSerials, serial)
	}
}

// TestServedOCSPAndCRLOverHTTP proves the OCSP responder and CRL endpoint are
// actually MOUNTED on the served mux of the running binary (the "wire it in"
// check, RED-007): it drives them over real HTTP, not just via the exported
// helpers. It issues and revokes via the served path, then GETs the CRL from
// /crl/{tenant} and POSTs an OCSP request to /ocsp/{tenant}, asserting both
// reflect the revocation and verify against the CA.
func TestServedOCSPAndCRLOverHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	caDER := decodePEM(t, asm.CACertPEM())

	// certs:issue is required to drive a privileged issue/revoke transition (the
	// RA-separation gate, EXC-WIRE-03); the requester scope alone cannot self-issue.
	token := mintToken(t, st, "owners:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"http-ocsp.svc","owner_id":"`+ownerID+`"}`)

	transition(t, ts, token, identityID, "issued")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (issue): %v", err)
	}
	serial, _ := list(t, ts, token, "/api/v1/certificates")[0]["serial"].(string)
	transition(t, ts, token, identityID, "revoked")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (revoke): %v", err)
	}

	// GET the CRL from the served CDP route and assert it lists the serial.
	crlDER := httpGetBytes(t, ts, "/crl/"+tenantA, "application/pkix-crl")
	info, err := crypto.ParseCRL(crlDER, caDER)
	if err != nil {
		t.Fatalf("CRL served over HTTP does not verify against the CA: %v", err)
	}
	listed := false
	for _, s := range info.RevokedSerials {
		if s == serial {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("CRL from /crl/%s does not list the revoked serial %s (serials: %v)", tenantA, serial, info.RevokedSerials)
	}

	// POST an OCSP request to the served responder route and assert "revoked".
	reqDER, err := crypto.BuildOCSPRequestForSerial(caDER, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	respDER := httpPostOCSP(t, ts, "/ocsp/"+tenantA, reqDER)
	status, err := crypto.ParseOCSPResponse(respDER, caDER)
	if err != nil {
		t.Fatalf("OCSP response served over HTTP does not verify against the CA: %v", err)
	}
	if status.Status != crypto.OCSPRevoked {
		t.Fatalf("OCSP status from /ocsp/%s = %q, want %q", tenantA, status.Status, crypto.OCSPRevoked)
	}
}

func httpGetBytes(t *testing.T, ts *httptest.Server, path, wantContentType string) []byte {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); ct != wantContentType {
		t.Errorf("GET %s Content-Type = %q, want %q", path, ct, wantContentType)
	}
	return b
}

func httpPostOCSP(t *testing.T, ts *httptest.Server, path string, reqDER []byte) []byte {
	t.Helper()
	httpReq, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := ts.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/ocsp-response" {
		t.Errorf("POST %s Content-Type = %q, want application/ocsp-response", path, ct)
	}
	return b
}
