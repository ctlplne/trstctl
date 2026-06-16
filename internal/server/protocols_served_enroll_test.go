package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

// TestServedESTEndToEnd is the EXC-WIRE-02 / INTEROP-008 acceptance proof for EST: the
// SERVED EST endpoint (RFC 7030, mounted on the binary's handler at /.well-known/est/)
// authenticates a Bearer API token, accepts a base64 PKCS#10 simpleenroll, mints the
// leaf through the out-of-process signer (AN-4), and returns a certs-only PKCS#7 the
// device parses. The leaf verifies against the served CA and a certificate.recorded
// event exists (AN-2). It MUST fail pre-wiring (no /.well-known/est/ route) and PASS
// after.
func TestServedESTEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "est") {
		t.Fatal("EST is not reported as served — wire-in failed")
	}
	token := seedAPIToken(t, h.store, servedTestTenant)
	csrDER := newDeviceCSR(t, "device-est-1")

	// EST simpleenroll: base64 PKCS#10 body, Bearer-token authenticated (the served
	// auth gate).
	body := base64.StdEncoding.EncodeToString(csrDER)
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("EST simpleenroll: %v", err)
	}
	p7b64, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("EST simpleenroll status %d: %s", resp.StatusCode, p7b64)
	}
	p7, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(p7b64)))
	if err != nil {
		t.Fatalf("EST response is not base64 PKCS#7: %v", err)
	}
	certs, err := crypto.CertsFromPKCS7(p7)
	if err != nil || len(certs) == 0 {
		t.Fatalf("EST response carries no certificate: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(certs[0], caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("EST-issued cert does not verify against the served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event — the served EST mint was not event-sourced (AN-2)")
	}

	// Negative: an EST enroll with NO token is rejected by the served auth gate.
	noauth, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(body)))
	noauth.Header.Set("Content-Type", "application/pkcs10")
	nresp, err := h.ts.Client().Do(noauth)
	if err != nil {
		t.Fatalf("EST no-auth enroll: %v", err)
	}
	_ = nresp.Body.Close()
	if nresp.StatusCode != http.StatusUnauthorized {
		t.Errorf("EST enroll without a token returned %d, want 401 (auth gate missing)", nresp.StatusCode)
	}
}

// TestServedSCEPEndToEnd is the EXC-WIRE-02 acceptance proof for SCEP: the SERVED SCEP
// endpoint (RFC 8894 at /scep) decrypts a CMS-enveloped PKCSReq, mints through the
// signer, and returns a CertRep the client decrypts to its certificate. It MUST fail
// pre-wiring (no /scep route) and PASS after.
func TestServedSCEPEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		SCEP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "scep") {
		t.Fatal("SCEP is not reported as served — wire-in failed")
	}

	// The client needs the SERVER's RA cert (from GetCACert) to envelope its request.
	// With an RA + CA chain the server returns a certs-only PKCS#7; the client extracts
	// the RSA RA cert (the CMS recipient) from it — exactly what a stock SCEP client
	// does. (A single-cert response would be raw DER.)
	caResp, err := h.ts.Client().Get(h.ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	caBody, _ := readAllClose(caResp)
	if len(caBody) == 0 {
		t.Fatal("SCEP GetCACert returned no cert")
	}
	raCertDER := scepRARecipient(t, caBody)

	clientCertDER, clientKeyPKCS8, csrDER := newSCEPClient(t, "device-scep-1")
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCertDER, clientKeyPKCS8, raCertDER, "served-scep-txn-1")
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("SCEP PKIOperation: %v", err)
	}
	replyDER, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SCEP PKIOperation status %d: %s", resp.StatusCode, replyDER)
	}
	issued, err := crypto.ParseSCEPResponse(replyDER, clientCertDER, clientKeyPKCS8)
	if err != nil {
		t.Fatalf("parse SCEP CertRep: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issued, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("SCEP-issued cert does not verify against the served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event — the served SCEP mint was not event-sourced (AN-2)")
	}
}

// TestServedCMPEndToEnd is the EXC-WIRE-02 acceptance proof for CMP: the SERVED CMP
// endpoint (RFC 4210/6712 at /cmp) accepts a p10cr PKIMessage, mints through the
// signer, and returns a protected response carrying the leaf. It MUST fail pre-wiring
// (no /cmp route) and PASS after.
func TestServedCMPEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		CMP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "cmp") {
		t.Fatal("CMP is not reported as served — wire-in failed")
	}

	clientCertDER, clientKeyPKCS8, csrDER := newSCEPClient(t, "device-cmp-1")
	reqDER, err := crypto.BuildCMPRequest(csrDER, clientCertDER, clientKeyPKCS8, []byte("served-cmp-txn"), []byte("nonce-1234567890"))
	if err != nil {
		t.Fatalf("build CMP request: %v", err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("CMP PKIOperation: %v", err)
	}
	replyDER, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CMP status %d: %s", resp.StatusCode, replyDER)
	}
	issued, err := crypto.ParseCMPResponse(replyDER)
	if err != nil {
		t.Fatalf("parse CMP response: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issued, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("CMP-issued cert does not verify against the served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event — the served CMP mint was not event-sourced (AN-2)")
	}
}

// seedAPIToken creates a tenant-scoped API token in the store and returns its raw
// secret (for the Authorization: Bearer header the served EST auth gate validates).
func seedAPIToken(t *testing.T, st *store.Store, tenant string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenant, TokenHash: hash, Subject: "est-device", Scopes: []string{"certs:request"},
	}); err != nil {
		t.Fatalf("seed api token: %v", err)
	}
	return raw
}

// newDeviceCSR builds a PKCS#10 CSR for an ECDSA device key through the crypto
// boundary (AN-3 forbids stdlib crypto even in tests).
func newDeviceCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn}, key)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}
	return der
}

// scepRARecipient extracts the RSA RA cert (the CMS recipient) from a SCEP GetCACert
// response. A multi-cert response is a certs-only PKCS#7 (RA + CA); the RSA cert is
// the recipient. A single-cert response is raw DER. Cert inspection routes through the
// crypto boundary (AN-3) via certinfo.Inspect.
func scepRARecipient(t *testing.T, body []byte) []byte {
	t.Helper()
	isRSA := func(der []byte) bool {
		info, err := certinfo.Inspect(der)
		return err == nil && info.KeyAlgorithm == "RSA"
	}
	// Try PKCS#7 first (the RA + CA chain case).
	if certs, err := crypto.CertsFromPKCS7(body); err == nil && len(certs) > 0 {
		for _, der := range certs {
			if isRSA(der) {
				return der
			}
		}
		return certs[0]
	}
	// Single cert: raw DER.
	if isRSA(body) {
		return body
	}
	t.Fatal("SCEP GetCACert response has no RSA RA cert")
	return nil
}

// newSCEPClient builds an RSA self-signed client cert + key (PKCS#8) + CSR — the SCEP/
// CMP device side (these protocols require an RSA transport key pair for CMS).
func newSCEPClient(t *testing.T, cn string) (certDER, keyPKCS8, csrDER []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	certDER, err = crypto.SelfSignedCACert(signer, cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err = crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyPKCS8, csrDER
}
