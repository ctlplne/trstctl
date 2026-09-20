// SPDX-License-Identifier: BUSL-1.1

package scep_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// caFixture is an RSA CA used as both the issuer and the SCEP RA (CMS) key.
type caFixture struct {
	certDER  []byte
	keyPKCS8 []byte
	signer   *crypto.LockedSigner
}

func newRSACA(t *testing.T) caFixture {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, "SCEP Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return caFixture{certDER: der, keyPKCS8: key, signer: signer}
}

type realEnroller struct{ ca caFixture }

func (e realEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

// scepClient builds a self-signed cert + CSR for a fresh RSA key (the device side).
func newClient(t *testing.T) (certDER, keyPKCS8, csrDER []byte) {
	t.Helper()
	return newClientWithTemplate(t, crypto.CertificateRequestTemplate{CommonName: "device-1"})
}

func newClientWithTemplate(t *testing.T, tmpl crypto.CertificateRequestTemplate) (certDER, keyPKCS8, csrDER []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	if tmpl.CommonName == "" {
		tmpl.CommonName = "device-1"
	}
	certDER, err = crypto.SelfSignedCACert(signer, tmpl.CommonName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err = crypto.CreateCertificateRequest(tmpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyPKCS8, csrDER
}

// TestSCEPEnrollRoundTrip drives a full RFC 8894 PKIOperation: the client envelopes and
// signs a PKCSReq, the server decrypts it, issues under the profile, and returns a CertRep
// the client decrypts back to its certificate.
func TestSCEPEnrollRoundTrip(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-1")
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PKIOperation status %d", resp.StatusCode)
	}
	replyDER, _ := io.ReadAll(resp.Body)

	issued, err := crypto.ParseSCEPResponse(replyDER, clientCert, clientKey)
	if err != nil {
		t.Fatalf("parse SCEP CertRep: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issued, ca.certDER); err != nil {
		t.Errorf("issued certificate is not signed by the CA: %v", err)
	}
}

// AUD-50: a device trace is evidence, not a reconstruction from whichever
// mutable inventory row happens to have the same serial. The served SCEP path
// therefore has to emit the join keys and the separate request/issuance facts
// itself. This is deliberately a real PKIOperation: a helper appending a fixture
// would prove the consumer while leaving the production writer unreachable.
func TestSCEPEmitsCorrelatableImmutableAttemptEvidence(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		Log: log,
	})
	clientCert, clientKey, csrDER := newClientWithTemplate(t, crypto.CertificateRequestTemplate{CommonName: "SERIAL-007"})
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-evidence-7")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(reqDER))
	srv.ServeHTTP(rec, req.WithContext(scep.WithTenant(req.Context(), "tenant-a")))
	if rec.Code != http.StatusOK {
		t.Fatalf("PKIOperation status = %d, want 200", rec.Code)
	}

	seen := map[string]scep.AttemptEvidence{}
	if err := log.Replay(t.Context(), 0, func(ev events.Event) error {
		if ev.TenantID != "tenant-a" || (ev.Type != scep.EventRequestObserved && ev.Type != scep.EventIssuanceObserved) {
			return nil
		}
		var evidence scep.AttemptEvidence
		if err := json.Unmarshal(ev.Data, &evidence); err != nil {
			return err
		}
		seen[ev.Type] = evidence
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request, ok := seen[scep.EventRequestObserved]
	if !ok || request.TransactionID != "txn-evidence-7" || request.DeviceSerial != "SERIAL-007" || request.Outcome != "ok" {
		t.Fatalf("request evidence = %+v, present=%v; want exact transaction/device request fact", request, ok)
	}
	issued, ok := seen[scep.EventIssuanceObserved]
	if !ok || issued.TransactionID != request.TransactionID || issued.DeviceSerial != request.DeviceSerial ||
		issued.Outcome != "ok" || issued.CertificateSerial == "" || issued.CertificateFingerprint == "" || issued.CertificateNotAfter.IsZero() {
		t.Fatalf("issuance evidence = %+v, present=%v; want minted-certificate identity and expiry", issued, ok)
	}
}

func TestSCEPChallengeFailureRetainsPreIssuanceAttemptEvidence(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device", Log: log,
		ChallengeValidator: func(context.Context, scep.ChallengeRequest) error { return errors.New("challenge signature rejected") },
	})
	clientCert, clientKey, csrDER := newClientWithTemplate(t, crypto.CertificateRequestTemplate{CommonName: "SERIAL-FAILED"})
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-failed-before-issue")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(reqDER))
	srv.ServeHTTP(rec, req.WithContext(scep.WithTenant(req.Context(), "tenant-a")))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PKIOperation status = %d, want 403", rec.Code)
	}

	var request, issued scep.AttemptEvidence
	if err := log.Replay(t.Context(), 0, func(ev events.Event) error {
		if ev.TenantID != "tenant-a" {
			return nil
		}
		switch ev.Type {
		case scep.EventRequestObserved:
			return json.Unmarshal(ev.Data, &request)
		case scep.EventIssuanceObserved:
			return json.Unmarshal(ev.Data, &issued)
		default:
			return nil
		}
	}); err != nil {
		t.Fatal(err)
	}
	if request.TransactionID == "" || request.DeviceSerial != "SERIAL-FAILED" {
		t.Fatalf("request evidence lost before challenge failure: %+v", request)
	}
	if issued.TransactionID != request.TransactionID || issued.Outcome != "failed" || !strings.Contains(issued.Detail, "challenge") {
		t.Fatalf("pre-issuance failure evidence = %+v; want failed issuance stage with remediation detail", issued)
	}
}

func TestGetCACertReturnsCA(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{CAChainDER: [][]byte{ca.certDER}, RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	der, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(der, ca.certDER) {
		t.Fatalf("GetCACert did not return the CA cert (status %d, %d bytes)", resp.StatusCode, len(der))
	}
}

func TestGetCACapsAdvertisesPOST(t *testing.T) {
	srv := scep.New(scep.Config{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/scep?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	caps, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(caps, []byte("POSTPKIOperation")) || !bytes.Contains(caps, []byte("SHA-256")) {
		t.Errorf("GetCACaps missing expected capabilities: %q", caps)
	}
}

// TestSCEPChallengeRejected: with an MDM challenge validator that rejects, enrollment
// fails closed (403) before any issuance — the Intune/JAMF gate (S8.5).
func TestSCEPChallengeRejected(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(context.Context, scep.ChallengeRequest) error { return errors.New("challenge required") },
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	clientCert, clientKey, csrDER := newClient(t)
	reqDER, _ := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-c1")
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rejected-challenge enroll status %d, want 403", resp.StatusCode)
	}
}

// TestSCEPChallengeAccepted: with a validator that accepts, enrollment proceeds.
func TestSCEPChallengeAccepted(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(context.Context, scep.ChallengeRequest) error { return nil },
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	clientCert, clientKey, csrDER := newClient(t)
	reqDER, _ := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-c2")
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accepted-challenge enroll status %d, want 200", resp.StatusCode)
	}
}

func TestSCEPChallengeValidatorGetsTenantCSRAndChallenge(t *testing.T) {
	ca := newRSACA(t)
	var seen scep.ChallengeRequest
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(_ context.Context, req scep.ChallengeRequest) error {
			seen = req
			if req.Challenge == "" {
				return errors.New("challenge required")
			}
			return nil
		},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.ServeHTTP(w, r.WithContext(scep.WithTenant(r.Context(), "tenant-a")))
	}))
	defer ts.Close()

	clientCert, clientKey, csrDER := newClientWithTemplate(t, crypto.CertificateRequestTemplate{
		CommonName:        "device-1",
		ChallengePassword: []byte("signed-intune-jws"),
	})
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-c3")
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accepted-challenge enroll status %d, want 200", resp.StatusCode)
	}
	if seen.TenantID != "tenant-a" || seen.TransactionID != "txn-c3" || seen.Challenge != "signed-intune-jws" || !bytes.Equal(seen.CSRDER, csrDER) {
		t.Fatalf("validator saw %+v; want tenant, transaction, challenge, and CSR DER", seen)
	}
}

func TestMalformedPKIOperationFailsClosed(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader([]byte("not a pkiMessage")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed PKIOperation status %d, want 400", resp.StatusCode)
	}
}

func TestPKIOperationRejectsOverLimitBody(t *testing.T) {
	srv := scep.New(scep.Config{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<18)+1)))
	req.Header.Set("Content-Type", "application/x-pki-message")
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit PKIOperation status %d, want 413", rec.Code)
	}
}

// TestSCEPGETMessageTooLarge proves FUZZ-005: the base64 GET `message` form is
// capped like the POST body. Before the fix the GET path base64-decoded an
// arbitrarily large `message` directly (no cap), so a hostile client could force
// an unbounded decode-buffer allocation that the POST path already rejects. An
// over-cap encoded value is now rejected with 413 BEFORE base64 decode runs.
func TestSCEPGETMessageTooLarge(t *testing.T) {
	srv := scep.New(scep.Config{})

	// base64.StdEncoding.EncodedLen(256 KiB) is the largest legitimate encoded
	// length; one full base64 quantum (4 chars) past it must be rejected. 'A' is a
	// valid base64 symbol, so the value would decode fine if it were not capped —
	// this proves the cap, not a base64 parse error.
	const maxPKIBody = 1 << 18
	over := base64.StdEncoding.EncodedLen(maxPKIBody) + 4
	msg := strings.Repeat("A", over)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scep?operation=PKIOperation&message="+msg, nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap GET message status %d, want 413", rec.Code)
	}
}
