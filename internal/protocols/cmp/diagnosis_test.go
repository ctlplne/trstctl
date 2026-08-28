// SPDX-License-Identifier: MPL-2.0

package cmp_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

// CMP binding failure is the most important actionable refusal: an anchored
// device tried to request somebody else's name. The diagnostic must distinguish
// that authorization problem from a rejected client credential and retain only
// bounded references—not the PKIMessage, certificate, key, or CSR.
func TestCMPIdentityMismatchEmitsTypedSecretFreeDiagnostic(t *testing.T) {
	ca := newRSACA(t)
	var got []enrollmentdiag.Diagnosis
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName: "device", ClientTrustAnchorsDER: [][]byte{ca.certDER},
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) {
			got = append(got, diagnosis)
		},
	})
	clientCert, clientKey := anchoredIdentity(t, ca, "device-alpha")
	requestBody := buildRequest(t, clientCert, clientKey, csrFor(t, "device-beta"))
	req := httptest.NewRequest(http.MethodPost, "https://cmp.example.test:9443/cmp",
		bytes.NewReader(requestBody))
	req.Host = "cmp.example.test:9443"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("CMP identity mismatch status = %d, want 403", rec.Code)
	}
	if len(got) != 1 {
		t.Fatalf("CMP identity mismatch emitted %d diagnostics, want 1", len(got))
	}
	diagnosis := got[0]
	if diagnosis.Protocol != enrollmentdiag.ProtocolCMP || diagnosis.Step != enrollmentdiag.StepAuthorize ||
		diagnosis.Cause != enrollmentdiag.CauseNameNotPermitted {
		t.Fatalf("diagnosis = %+v, want CMP authorize/name_not_permitted", diagnosis)
	}
	if !strings.HasPrefix(diagnosis.OperationRef, "cmp-message:sha256:") ||
		diagnosis.OperationRef == "cmp-message:sha256:" || diagnosis.EndpointRef != "cmp.example.test:9443" {
		t.Fatalf("diagnostic references = %+v, want exact operation and endpoint", diagnosis)
	}
	if diagnosis.IdentityRef != "" {
		t.Fatalf("pre-parse identity reference = %q, want empty rather than a guessed or raw identity", diagnosis.IdentityRef)
	}
}

func TestCMPPreParseFailuresUseStableDistinctMessageReferences(t *testing.T) {
	ca := newRSACA(t)
	var got []enrollmentdiag.Diagnosis
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName: "device", ClientTrustAnchorsDER: [][]byte{ca.certDER},
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) {
			got = append(got, diagnosis)
		},
	})
	selfSignedCert, selfSignedKey, csrDER := newClient(t)
	bodyA := buildRequest(t, selfSignedCert, selfSignedKey, csrDER)
	bodyB := buildRequest(t, selfSignedCert, selfSignedKey, csrFor(t, "another-device"))

	for _, body := range [][]byte{bodyA, bodyA, bodyB} {
		req := httptest.NewRequest(http.MethodPost, "https://cmp.example.test/cmp", bytes.NewReader(body))
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(got) != 3 {
		t.Fatalf("CMP controls emitted %d diagnostics, want 3", len(got))
	}
	if got[0].OperationRef != got[1].OperationRef {
		t.Fatalf("same message refs differ: %q != %q", got[0].OperationRef, got[1].OperationRef)
	}
	if got[0].OperationRef == got[2].OperationRef {
		t.Fatalf("distinct message refs collided: %q", got[0].OperationRef)
	}
	for _, diagnosis := range got {
		if !strings.HasPrefix(diagnosis.OperationRef, "cmp-message:sha256:") || len(diagnosis.OperationRef) != len("cmp-message:sha256:")+64 {
			t.Fatalf("operation ref = %q, want bounded SHA-256 reference", diagnosis.OperationRef)
		}
	}
}

func TestCMPUntrustedProtectionIdentityNamesCredentialRepair(t *testing.T) {
	ca := newRSACA(t)
	var got enrollmentdiag.Diagnosis
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName: "device", ClientTrustAnchorsDER: [][]byte{ca.certDER},
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) { got = diagnosis },
	})
	selfSignedCert, selfSignedKey, csrDER := newClient(t)
	req := httptest.NewRequest(http.MethodPost, "https://cmp.example.test/cmp",
		bytes.NewReader(buildRequest(t, selfSignedCert, selfSignedKey, csrDER)))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("untrusted protection identity enrolled successfully")
	}
	if got.Protocol != enrollmentdiag.ProtocolCMP || got.Cause != enrollmentdiag.CauseClientCertRejected || !got.Actionable() {
		t.Fatalf("untrusted identity diagnosis = %+v, want actionable CMP client-cert rejection", got)
	}
}

func TestCMPFullWorkerPoolEmitsRetryableCapacityDiagnosis(t *testing.T) {
	ca := newRSACA(t)
	pool := bulkhead.New(bulkhead.Config{Name: "cmp-diagnosis", Workers: 1, Queue: 0})
	release := make(chan struct{})
	started := make(chan struct{})
	if err := pool.Submit(func() { close(started); <-release }); err != nil {
		t.Fatal(err)
	}
	<-started
	t.Cleanup(func() { close(release); pool.Close() })

	var got enrollmentdiag.Diagnosis
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName: "device", ClientTrustAnchorsDER: [][]byte{ca.certDER}, Pool: pool,
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) { got = diagnosis },
	})
	clientCert, clientKey := anchoredIdentity(t, ca, "device-alpha")
	req := httptest.NewRequest(http.MethodPost, "https://cmp.example.test/cmp",
		bytes.NewReader(buildRequest(t, clientCert, clientKey, csrFor(t, "device-alpha"))))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated CMP status = %d, want 503", rec.Code)
	}
	if got.Protocol != enrollmentdiag.ProtocolCMP || got.Cause != enrollmentdiag.CauseCapacityFull || !got.Actionable() {
		t.Fatalf("saturated CMP diagnosis = %+v, want actionable bounded-capacity repair", got)
	}
	if got.OperationRef == "" || got.IdentityRef != "protection-cn:device-alpha" {
		t.Fatalf("saturated CMP references = %+v, want transaction and authenticated identity", got)
	}
}
