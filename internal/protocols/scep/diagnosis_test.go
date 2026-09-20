// SPDX-License-Identifier: BUSL-1.1

package scep_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// AUD-49: this drives the real PKIOperation refusal boundary. The immutable
// diagnostic must carry the SCEP transaction, device, and refused endpoint; a
// generic "SCEP failed" row cannot be proved fixed later.
func TestSCEPRefusalEmitsTypedDiagnosticWithExactEvidence(t *testing.T) {
	ca := newRSACA(t)
	var got []enrollmentdiag.Diagnosis
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(context.Context, scep.ChallengeRequest) error {
			return errors.New("challenge signature rejected")
		},
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) {
			got = append(got, diagnosis)
		},
	})
	clientCert, clientKey, csrDER := newClientWithTemplate(t, crypto.CertificateRequestTemplate{CommonName: "SERIAL-DIAGNOSTIC"})
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-diagnostic")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://scep.example.test:9443/scep?operation=PKIOperation", bytes.NewReader(reqDER))
	req.Host = "scep.example.test:9443"
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SCEP refusal status = %d, want 403", rec.Code)
	}
	if len(got) != 1 {
		t.Fatalf("SCEP refusal emitted %d diagnostics, want 1", len(got))
	}
	diagnosis := got[0]
	if diagnosis.Protocol != enrollmentdiag.ProtocolSCEP || diagnosis.Cause != enrollmentdiag.CauseClientCertRejected {
		t.Fatalf("diagnosis = %+v, want typed SCEP challenge refusal", diagnosis)
	}
	if diagnosis.OperationRef != "scep:txn-diagnostic" || diagnosis.IdentityRef != "device:SERIAL-DIAGNOSTIC" {
		t.Fatalf("operation/identity refs = %q/%q, want exact transaction and device",
			diagnosis.OperationRef, diagnosis.IdentityRef)
	}
	if diagnosis.EndpointRef != "scep.example.test:9443" || diagnosis.VerificationAddress != "" ||
		diagnosis.VerificationServerName != "" || diagnosis.VerificationKind != "" {
		t.Fatalf("endpoint evidence = %+v, want exact refused SCEP endpoint without a guessed deployment target", diagnosis)
	}
}
