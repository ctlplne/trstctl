// SPDX-License-Identifier: MPL-2.0

package est_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/protocols/est"
)

type refusingEnroller struct{}

func (refusingEnroller) Enroll(context.Context, []byte, string, string, string) ([]byte, error) {
	return nil, errors.New("request was denied by the certificate template ACL")
}

// AUD-49: a production refusal is useful only when the stored diagnosis names
// the exact operation, requested identity, and endpoint an operator must fix.
// A package-level classifier test cannot prove that the live refusal boundary
// supplies those facts, so drive the actual EST handler.
func TestESTRefusalEmitsTypedDiagnosticWithExactEvidence(t *testing.T) {
	csr := deviceCSR(t)
	var got []enrollmentdiag.Diagnosis
	srv := est.New(est.Config{
		Enroller: refusingEnroller{}, Auth: allowAuth{}, ProfileName: "iot",
		FailureDiagnosis: func(_ context.Context, diagnosis enrollmentdiag.Diagnosis) {
			got = append(got, diagnosis)
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://est.example.test:8443/.well-known/est/simpleenroll", b64Body(csr))
	req.Host = "est.example.test:8443"
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("EST refusal status = %d, want 403", rec.Code)
	}
	if len(got) != 1 {
		t.Fatalf("EST refusal emitted %d diagnostics, want 1", len(got))
	}
	diagnosis := got[0]
	digest := crypto.SHA256Hex(csr)
	if diagnosis.Protocol != enrollmentdiag.ProtocolEST || diagnosis.Cause != enrollmentdiag.CauseTemplateACLDenied {
		t.Fatalf("diagnosis = %+v, want typed EST template refusal", diagnosis)
	}
	if diagnosis.OperationRef != "est-enroll:"+digest || diagnosis.IdentityRef != "dns:device-1.iot.test" {
		t.Fatalf("operation/identity refs = %q/%q, want exact idempotent request refs",
			diagnosis.OperationRef, diagnosis.IdentityRef)
	}
	if diagnosis.EndpointRef != "est.example.test:8443" || diagnosis.VerificationAddress != "" ||
		diagnosis.VerificationServerName != "" || diagnosis.VerificationKind != "" {
		t.Fatalf("endpoint evidence = %+v, want exact refused EST endpoint without a guessed deployment target", diagnosis)
	}
}
