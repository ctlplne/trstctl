// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
)

func TestHostRenewalRetainsExplicitAlgorithmAndRefusesInvalidIntent(t *testing.T) {
	for _, algorithm := range []string{string(crypto.ECDSAP256), "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		raw, err := json.Marshal(map[string]any{"subject_key_algorithm": algorithm, "owner_note": "unrelated"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := hostRenewalSubjectAlgorithm(raw)
		if err != nil || got != algorithm {
			t.Fatalf("choice changed: %q %v", got, err)
		}
	}
	for _, raw := range []string{`{"subject_key_algorithm":null}`, `{"subject_key_algorithm":42}`, `{"subject_key_algorithm":""}`, `{"subject_key_algorithm":"unsupported"}`, `{`} {
		if got, err := hostRenewalSubjectAlgorithm([]byte(raw)); err == nil || got != "" {
			t.Fatalf("malformed intent accepted: %s", raw)
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"unrelated":"field"}`)} {
		if got, err := hostRenewalSubjectAlgorithm(raw); err != nil || got != "" {
			t.Fatalf("legacy choice changed: %q %v", got, err)
		}
	}
}

func TestHostCSRAlgorithmCannotWidenReviewedChoice(t *testing.T) {
	d := subjectAdmissionDispatcher()
	key, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := d.authorizeAgentSubjectAlgorithm(key.CSRDER, string(pqc.MLDSA65)); err != nil {
		t.Fatal(err)
	}
	for _, choice := range []string{string(pqc.MLDSA44), string(pqc.MLDSA87), string(crypto.ECDSAP256)} {
		if err := d.authorizeAgentSubjectAlgorithm(key.CSRDER, choice); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("algorithm substitution accepted: %q %v", choice, err)
		}
	}
	classical, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer classical.Destroy()
	if err := d.authorizeAgentSubjectAlgorithm(classical.CSRDER, string(pqc.MLDSA65)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("silent classical downgrade accepted: %v", err)
	}
}
