// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
)

// A215: a recovery event carries only bytes that hash to the row's
// fingerprint; nothing is attached from a name or serial alone.
func TestRecoveredCertificateBytesMustHashToTheFingerprint(t *testing.T) {
	der := []byte("a215 certificate bytes")
	good := projections.CertificateDERRecovered{
		CertificateID: "6f6c3b0a-1d2e-4f50-8a21-a215a215a215", Fingerprint: crypto.SHA256Hex(der),
		Method: "endpoint", Evidence: "10.0.0.5:443", CertificateDER: der,
	}
	if err := projections.ValidateCertificateDERRecovered(good); err != nil {
		t.Fatalf("valid recovery refused: %v", err)
	}
	for name, mutate := range map[string]func(*projections.CertificateDERRecovered){
		"other bytes":      func(r *projections.CertificateDERRecovered) { r.CertificateDER = []byte("other") },
		"no bytes":         func(r *projections.CertificateDERRecovered) { r.CertificateDER = nil },
		"unknown method":   func(r *projections.CertificateDERRecovered) { r.Method = "guess" },
		"no evidence":      func(r *projections.CertificateDERRecovered) { r.Evidence = "" },
		"no inventory row": func(r *projections.CertificateDERRecovered) { r.CertificateID = "" },
	} {
		bad := good
		mutate(&bad)
		if err := projections.ValidateCertificateDERRecovered(bad); err == nil {
			t.Fatalf("%s: a recovery was accepted", name)
		}
	}
}
