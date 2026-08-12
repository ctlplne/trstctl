// SPDX-License-Identifier: MPL-2.0

package revocationhealth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateObservedRejectsUnverifiedAuthorityAndContradictoryEvidence(t *testing.T) {
	next := time.Now().UTC().Add(time.Hour)
	target := Target{
		Key:                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Protocol:               ProtocolCRL,
		Endpoint:               "https://pki.example.test/root.crl",
		IssuerSubject:          "CN=Root CA",
		CertificateID:          "certificate-1",
		CertificateSubject:     "CN=service.example.test",
		CertificateFingerprint: "leaf-fingerprint",
		CertificateSerial:      "01",
	}
	observed := Observed{
		ProbeID: uuid.NewString(), Bucket: "2026-08-12T10:00:00Z", BatchIndex: 1, BatchCount: 1,
		AgentID: uuid.NewString(), AgentName: "relay-1",
		EvidenceDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Targets:        []Target{target},
		Findings: []Finding{{
			TargetKey: target.Key, Protocol: target.Protocol, Endpoint: target.Endpoint,
			Status: StatusFresh, DetailCode: "fresh", SignatureVerified: true, NextUpdate: &next,
		}},
	}
	if err := ValidateObserved(observed); err != nil {
		t.Fatalf("valid signed observation rejected: %v", err)
	}

	missingAuthority := observed
	missingAuthority.AgentID = ""
	if err := ValidateObserved(missingAuthority); err == nil {
		t.Fatal("observation without verified agent authority accepted")
	}

	contradictory := observed
	contradictory.Findings = append([]Finding(nil), observed.Findings...)
	contradictory.Findings[0].SignatureVerified = false
	if err := ValidateObserved(contradictory); err == nil {
		t.Fatal("fresh observation without a verified signature accepted")
	}
}
