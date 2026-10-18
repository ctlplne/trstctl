// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"strings"
	"testing"
	"time"
)

func TestLockedCertificateMustStillBeUnobservedAtReleaseClaim(t *testing.T) {
	expired := time.Now().UTC().Add(-time.Minute)
	review := Review{SourceEventID: "mint", Serial: "7a", CertificateSHA256: strings.Repeat("a", 64), NotAfter: expired}
	facts := lockedCertificateFacts{
		status: "active", keyOrigin: "requester", notAfter: &expired,
	}
	if err := facts.validate(review, time.Now().UTC()); err != nil {
		t.Fatalf("unchanged eligible locked row refused: %v", err)
	}
	// The immutable certificate source and DER digest are checked separately;
	// each
	// operational field must refuse a release if a projector changed it after
	// the effect-free preview but before the SQL first-writer claim.
	for name, change := range map[string]func(*lockedCertificateFacts){
		"revoked":  func(f *lockedCertificateFacts) { f.status = "revoked" },
		"custody":  func(f *lockedCertificateFacts) { f.keyOrigin = "signer" },
		"deployed": func(f *lockedCertificateFacts) { f.deploymentLocation = "web-01" },
		"observed": func(f *lockedCertificateFacts) { now := time.Now().UTC(); f.lastSeen = &now },
		"validity": func(f *lockedCertificateFacts) { future := time.Now().UTC().Add(time.Hour); f.notAfter = &future },
	} {
		t.Run(name, func(t *testing.T) {
			changed := facts
			change(&changed)
			if err := changed.validate(review, time.Now().UTC()); err == nil {
				t.Fatal("changed certificate state passed the pre-append locked-row check")
			}
		})
	}
}

func TestLockedDependentMustStillHaveNoTerminalAccounting(t *testing.T) {
	base := lockedDependencyFacts{registered: 17}
	if err := base.validate(17); err != nil {
		t.Fatalf("outstanding dependent refused: %v", err)
	}
	terminal := int64(18)
	for name, change := range map[string]func(*lockedDependencyFacts){
		"registered mint changed": func(f *lockedDependencyFacts) { f.registered = 19 },
		"completion":              func(f *lockedDependencyFacts) { f.accounted = &terminal },
		"prior release":           func(f *lockedDependencyFacts) { f.released = &terminal },
		"erasure designation":     func(f *lockedDependencyFacts) { f.erased = &terminal },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if err := changed.validate(17); err == nil {
				t.Fatal("terminal or rebound dependent passed the pre-append lock")
			}
		})
	}
}

func TestReviewPurposeBindsEveryPublicDispositionFact(t *testing.T) {
	base := Review{
		TenantID:      "11111111-1111-4111-8111-111111111111",
		KeyID:         "22222222-2222-4222-8222-222222222222",
		CertificateID: "33333333-3333-4333-8333-333333333333",
		SourceEventID: "mint-event", SourceSequence: 17, Serial: "7a",
		CertificateSHA256: strings.Repeat("a", 64),
		Reason:            "verified local retirement and accepted external-use risk", RiskAccepted: true,
		NotAfter: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
	purpose := base.Purpose()
	if purpose == "" || !strings.Contains(purpose, base.CertificateID) || !strings.Contains(purpose, base.Reason) {
		t.Fatalf("review purpose omits human-readable certificate and reason: %q", purpose)
	}
	mutations := map[string]func(*Review){
		"tenant":          func(r *Review) { r.TenantID = "other" },
		"key":             func(r *Review) { r.KeyID = "other" },
		"certificate":     func(r *Review) { r.CertificateID = "other" },
		"source":          func(r *Review) { r.SourceEventID = "other" },
		"source position": func(r *Review) { r.SourceSequence++ },
		"serial":          func(r *Review) { r.Serial = "other" },
		"public digest":   func(r *Review) { r.CertificateSHA256 = strings.Repeat("b", 64) },
		"reason":          func(r *Review) { r.Reason = "different risk decision" },
		"risk acceptance": func(r *Review) { r.RiskAccepted = false },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := changed.Purpose(); got == purpose {
				t.Fatal("ceremony purpose did not bind the changed public fact")
			}
		})
	}
}
