// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

func TestACMEARIPostureDoesNotCallDisabledSchedulerPending(t *testing.T) {
	tests := []struct {
		name              string
		certificateStatus string
		identityID        string
		schedulerStatus   string
		want              string
	}{
		{
			name:              "disabled scheduler with lifecycle identity",
			certificateStatus: "active",
			identityID:        "11111111-1111-4111-8111-111111111111",
			schedulerStatus:   api.ACMEARISchedulerDisabled,
			want:              api.ACMEARIRunNotApplicable,
		},
		{
			name:              "enabled scheduler with lifecycle identity",
			certificateStatus: "active",
			identityID:        "11111111-1111-4111-8111-111111111111",
			schedulerStatus:   api.ACMEARISchedulerEnabled,
			want:              api.ACMEARIRunPending,
		},
		{
			name:              "published certificate without lifecycle identity",
			certificateStatus: "active",
			schedulerStatus:   api.ACMEARISchedulerEnabled,
			want:              api.ACMEARIRunNotApplicable,
		},
		{
			name:              "revoked certificate is never pending",
			certificateStatus: "revoked",
			identityID:        "11111111-1111-4111-8111-111111111111",
			schedulerStatus:   api.ACMEARISchedulerEnabled,
			want:              api.ACMEARIRunNotApplicable,
		},
		{
			name:              "superseded predecessor without evidence is never pending",
			certificateStatus: "superseded",
			identityID:        "11111111-1111-4111-8111-111111111111",
			schedulerStatus:   api.ACMEARISchedulerEnabled,
			want:              api.ACMEARIRunNotApplicable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initialACMEARISchedulerStatus(tt.certificateStatus, tt.identityID, tt.schedulerStatus); got != tt.want {
				t.Fatalf("initial scheduler status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSchedulerRenewalTargetsOnlyItsSelectedCertificate(t *testing.T) {
	certs := []store.Certificate{
		{ID: "cert-a", Fingerprint: "fingerprint-a"},
		{ID: "cert-b", Fingerprint: "fingerprint-b"},
	}
	selected, err := renewalCertificatesForTrigger(certs, transitionTrigger{
		IdentityID:             "identity-a",
		Origin:                 lifecycleTransitionOriginScheduler,
		PredecessorFingerprint: "fingerprint-a",
	})
	if err != nil {
		t.Fatalf("select scheduler predecessor: %v", err)
	}
	if len(selected) != 1 || selected[0].ID != "cert-a" {
		t.Fatalf("scheduler renewal targets = %+v, want only cert-a", selected)
	}

	manual, err := renewalCertificatesForTrigger(certs, transitionTrigger{IdentityID: "identity-a"})
	if err != nil {
		t.Fatalf("manual renewal selection: %v", err)
	}
	if len(manual) != 2 {
		t.Fatalf("manual renewal targets = %+v, want existing renew-all behavior", manual)
	}

	_, err = renewalCertificatesForTrigger(certs, transitionTrigger{
		IdentityID: "identity-a",
		Origin:     lifecycleTransitionOriginScheduler,
	})
	if err == nil {
		t.Fatal("structured scheduler renewal accepted an empty predecessor fingerprint")
	}

	_, err = renewalCertificatesForTrigger(certs, transitionTrigger{
		IdentityID:             "identity-a",
		Origin:                 lifecycleTransitionOriginScheduler,
		PredecessorFingerprint: "missing",
	})
	if err == nil {
		t.Fatal("scheduler renewal did not fail closed when its selected predecessor disappeared")
	}
}

func TestRotationTriggerRequiresStructuredOrLegacyInternalSchedulerProvenance(t *testing.T) {
	const (
		eventNUID = "ABCDEFGHIJKLMNOPQRSTUV"
		ariReason = lifecycleARIRenewalReasonPrefix + "2026-01-01T00:00:00Z..2026-01-02T00:00:00Z"
	)
	tests := []struct {
		name           string
		origin         string
		idempotencyKey string
		reason         string
		want           string
	}{
		{
			name:           "structured scheduler",
			origin:         lifecycleTransitionOriginScheduler,
			idempotencyKey: eventNUID,
			reason:         ariReason,
			want:           "scheduler",
		},
		{
			name:           "legacy scheduler survives rolling upgrade",
			idempotencyKey: eventNUID,
			reason:         ariReason,
			want:           "scheduler",
		},
		{
			name:           "served caller cannot forge scheduler with prose",
			idempotencyKey: "transition:caller-controlled-key",
			reason:         ariReason,
			want:           "manual",
		},
		{
			name:           "unknown origin fails honest",
			origin:         "operator",
			idempotencyKey: eventNUID,
			reason:         ariReason,
			want:           "manual",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rotationTrigger(tt.origin, tt.idempotencyKey, tt.reason); got != tt.want {
				t.Fatalf("rotation trigger = %q, want %q", got, tt.want)
			}
		})
	}
}
