// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestSequentialSourceAdmissionUsesCommittedProjection(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	trustID := uuid.NewString()
	trust, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: trustID, Name: "Source trust", Method: "k8s_sat",
		Issuer: "https://issuer.example.test", Audience: "trstctl",
		JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventWorkloadAttesterTrustSourceUpserted,
		TenantID: h.tenant, Data: trust}); err != nil {
		t.Fatalf("trust source admission: %v", err)
	}
	appendSource := func(id string) (events.Event, error) {
		data, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceUpserted{
			ID: id, Name: "Workload source", Provider: "aws",
			RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
			Audience: "trstctl", Subject: "system:serviceaccount:default:web",
			TargetID: "aws-target", WorkloadProofRef: "secret://proof",
			TrustSourceID: trustID, Enabled: true,
		})
		if err != nil {
			return events.Event{}, err
		}
		return log.Append(ctx, events.Event{
			Type: projections.EventSecretSyncWorkloadIdentityUpserted, TenantID: h.tenant, Data: data,
		})
	}
	if _, err := appendSource(uuid.NewString()); err != nil {
		t.Fatalf("first source admission: %v", err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendSource(uuid.NewString()); err == nil {
		t.Fatal("second admission did not observe the first source's committed projection")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("source head after refused source=%d err=%v, want %d", after, err, before)
	}
}
