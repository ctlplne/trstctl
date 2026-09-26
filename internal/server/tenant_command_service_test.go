// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestServedBackgroundCommandRequiresLiveTenantService(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "Background command tenant")
	ctx := t.Context()
	if _, err := h.srv.orch.CreateOwner(ctx, h.tenant, "team", "before deletion", "qa@example.test"); err != nil {
		t.Fatal(err)
	}
	sequence := func() uint64 {
		t.Helper()
		n, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := sequence()
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error {
		// Deliberately use the independent worker context, not the barrier's
		// privileged context. No API middleware wraps a background command.
		_, err := h.srv.orch.CreateOwner(ctx, h.tenant, "team", "during lifecycle change", "qa@example.test")
		if !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Errorf("background command during lifecycle barrier = %v, want busy", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if after := sequence(); after != before {
		t.Errorf("refused busy command appended source events: %d -> %d", before, after)
	}
	// Once the barrier is released, normal background work must still succeed.
	if _, err := h.srv.orch.CreateOwner(ctx, h.tenant, "team", "after barrier", "qa@example.test"); err != nil {
		t.Fatal(err)
	}
	offboardServedTestTenant(t, h)
	before = sequence()
	_, err := h.srv.orch.CreateOwner(ctx, h.tenant, "team", "late completion", "qa@example.test")
	if !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("background command after deletion = %v, want unavailable", err)
	}
	if after := sequence(); after != before {
		t.Errorf("deleted tenant command appended source events: %d -> %d", before, after)
	}
	if err := h.srv.orch.RecordAuthzDecision(ctx, h.tenant, orchestrator.AuthzDecision{Decision: "deny"}); err != nil {
		t.Fatalf("erased tenant access refusal lost its audit evidence: %v", err)
	}
	if after := sequence(); after != before+1 {
		t.Errorf("expected exactly one retained refusal audit event: %d -> %d", before, after)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM owners WHERE tenant_id=$1`, h.tenant).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Errorf("late command recreated %d owner rows", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Exercise separate append/project/outbox paths used by background verification.
// Synthetic public observation metadata tests persistence admission, not actual
// CRL/OCSP verification or delivery to an external endpoint.
func TestServedBackgroundObservationRequiresLiveTenantService(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "Background observation tenant")
	ctx := t.Context()
	target := revocationhealth.Target{Key: strings.Repeat("a", 64), Protocol: revocationhealth.ProtocolCRL,
		Endpoint: "https://ca.example.test/issuer.crl", IssuerSubject: "Example CA",
		CertificateID: uuid.NewString(), CertificateFingerprint: strings.Repeat("b", 64),
		CertificateSerial: "01", CertificateSubject: "service.example.test"}
	actions := []struct {
		name string
		run  func() error
	}{
		{"endpoint", func() error {
			return h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
				EndpointID: "background-endpoint", Address: "service.example.test:443", Vantage: "relay", Reached: true,
				ExpectedFingerprint: strings.Repeat("b", 64), ObservedFingerprint: strings.Repeat("b", 64), ObservedAt: time.Now().UTC(),
			})
		}},
		{"revocation-probe", func() error {
			_, _, err := h.srv.orch.QueueRevocationProbe(ctx, h.tenant, revocationhealth.Intent{ID: uuid.NewString(),
				Bucket: "background", BatchIndex: 1, BatchCount: 1, RequiredAgentRole: revocationhealth.RequiredRoleNetwork,
				Targets: []revocationhealth.Target{target}})
			return err
		}},
		{"revocation-observation", func() error {
			return h.srv.orch.RecordRevocationHealthObservedWithEventID(ctx, h.tenant, uuid.NewString(), revocationhealth.Observed{
				ProbeID: uuid.NewString(), Bucket: "background", BatchIndex: 1, BatchCount: 1,
				AgentID: uuid.NewString(), AgentName: "observation-relay", EvidenceDigest: strings.Repeat("c", 64),
				Targets: []revocationhealth.Target{target}, Findings: []revocationhealth.Finding{{TargetKey: target.Key,
					Protocol: target.Protocol, Endpoint: target.Endpoint, Status: revocationhealth.StatusUnreachable, DetailCode: "transport_failed"}},
			})
		}},
	}
	for _, action := range actions {
		if err := action.run(); err != nil {
			t.Fatalf("active %s: %v", action.name, err)
		}
	}
	assertRefused := func(want error) {
		t.Helper()
		before, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range actions {
			if err := action.run(); !errors.Is(err, want) {
				t.Errorf("%s = %v, want %v", action.name, err, want)
			}
		}
		after, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after != before {
			t.Errorf("refused observations appended source events: %d -> %d", before, after)
		}
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error {
		assertRefused(store.ErrTenantServiceBusy)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	offboardServedTestTenant(t, h)
	assertRefused(tenancy.ErrServiceUnavailable)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for _, table := range []string{"endpoint_verifications", "revocation_endpoint_health", "outbox"} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", h.tenant).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("late observations recreated %d %s rows", n, table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
