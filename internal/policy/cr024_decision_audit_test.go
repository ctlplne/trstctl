// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
)

func TestCR024PolicyDecisionFailsClosedWhenAuditAppendFails(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithFixtureAppendAdmission())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	engine, err := policy.New(policy.Config{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	before := auditsink.DroppedEvents()
	d, err := engine.Evaluate(t.Context(), policy.Input{TenantID: "11111111-1111-1111-1111-111111111111", Action: policy.ActionRevoke})
	if !errors.Is(err, policy.ErrDecisionAuditUnavailable) || d.Allow {
		t.Fatalf("policy allowed an unaudited revocation: decision=%+v err=%v", d, err)
	}
	if auditsink.DroppedEvents() <= before {
		t.Fatal("failed policy append did not increment the audit-failure counter")
	}
}

func TestCR024ABACDecisionFailsClosedWhenAuditAppendFails(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithFixtureAppendAdmission())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	engine, err := policy.NewABAC(policy.ABACConfig{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	before := auditsink.DroppedEvents()
	d, err := engine.EvaluateDeny(t.Context(), policy.ABACInput{TenantID: "11111111-1111-1111-1111-111111111111", Permission: "certs:issue"})
	if !errors.Is(err, policy.ErrDecisionAuditUnavailable) || !d.Deny {
		t.Fatalf("ABAC allowed an unaudited operation: decision=%+v err=%v", d, err)
	}
	if auditsink.DroppedEvents() <= before {
		t.Fatal("failed ABAC append did not increment the audit-failure counter")
	}
}
