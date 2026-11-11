// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/governance/misuse"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// M2-L4: when a finding's event is appended but its tenant transaction fails,
// the event tail projects the finding later with no alert row. The next
// detection pass writes that alert, once, rebuilt from the finding's event;
// a finding that did not alert gets none, and one older than the
// reconciliation window is left alone.
func TestMisuseAlertIsWrittenForAFindingTheTailProjectedM2L4(t *testing.T) {
	ctx := context.Background()
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f := &usageFixture{t: t, ctx: ctx, st: st, log: log, proj: projections.New(st)}
	reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: misuseTenant, Data: []byte(`{"name":"misuse tenant"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.proj.Apply(ctx, reg); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hour := now.Truncate(time.Hour)
	f.use("deployer", "127.0.0.0/24", projections.CredentialActionAPICall, hour, 1) // the tenant has recent usage

	findings := misuse.NewProjection(st)
	tail := func(id string, finding misuse.FindingDetected) {
		t.Helper()
		payload, err := json.Marshal(finding)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{ID: id, Type: misuse.EventFindingDetected, TenantID: misuseTenant, Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		if err := findings.Apply(ctx, ev); err != nil { // the tail projects it; no alert row is written
			t.Fatal(err)
		}
	}
	tail("a1900000-0000-4000-8000-0000000000a1", misuse.FindingDetected{Rule: misuse.RuleNewSourceLease, CredentialID: "deployer", Principal: "svc-deployer",
		Source: "10.20.30.0/24", WindowStart: hour, ObservedCount: 1, NormalSources: []string{"127.0.0.0/24"}, Alerted: true})
	tail("a1900000-0000-4000-8000-0000000000a2", misuse.FindingDetected{Rule: misuse.RuleSecretReadBurst, CredentialID: "reader", Principal: "svc-reader",
		Source: "127.0.0.0/24", WindowStart: hour, ObservedCount: 64, Baseline: 2, Alerted: false})
	if got := f.alerts(); len(got) != 0 {
		t.Fatalf("alerts before the pass = %v", got)
	}

	detector, _ := misuse.NewDetector(misuse.Options{Store: st, Log: log, Now: func() time.Time { return now }})
	for range 2 {
		if err := detector.DetectOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	alerts := f.alerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts after two passes = %v, want exactly the alerting finding's", alerts)
	}
	if !strings.Contains(alerts[0], "misuse:a1900000-0000-4000-8000-0000000000a1") || !strings.Contains(alerts[0], "10.20.30.0/24") || !strings.Contains(alerts[0], "127.0.0.0/24") {
		t.Fatalf("reconciled alert = %s, want the finding's own key, network and normal networks", alerts[0])
	}

	// Past the window, a finding missing its alert is left alone: its alert,
	// if it was written, may already have been delivered and swept.
	tail("a1900000-0000-4000-8000-0000000000a3", misuse.FindingDetected{Rule: misuse.RuleNewSourceLease, CredentialID: "builder", Principal: "svc-builder",
		Source: "10.99.0.0/24", WindowStart: hour, ObservedCount: 1, NormalSources: []string{"127.0.0.0/24"}, Alerted: true})
	later, _ := misuse.NewDetector(misuse.Options{Store: st, Log: log, Now: func() time.Time { return now.Add(7 * time.Hour) }})
	f.use("deployer", "127.0.0.0/24", projections.CredentialActionAPICall, hour.Add(7*time.Hour), 1) // still a tenant with recent usage then
	if err := later.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.alerts(); len(got) != 1 {
		t.Fatalf("a finding past the reconciliation window was alerted: %v", got)
	}
}
