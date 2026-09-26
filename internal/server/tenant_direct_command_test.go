// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// Direct worker callers do not inherit HTTP admission. These public synthetic
// facts exercise real append/projection/outbox writes, not external execution.
func TestServedDirectCommandsCannotRecreateDeletedTenantState(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "Direct command tenant")
	ctx := t.Context()
	actions := []struct {
		name string
		run  func() error
	}{
		{"certificate", func() error {
			before, after := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
			payload, err := json.Marshal(projections.CertificateRecorded{ID: uuid.NewString(), Fingerprint: strings.Repeat("d", 64), Serial: "01", Subject: "CN=owned.example.test", Issuer: "CN=owned CA", NotBefore: &before, NotAfter: &after, Source: "discovery"})
			if err != nil {
				return err
			}
			return h.srv.orch.RecordCertificateEvent(ctx, events.Event{ID: uuid.NewString(), Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: payload})
		}},
		{"access-change", func() error {
			_, err := h.srv.orch.CreateAccessChangeRequest(ctx, h.tenant, orchestrator.AccessChangeRequestCreateRequest{RequestedAction: "rotate", RequesterSubject: "owned-operator", NHIID: "owned-nhi", NHIKind: "certificate", Resource: "owned-resource", Entitlement: "use", ChangeRef: "CHG-001", Reason: "owned test"})
			return err
		}},
		{"ticket-outbox", func() error {
			_, err := h.srv.orch.RequestServiceNowTicket(ctx, h.tenant, orchestrator.ServiceNowTicketRequest{InstanceURL: "https://owned.example.test", TokenRef: filepath.Join(t.TempDir(), "servicenow-reference"), ShortDescription: "owned test"})
			return err
		}},
		{"remediation", func() error {
			_, err := h.srv.orch.RecordRemediationPlaybookRun(ctx, h.tenant, store.RemediationPlaybookRun{ID: uuid.NewString(), PlaybookID: "owned-playbook", Status: "completed", Phase: "verify", Action: "observe", CreatedBy: "owned-operator"}, "")
			return err
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
			t.Errorf("refused direct commands appended events: %d -> %d", before, after)
		}
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { assertRefused(store.ErrTenantServiceBusy); return nil }); err != nil {
		t.Fatal(err)
	}
	offboardServedTestTenant(t, h)
	assertRefused(tenancy.ErrServiceUnavailable)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for _, table := range []string{"certificates", "access_change_requests", "remediation_playbook_runs", "outbox"} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", h.tenant).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("late command recreated %d %s rows", n, table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
