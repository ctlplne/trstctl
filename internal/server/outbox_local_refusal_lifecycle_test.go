// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A configured integration can lose its local credential before the queued
// command runs. No remote request occurred, so this must not leave an indefinite
// customer lifecycle hold. A real receiver error remains ambiguous.
func TestServedTicketLocalRefusalDoesNotInventRemoteWork(t *testing.T) {
	for _, tc := range []struct {
		name        string
		credential  string
		response    int
		wantCalls   int32
		wantPending int
	}{
		{name: "missing-local-credential", response: http.StatusCreated},
		{name: "receiver-error", credential: "fixture", response: http.StatusServiceUnavailable, wantCalls: 1, wantPending: 1},
		{name: "completed", credential: "fixture", response: http.StatusCreated, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/api/now/table/incident" {
					t.Errorf("unexpected receiver request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.response)
			}))
			defer receiver.Close()
			t.Setenv("TRSTCTL_LIFECYCLE_TICKET_FIXTURE", tc.credential)
			const ref = "env:TRSTCTL_LIFECYCLE_TICKET_FIXTURE"
			h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.ServiceNowBindings = []api.ServiceNowBinding{{
					InstanceURL: receiver.URL, TokenRef: ref, AllowPrivateEndpoint: true,
					PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, receiver.URL)},
				}}
			})
			token := seedScopedToken(t, h.store, h.tenant, "incidents:write", string(authz.PrivateEgress))
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", token, "lifecycle-ticket-"+tc.name, map[string]any{
				"instance_url": receiver.URL, "table": "incident", "token_ref": ref,
				"short_description": "Owned lifecycle recovery probe", "allow_private_endpoint": true,
			})
			if status != http.StatusAccepted {
				t.Fatalf("queue ticket: status=%d body=%s", status, body)
			}
			var queued struct {
				OutboxID int64 `json:"outbox_id"`
			}
			if err := json.Unmarshal(body, &queued); err != nil || queued.OutboxID == 0 {
				t.Fatalf("queued identity: %d, %v", queued.OutboxID, err)
			}
			claimed, err := h.srv.outbox.DispatchOneScoped(t.Context(), h.srv.obHandler,
				orchestrator.DestinationScope{IncludePrefixes: []string{orchestrator.DestinationITSMServiceNow}})
			if err != nil || !claimed {
				t.Fatalf("dispatch: claimed=%v err=%v", claimed, err)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Fatalf("receiver calls=%d, want %d", got, tc.wantCalls)
			}
			var pending, attempts int
			var outboxStatus, detail string
			if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(t.Context(), `SELECT cardinality(receiver_pending_ids), attempts, status, COALESCE(last_error,'')
					FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, queued.OutboxID).Scan(&pending, &attempts, &outboxStatus, &detail)
			}); err != nil {
				t.Fatal(err)
			}
			if pending != tc.wantPending || attempts != 1 {
				t.Errorf("remote hold=%d attempts=%d, want hold=%d attempts=1 (status=%s)", pending, attempts, tc.wantPending, outboxStatus)
			}
			if tc.response != http.StatusCreated || tc.wantCalls == 0 {
				if outboxStatus != "pending" || detail != "external_delivery_failed" {
					t.Errorf("failed attempt lost retry/redaction behavior: status=%s detail=%q", outboxStatus, detail)
				}
			} else if outboxStatus != "delivered" {
				t.Errorf("completed delivery status=%s", outboxStatus)
			}
			err = h.store.WithTenantServiceBarrier(t.Context(), h.tenant, func(ctx context.Context) error {
				return h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					return h.store.RequireTenantAgentWorkQuiescentTx(ctx, tx, h.tenant)
				})
			})
			if tc.wantPending == 0 && err != nil {
				t.Errorf("known local/complete result blocks lifecycle: %v", err)
			}
			if tc.wantPending != 0 && !errors.Is(err, store.ErrTenantServiceBusy) {
				t.Errorf("ambiguous receiver failure did not block lifecycle: %v", err)
			}
			if tc.wantPending == 0 && err == nil {
				offboardServedTestTenant(t, h)
			}
		})
	}
}

func TestUnconfiguredDispatcherCannotInventRemoteWork(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	for _, destination := range []string{
		destinationACMEDNS01Present, ca.DestinationExternalCAIssue,
		"notification.probe", "transparency.probe", "managedkey.probe", "unsupported.probe",
	} {
		t.Run(destination, func(t *testing.T) {
			var id int64
			if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				var err error
				id, err = h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
					TenantID: h.tenant, Destination: destination, IdempotencyKey: "unconfigured-" + destination, Payload: []byte(`{}`),
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// Real routing, with every optional receiver deliberately absent.
			claimed, err := h.srv.outbox.DispatchOneScoped(ctx, &issuanceDispatcher{}, orchestrator.DestinationScope{IncludePrefixes: []string{destination}})
			if err != nil || !claimed {
				t.Fatalf("dispatch=%v, %v", claimed, err)
			}
			var pending, attempts int
			var status, detail string
			if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT cardinality(receiver_pending_ids), attempts, status, COALESCE(last_error,'')
					FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, id).Scan(&pending, &attempts, &status, &detail)
			}); err != nil {
				t.Fatal(err)
			}
			if pending != 0 || attempts != 1 || status != "pending" || detail != "external_delivery_failed" {
				t.Errorf("unconfigured route: remote hold=%d attempts=%d status=%s detail=%q", pending, attempts, status, detail)
			}
		})
	}
	if !t.Failed() {
		offboardServedTestTenant(t, h)
	}
}
