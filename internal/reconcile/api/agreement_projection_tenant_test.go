// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/reconcile"
	reconcileapi "trstctl.com/trstctl/internal/reconcile/api"
	"trstctl.com/trstctl/internal/reconcile/quarantine"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

// Replay real projection events through the same runtime and API factory used
// by assembly. This qualifies the served projection boundary, not collection
// from external authorities or authentication by a production identity provider.
func TestAgreementProjectionKeepsEveryMetricWithinRequestTenant(t *testing.T) {
	runtime, err := reconcile.NewRuntime(reconcile.RuntimeConfig{Schedules: []rounds.Config{
		{TenantID: "tenant-a", Cadence: time.Hour, Planes: []rounds.PlaneConfig{
			{AuthorityID: "trstctl-self"}, {AuthorityID: "trstctl-ca"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1000, 0).UTC()
	var sequence uint64
	apply := func(tenant, kind string, at time.Time, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		if err := runtime.DriftProjection.Apply(eventspec.Event{
			TenantID: tenant, Type: kind, Sequence: sequence, Time: at,
			SchemaVersion: eventspec.DefaultSchemaVersion, Data: data,
		}); err != nil {
			t.Fatal(err)
		}
	}
	record := func(tenant, id string) {
		t.Helper()
		apply(tenant, witness.EventTypeWitnessRecorded, base, witness.WitnessRecorded{
			TenantID: tenant, WitnessID: id, Authorities: []string{"same-authority-name"},
			Evidence: witness.Evidence{Body: witness.Body{
				TenantID: tenant, WitnessID: id, GeneratedAt: base.Unix(),
				Entries: []witness.Entry{{Class: witness.ClassPresence}},
			}},
		})
	}
	complete := func(tenant, id string, elapsed time.Duration) {
		t.Helper()
		apply(tenant, quarantine.EventTypeCompleted, base.Add(elapsed), quarantine.Completed{
			TenantID: tenant, WitnessID: id, CompletedAt: base.Add(elapsed).Unix(),
		})
	}
	record("tenant-a", "resolved-a")
	complete("tenant-a", "resolved-a", 10*time.Second)
	record("tenant-a", "open-a")
	record("tenant-b", "resolved-b")
	complete("tenant-b", "resolved-b", 90*time.Second)
	record("tenant-b", "open-b-1")
	record("tenant-b", "open-b-2")

	opts, err := reconcileapi.NewAPIOptionsFactory(runtime.DriftProjection, runtime.RoundsScheduledByTenant)(editionseam.LicensedAPIOptionsDeps{})
	if err != nil {
		t.Fatal(err)
	}
	role := authz.Role{Name: "reader", Permissions: []authz.Permission{authz.CertsRead}}
	var principal authz.Principal
	var resolveErr error
	opts = append(opts, coreapi.WithRoles(role), coreapi.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return principal, resolveErr
	}))
	h := coreapi.New(nil, nil, nil, opts...)
	for _, tc := range []struct {
		tenant     string
		open       int
		total      int64
		seconds    int64
		watermark  uint64
		collecting bool
	}{
		{"tenant-a", 1, 2, 10, 3, true},
		{"tenant-b", 2, 3, 90, 7, false},
		{"tenant-empty", 0, 0, 0, 0, false},
	} {
		t.Run(tc.tenant, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/reconcile/agreement", nil)
			principal = authz.Principal{TenantID: tc.tenant, Subject: "operator-" + tc.tenant,
				Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tc.tenant}}}}
			// No identity headers: the endpoint must use the resolved principal.

			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
			}
			var report reconcileapi.AgreementReport
			if err := json.Unmarshal(res.Body.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.OpenWitnesses != tc.open || report.ReplayWatermark != tc.watermark || report.Collecting != tc.collecting {
				t.Errorf("tenant metrics include another tenant: got %+v; want open=%d watermark=%d collecting=%t", report, tc.open, tc.watermark, tc.collecting)
			}
			wantResolved, wantAuthorities := 1, 1
			if tc.total == 0 {
				wantResolved, wantAuthorities = 0, 0
			}
			if report.ResolvedInWindow != wantResolved || report.MedianResolutionSeconds != tc.seconds {
				t.Errorf("tenant resolution metrics: got %+v; want samples=%d median=%d", report, wantResolved, tc.seconds)
			}
			if len(report.Authorities) != wantAuthorities {
				t.Errorf("authority count=%d want %d", len(report.Authorities), wantAuthorities)
			}
			for _, authority := range report.Authorities {
				if authority.AuthorityID != "same-authority-name" || authority.Total != tc.total {
					t.Errorf("same-named authority combined across tenants: %+v; want total=%d", authority, tc.total)
				}
			}
		})
	}
	for _, tc := range []struct {
		name       string
		header     string
		permission bool
		anonymous  bool
		status     int
	}{
		{"foreign tenant assertion", "tenant-b", true, false, http.StatusForbidden},
		{"missing permission", "", false, false, http.StatusForbidden},
		{"anonymous", "", false, true, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal = authz.Principal{TenantID: "tenant-a", Subject: "operator-a"}
			resolveErr = nil
			if tc.permission {
				principal.Grants = []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: "tenant-a"}}}
			}
			if tc.anonymous {
				resolveErr = errors.New("no credentials")
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/reconcile/agreement", nil)
			if tc.header != "" {
				req.Header.Set("X-Tenant-ID", tc.header)
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != tc.status {
				t.Fatalf("status=%d want %d body=%s", res.Code, tc.status, res.Body.String())
			}
		})
	}
}
