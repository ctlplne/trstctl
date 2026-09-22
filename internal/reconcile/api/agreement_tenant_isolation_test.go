// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	reconcileapi "trstctl.com/trstctl/internal/reconcile/api"
	"trstctl.com/trstctl/internal/reconcile/quarantine"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

func TestAgreementRouteDoesNotExposeAnotherTenantsAuthority(t *testing.T) {
	// Use the real shared projection so the test checks both its tenant read
	// boundary and the handler's choice of authenticated tenant.
	projection := namedTenantAgreementProjection(t)
	opts, err := reconcileapi.NewAPIOptionsFactory(projection, map[string]int{"tenant-a": 1})(editionseam.LicensedAPIOptionsDeps{})
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, coreapi.WithInsecureHeaderResolver(), coreapi.WithRoles(authz.Role{Name: "reader", Permissions: []authz.Permission{authz.CertsRead}}))
	h := coreapi.New(nil, nil, nil, opts...)
	for _, tc := range []struct {
		tenant, authority string
		count, seconds    int64
	}{
		{"tenant-a", "private-authority-a", 1, 10},
		{"tenant-b", "private-authority-b", 3, 90},
		{"tenant-empty", "", 0, 0},
	} {
		t.Run(tc.tenant, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/reconcile/agreement", nil)
			req.Header.Set("X-Tenant-ID", tc.tenant)
			req.Header.Set("X-Subject", "reader-"+tc.tenant)
			req.Header.Set("X-Roles", "reader")
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
			}
			var report reconcileapi.AgreementReport
			if err := json.Unmarshal(res.Body.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			wantAuthorities := 1
			wantResolved := 1
			if tc.authority == "" {
				wantAuthorities = 0
				wantResolved = 0
			}
			if len(report.Authorities) != wantAuthorities {
				t.Errorf("tenant %s received authorities %+v", tc.tenant, report.Authorities)
			}
			for _, authority := range report.Authorities {
				if authority.AuthorityID != tc.authority || authority.Total != tc.count {
					t.Errorf("tenant %s received foreign or combined authority %+v", tc.tenant, authority)
				}
			}
			if report.ResolvedInWindow != wantResolved || report.MedianResolutionSeconds != tc.seconds {
				t.Errorf("tenant %s received combined resolution metrics: %+v", tc.tenant, report)
			}
		})
	}
}

func namedTenantAgreementProjection(t *testing.T) *rounds.DriftProjection {
	t.Helper()
	p := rounds.NewDriftProjection(time.Hour)
	at := time.Unix(100, 0).UTC()
	var sequence uint64
	apply := func(tenant, kind string, payload any, when time.Time) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		if err := p.Apply(eventspec.Event{TenantID: tenant, Type: kind, Data: data, Time: when,
			Sequence: sequence, SchemaVersion: eventspec.DefaultSchemaVersion}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		tenant, authority string
		count             int
		seconds           int64
	}{
		{"tenant-a", "private-authority-a", 1, 10},
		{"tenant-b", "private-authority-b", 3, 90},
	} {
		for i := 0; i < tc.count; i++ {
			id := fmt.Sprintf("%s-witness-%d", tc.tenant, i)
			apply(tc.tenant, witness.EventTypeWitnessRecorded, witness.WitnessRecorded{
				TenantID: tc.tenant, WitnessID: id, Authorities: []string{tc.authority},
				Evidence: witness.Evidence{Body: witness.Body{TenantID: tc.tenant, WitnessID: id,
					GeneratedAt: at.Unix(), Entries: []witness.Entry{{Class: witness.ClassPresence}}}},
			}, at)
			if i == 0 {
				completed := at.Add(time.Duration(tc.seconds) * time.Second)
				apply(tc.tenant, quarantine.EventTypeCompleted, quarantine.Completed{
					TenantID: tc.tenant, WitnessID: id, CompletedAt: completed.Unix(),
				}, completed)
			}
		}
	}
	return p
}
