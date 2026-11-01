// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

type m1Clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *m1Clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *m1Clock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

type m1Finding struct {
	InventoryID  string   `json:"inventory_id"`
	Kind         string   `json:"kind"`
	FindingTypes []string `json:"finding_types"`
	EvidenceRefs []string `json:"evidence_refs"`
}

func seedM1Token(t *testing.T, h *servedHarness, subject string, scopes ...string) (string, string) {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.CreateAPIToken(context.Background(), store.APITokenRecord{TenantID: h.tenant, TokenHash: hash, Subject: subject, Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token, rec.ID
}

// M1: trstctl turns its own activity into usage posture with no operator
// input. An API token unused for N days is flagged; use from a new client
// network, and a machine login from a newly attested workload, are flagged
// until they have become normal (three days of use); a recorded gap in the
// telemetry suspends "unused" rather than counting as non-use; and the usage
// read model rebuilds identically from the event log.
func TestServedCredentialUsagePostureM1(t *testing.T) {
	clock := &m1Clock{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithCredentialUsageClock(clock.now))
	})
	ctx := t.Context()
	now := time.Now().UTC()
	base := now.AddDate(0, 0, -40)
	reader, _ := seedM1Token(t, h, "m1-posture-reader", "nhi:read", "graph:read")
	active, activeID := seedM1Token(t, h, "m1-ci-deployer", "nhi:read")
	_, idleID := seedM1Token(t, h, "m1-forgotten", "nhi:read")
	use := func(token, remote string, at time.Time) {
		t.Helper()
		clock.set(at)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nhi/inventory", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ts.Config.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("token use: HTTP %d %s", rec.Code, rec.Body.String())
		}
		if err := h.srv.DrainCredentialUsage(ctx); err != nil {
			t.Fatalf("drain usage: %v", err)
		}
	}
	posture := func(unusedDays int) map[string]m1Finding {
		t.Helper()
		clock.set(now)
		status, body := secretsReq(t, h, http.MethodGet, fmt.Sprintf("/api/v1/nhi/posture/stale?unused_days=%d", unusedDays), reader, nil)
		if status != http.StatusOK {
			t.Fatalf("stale posture: HTTP %d %s", status, body)
		}
		var out struct {
			Thresholds struct {
				UnusedNoActivityDays int `json:"unused_no_activity_days"`
			} `json:"thresholds"`
			Findings []m1Finding `json:"findings"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.Thresholds.UnusedNoActivityDays != unusedDays {
			t.Fatalf("decode posture (%v): %s", err, body)
		}
		if err := h.srv.DrainCredentialUsage(ctx); err != nil {
			t.Fatal(err)
		}
		byID := map[string]m1Finding{}
		for _, f := range out.Findings {
			byID[f.InventoryID] = f
		}
		return byID
	}
	// The forgotten token predates tracking; tracking began with the first
	// recorded use in the tenant, 40 days ago.
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE api_tokens SET created_at = $1 WHERE tenant_id = $2 AND id = $3`,
		now.AddDate(0, 0, -45), h.tenant, idleID); err != nil {
		t.Fatal(err)
	}
	if got := posture(30)["api-token/"+idleID]; slices.Contains(got.FindingTypes, "unused_no_activity") {
		t.Fatalf("a token was called unused before any use was recorded in the tenant: %+v", got)
	}

	// Three days of use from one client network make it normal.
	for day := 0; day < 3; day++ {
		use(active, "127.0.0.1:50000", base.AddDate(0, 0, day))
	}
	// A new client network is flagged …
	use(active, "10.20.30.40:41000", base.AddDate(0, 0, 3))
	f := posture(30)["api-token/"+activeID]
	if !slices.Contains(f.FindingTypes, "new_source") || !slices.Contains(f.EvidenceRefs, "usage:new_source:10.20.30.0/24") {
		t.Fatalf("use from a new network was not flagged: %+v", f)
	}
	// … and clears once it is used from there on three different days.
	use(active, "10.20.30.41:41000", base.AddDate(0, 0, 4))
	use(active, "10.20.30.42:41000", base.AddDate(0, 0, 5))
	use(active, "127.0.0.1:50000", now.Add(-time.Hour))
	findings := posture(30)
	if f := findings["api-token/"+activeID]; slices.Contains(f.FindingTypes, "new_source") || slices.Contains(f.FindingTypes, "unused_no_activity") {
		t.Fatalf("normal, recent use still flagged: %+v", f)
	}
	// The forgotten token: no recorded use for 40 days → unused at 30, not at 60.
	idle := findings["api-token/"+idleID]
	if !slices.Contains(idle.FindingTypes, "unused_no_activity") || !strings.HasPrefix(evidenceWith(idle.EvidenceRefs, "usage:no_recorded_use_since:"), "usage:no_recorded_use_since:") {
		t.Fatalf("a token unused for 40 days was not flagged at 30: %+v", idle)
	}
	if f := posture(60)["api-token/"+idleID]; slices.Contains(f.FindingTypes, "unused_no_activity") {
		t.Fatalf("a token unused for 40 days was flagged at 60: %+v", f)
	}

	// A recorded telemetry gap in the window suspends the verdict.
	gapID := uuid.NewString()
	if err := h.srv.orch.RecordCredentialUsageGap(ctx, h.tenant, gapID, projections.CredentialUsageGap{
		From: now.AddDate(0, 0, -20), To: now.AddDate(0, 0, -19), Dropped: 7,
	}); err != nil {
		t.Fatal(err)
	}
	if f, flagged := posture(30)["api-token/"+idleID]; flagged {
		t.Fatalf("missing telemetry counted as non-use (gap %s): %+v", gapID, f)
	}

	// Machine logins: three days of logins by one attested workload, then a
	// new workload on the same login method.
	login := func(principal string, at time.Time) {
		t.Helper()
		payload, err := json.Marshal(projections.MachineSessionStarted{
			ID: uuid.NewString(), Principal: principal, Method: "kubernetes", IssuedAt: at, ExpiresAt: at.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := h.log.Append(ctx, events.Event{Type: projections.EventMachineSessionStarted, TenantID: h.tenant, Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.proj.Apply(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for day := 0; day < 3; day++ {
		login("system:serviceaccount:payments:api", base.AddDate(0, 0, day))
	}
	login("system:serviceaccount:payments:debug-shell", now.Add(-2*time.Hour))
	f = posture(30)["machine-login/kubernetes"]
	if f.Kind != "workload_identity" || !slices.Contains(f.FindingTypes, "new_source") ||
		!slices.Contains(f.EvidenceRefs, "usage:new_source:system:serviceaccount:payments:debug-shell") {
		t.Fatalf("a login from a newly attested workload was not flagged: %+v", f)
	}
	login("system:serviceaccount:payments:debug-shell", now.Add(24*time.Hour))
	login("system:serviceaccount:payments:debug-shell", now.Add(48*time.Hour))
	if f := posture(30)["machine-login/kubernetes"]; slices.Contains(f.FindingTypes, "new_source") {
		t.Fatalf("a workload that logged in on three days is still flagged: %+v", f)
	}

	// The graph shows when and from where the token was last used.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/graph", reader, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"last_used_source":"127.0.0.0/24"`) {
		t.Fatalf("graph lacks the token's last use: HTTP %d", status)
	}

	// The usage read model rebuilds identically from the event log.
	snapshot := func() []string {
		t.Helper()
		var rows []string
		for _, q := range []string{
			`SELECT kind || '|' || credential_id || '|' || principal || '|' || first_used_at || '|' || last_used_at || '|' || last_source FROM credential_usage WHERE tenant_id = $1 ORDER BY 1`,
			`SELECT kind || '|' || credential_id || '|' || source || '|' || first_seen_at || '|' || last_seen_at || '|' || days_seen || '|' || last_day FROM credential_usage_sources WHERE tenant_id = $1 ORDER BY 1`,
			`SELECT gap_id || '|' || from_at || '|' || to_at || '|' || dropped FROM credential_usage_gaps WHERE tenant_id = $1 ORDER BY 1`,
		} {
			r, err := h.store.SystemPool().Query(ctx, q, h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for r.Next() {
				var row string
				if err := r.Scan(&row); err != nil {
					t.Fatal(err)
				}
				rows = append(rows, row)
			}
			r.Close()
		}
		return rows
	}
	before := snapshot()
	if len(before) < 6 {
		t.Fatalf("usage read model too small to compare: %v", before)
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("usage read model changed across a rebuild:\nbefore %v\nafter  %v", before, after)
	}
	t.Logf("M1_OK rows=%d idle=%v", len(before), idle.FindingTypes)
}

func evidenceWith(refs []string, prefix string) string {
	for _, ref := range refs {
		if strings.HasPrefix(ref, prefix) {
			return ref
		}
	}
	return ""
}
