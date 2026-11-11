// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// scheduledLeaseCommandView is the rotation command a dynamic-lease schedule
// queues, read through the served API.
type scheduledLeaseCommandView struct {
	ID         string `json:"id"`
	Phase      string `json:"phase"`
	Terminal   bool   `json:"terminal"`
	OldRef     string `json:"old_ref"`
	NewRef     string `json:"new_ref"`
	TTLSeconds int    `json:"ttl_seconds"`
	ScheduleID string `json:"schedule_id"`
	Error      string `json:"error"`
}

// TestServedScheduledDynamicLeaseRotationRevokesTheOldLeaseA201L1 is A201-L1
// against the server tests' own PostgreSQL: a dynamic-lease schedule is
// refused before persistence when it cannot run, and once created each due
// edge issues a new lease of the schedule's TTL, publishes it as the secret's
// next version and revokes the lease before. The second edge starts from the
// lease the first one left live, and both predecessors' roles are gone from
// PostgreSQL itself.
func TestServedScheduledDynamicLeaseRotationRevokesTheOldLeaseA201L1(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	const role = "reporting-sched"
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pg-sched", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "pg-admin-dsn", dsn), Database: parsed.Database,
		AllowedRoles: []string{role}, RoleAccess: map[string]string{role: "read"}, MaxTTL: "1h", UsernamePrefix: "trstctl_a201l1",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "scheduled dynamic-lease rotation tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	readLease := func(id string) dynamicLeaseView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read lease %s: %d %s", id, status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a201l1-l1",
		map[string]any{"provider": "pg-sched", "role": role, "ttl_seconds": 600})
	if status != http.StatusCreated {
		t.Fatalf("issue the first lease: %d %s", status, body)
	}
	var first dynamicLeaseView
	if err := json.Unmarshal(body, &first); err != nil || first.ID == "" || first.Credential == "" {
		t.Fatalf("decode the first lease: %v %s", err, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a201l1-seed",
		map[string]any{"name": role, "value": first.Credential}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("publish the first lease: %d %s", status, body)
	}

	// Refusals before anything is persisted: a TTL is required, bounded by the
	// provider's maximum, the provider must exist, a TTL belongs only to a
	// dynamic-lease schedule, and old_ref must be the role's active lease.
	schedule := func(name string, extra map[string]any) map[string]any {
		body := map[string]any{"name": name, "provider": "dynamic-lease:pg-sched", "key": role, "old_ref": first.ID, "interval_seconds": 1,
			"enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for _, c := range []struct {
		name  string
		extra map[string]any
		want  int
	}{
		{"no-ttl", nil, http.StatusBadRequest},
		{"ttl-over-max", map[string]any{"ttl_seconds": 7200}, http.StatusUnprocessableEntity},
		{"absent-provider", map[string]any{"provider": "dynamic-lease:absent", "ttl_seconds": 600}, http.StatusServiceUnavailable},
		{"ttl-on-connector", map[string]any{"provider": "connector:nowhere", "old_ref": "version:1", "ttl_seconds": 600}, http.StatusBadRequest},
		{"stale-old-ref", map[string]any{"old_ref": "00000000-0000-4000-8000-00000000a201", "ttl_seconds": 600}, http.StatusConflict},
	} {
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, schedule("refused-"+c.name, c.extra)); status != c.want {
			t.Fatalf("schedule %s = %d %s, want %d", c.name, status, body, c.want)
		}
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules", tok, nil); status != http.StatusOK || strings.Contains(string(body), "refused-") {
		t.Fatalf("a refused schedule was persisted: %d %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "a201l1-schedule",
		schedule("reporting-every-second", map[string]any{"ttl_seconds": 1200}))
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create the schedule: %d %s", status, body)
	}
	var created struct {
		ID         string `json:"id"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == "" || created.TTLSeconds != 1200 {
		t.Fatalf("created schedule = %s (%v), want ttl_seconds 1200", body, err)
	}

	follow := func(id string) scheduledLeaseCommandView {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			h.srv.dispatchOnce(ctx)
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
			if status != http.StatusOK {
				t.Fatalf("read command %s: %d %s", id, status, body)
			}
			var view scheduledLeaseCommandView
			_ = json.Unmarshal(body, &view)
			if view.Terminal {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("command %s did not finish: %+v", id, view)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	tick := func(n int) scheduledLeaseCommandView {
		t.Helper()
		for {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules/"+created.ID, tok, nil)
			if status != http.StatusOK {
				t.Fatalf("read schedule: %d %s", status, body)
			}
			var view struct {
				NextRunAt time.Time `json:"next_run_at"`
			}
			_ = json.Unmarshal(body, &view)
			if wait := time.Until(view.NextRunAt); wait > 0 {
				time.Sleep(wait + 10*time.Millisecond)
				continue
			}
			break
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("a201l1-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+url.QueryEscape(role), tok, nil)
		var list struct {
			Items []scheduledLeaseCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n || list.Items[0].ScheduleID != created.ID {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return follow(list.Items[0].ID)
	}

	one := tick(1)
	if one.Phase != "completed" || one.OldRef != first.ID || one.NewRef == "" || one.TTLSeconds != 1200 {
		t.Fatalf("first scheduled rotation = %+v, want completed from the first lease with a 1200 s lease", one)
	}
	two := tick(2)
	if two.Phase != "completed" || two.OldRef != one.NewRef || two.NewRef == "" || two.NewRef == one.NewRef || two.TTLSeconds != 1200 {
		t.Fatalf("second scheduled rotation = %+v, want completed from the lease the first one left live", two)
	}

	live := readLease(two.NewRef)
	if live.State != "active" {
		t.Fatalf("the newest lease is %q", live.State)
	}
	if lifetime := live.ExpiresAt.Sub(live.IssuedAt); lifetime < 1198*time.Second || lifetime > 1202*time.Second {
		t.Fatalf("the scheduled lease lives %s, want 1200 s", lifetime)
	}
	for _, id := range []string{first.ID, one.NewRef} {
		if old := readLease(id); old.State != "revoked" || old.RevocationStatus != "completed" {
			t.Fatalf("lease %s is %q with revocation %q, want revoked and completed", id, old.State, old.RevocationStatus)
		}
	}

	// Without trstctl: the published credential logs in as the newest lease's
	// role, and the first lease's role is gone from PostgreSQL.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+role, tok, nil)
	var published struct {
		Value string `json:"value"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &published) != nil || published.Value == "" {
		t.Fatalf("read the published secret: %d", status)
	}
	conn, err := pgx.Connect(ctx, published.Value)
	if err != nil {
		t.Fatalf("the published credential does not log in: %v", err)
	}
	_ = conn.Close(ctx)
	oldConfig, err := pgx.ParseConfig(first.Credential)
	if err != nil {
		t.Fatal(err)
	}
	var roles int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname = $1`, oldConfig.User).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 0 {
		t.Fatalf("the first lease's role %q still exists", oldConfig.User)
	}
	t.Logf("A201L1_SCHEDULED_OK leases=%s->%s->%s ttl=%ds", first.ID, one.NewRef, two.NewRef, live.ExpiresAt.Sub(live.IssuedAt)/time.Second)
}
