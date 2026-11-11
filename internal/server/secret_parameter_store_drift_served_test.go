// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/secretsync/ssmtest"
)

// TestServedParameterStoreDriftIsDetectedAndRePushedA202L1 is A202-L1 through
// the served scoped sync against a Parameter Store stand-in built from the SSM
// API reference: a parameter changed outside trstctl is found by the plan's
// read-back and written back by the apply; an auto scoped sync's drift check
// re-pushes one with nobody applying; and the plan never carries a value.
func TestServedParameterStoreDriftIsDetectedAndRePushedA202L1(t *testing.T) {
	stand := ssmtest.New()
	t.Cleanup(stand.Close)
	pusher, err := secretsync.NewAWSParameterStorePusher(secretsync.AWSParameterStoreConfig{
		Endpoint: stand.URL, HTTPClient: stand.Client(), Region: "us-east-1",
		AccessKeyID: "stand-in-ssm-key-id", SecretAccessKey: []byte("stand-in-ssm-secret"), PathPrefix: "apps", // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pusher.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"ssm": secretsync.NewAWSParamStoreTarget(pusher)}}
	})
	registerServedTenant(t, h, "A202-L1 parameter store drift tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a202l1-operator", "secrets:read", "secrets:write")
	write := func(name, value string) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a202l1-"+name, map[string]any{"name": name, "value": value}); status != http.StatusCreated {
			t.Fatalf("write %s: HTTP %d %s", name, status, raw)
		}
	}
	drain := func() {
		t.Helper()
		for range 3 {
			head, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE projection_checkpoint SET applied_seq = GREATEST(applied_seq, $1), updated_at = now() WHERE id = 1`, head); err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			_ = h.srv.Drain(ctx)
			cancel()
		}
	}
	type planView struct {
		PlanDigest string `json:"plan_digest"`
		Items      []struct {
			Key    string `json:"key"`
			Action string `json:"action"`
		} `json:"items"`
		Changes int `json:"changes"`
	}
	action := func(p planView, key string) string {
		for _, item := range p.Items {
			if item.Key == key {
				return item.Action
			}
		}
		return ""
	}
	define := func(key string, body map[string]any) string {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scoped-syncs", tok, key, body)
		var out struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(raw, &out) != nil || out.ID == "" {
			t.Fatalf("define: HTTP %d %s", status, raw)
		}
		return out.ID
	}

	write("ssm202/prod/a", "a-one")
	write("ssm202/prod/b", "b-one")
	reviewed := define("a202l1-define", map[string]any{"name": "ssm202-reviewed", "source_prefix": "ssm202/prod/", "target": "ssm", "destination_prefix": "drift202"})
	base := "/api/v1/secrets/scoped-syncs/" + reviewed
	preview := func() planView {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodPost, base+"/preview", tok, nil)
		var p planView
		if status != http.StatusOK || json.Unmarshal(raw, &p) != nil {
			t.Fatalf("preview: HTTP %d %s", status, raw)
		}
		for _, v := range []string{"a-one", "b-one", "tampered"} {
			if strings.Contains(string(raw), v) {
				t.Fatalf("the plan carries a value (%q): %s", v, raw)
			}
		}
		return p
	}
	apply := func(key string, p planView) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, http.MethodPost, base+"/apply", tok, key, map[string]any{"plan_digest": p.PlanDigest}); status != http.StatusCreated {
			t.Fatalf("apply: HTTP %d %s", status, raw)
		}
		drain()
	}

	plan := preview()
	if action(plan, "drift202/a") != "create" || action(plan, "drift202/b") != "create" {
		t.Fatalf("first plan = %+v", plan)
	}
	apply("a202l1-apply-1", plan)
	if v, _ := stand.Value("/apps/drift202/a"); v != "a-one" {
		t.Fatalf("Parameter Store holds %q for a", v)
	}
	if plan := preview(); plan.Changes != 0 || action(plan, "drift202/a") != "unchanged" {
		t.Fatalf("an unchanged destination plans changes: %+v", plan)
	}

	// Drift: the parameter is changed outside trstctl. The plan's read-back
	// finds it, and the apply writes the source value again.
	stand.Set("/apps/drift202/a", "tampered")
	tamperedVersion := stand.Version("/apps/drift202/a")
	plan = preview()
	if action(plan, "drift202/a") != "update" || action(plan, "drift202/b") != "unchanged" || plan.Changes != 1 {
		t.Fatalf("drift was not detected: %+v", plan)
	}
	apply("a202l1-apply-2", plan)
	if v, _ := stand.Value("/apps/drift202/a"); v != "a-one" || stand.Version("/apps/drift202/a") != tamperedVersion+1 {
		t.Fatalf("the drifted parameter was not re-pushed: %q (version %d)", v, stand.Version("/apps/drift202/a"))
	}

	// An auto scoped sync's drift check re-pushes with nobody applying.
	auto := define("a202l1-define-auto", map[string]any{"name": "ssm202-auto", "source_prefix": "ssm202/prod/", "target": "ssm", "destination_prefix": "auto202", "mode": "auto"})
	state := api.ScopedSyncReconcileState{}
	now := time.Now().UTC()
	if n, err := h.srv.api.ReconcileScopedSecretSyncs(t.Context(), []string{h.tenant}, state, now, time.Minute); err != nil || n != 1 {
		t.Fatalf("first auto pass applied %d (%v), want 1", n, err)
	}
	drain()
	if v, _ := stand.Value("/apps/auto202/b"); v != "b-one" {
		t.Fatalf("auto destination b = %q", v)
	}
	stand.Set("/apps/auto202/b", "tampered")
	if n, err := h.srv.api.ReconcileScopedSecretSyncs(t.Context(), []string{h.tenant}, state, now.Add(30*time.Second), time.Minute); err != nil || n != 0 {
		t.Fatalf("a pass before the drift check is due applied %d (%v)", n, err)
	}
	if n, err := h.srv.api.ReconcileScopedSecretSyncs(t.Context(), []string{h.tenant}, state, now.Add(2*time.Minute), time.Minute); err != nil || n != 1 {
		t.Fatalf("the due drift check applied %d (%v), want 1", n, err)
	}
	drain()
	if v, _ := stand.Value("/apps/auto202/b"); v != "b-one" {
		t.Fatalf("the auto drift check did not re-push b: %q", v)
	}
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/scoped-syncs/"+auto, tok, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"reconcile_status":"applied"`) {
		t.Fatalf("auto definition after the drift check: HTTP %d %s", status, raw)
	}
	t.Logf("A202L1_DRIFT_OK reviewed=%s auto=%s", reviewed, auto)
}
