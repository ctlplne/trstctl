// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// a244l2Step is one review plan step as the application view returns it.
type a244l2Step struct {
	Action  string `json:"action"`
	Subject string `json:"subject"`
	Preview struct {
		State     string   `json:"state"`
		From      string   `json:"from"`
		To        string   `json:"to"`
		EventType string   `json:"event_type"`
		Ready     bool     `json:"ready"`
		WaitsOn   string   `json:"waits_on"`
		Refusals  []string `json:"refusals"`
		Warnings  []string `json:"warnings"`
		Policy    []string `json:"policy"`
		Readback  []string `json:"readback"`
	} `json:"preview"`
}

// TestServedApplicationReviewPlanCarriesTheTransitionPreviewA244L2 is
// A244-L2's Done-when (served): the review plan was derived from the bound
// configuration alone, not a dry run, so it said nothing of a refusal
// execution would meet. Each step now carries the effect-free transition
// preview's result. Under a profile that does not permit its DNS name, a
// requested certificate bound to a destination reads: issue previewed
// (requested → issued), not ready, refused with the profile and the name
// named, exactly as execution then refuses it (409 profile_refused, nothing
// recorded); deploy later (issued → deployed, its connector.deploy intent
// named) and verify both waiting on issue. Reading the view three times
// appends no event, enqueues no outbox intent and leaves the identity's
// state and version as they were. Under the profile's next version, which
// permits the name, issue is previewed ready with the preview's policy and
// readback and its other warnings apart from refusals; deploy and verify no
// longer wait.
// After the issue is accepted, issue reads accepted and deploy is previewed
// with the standalone preview's own prerequisites and verification steps.
func TestServedApplicationReviewPlanCarriesTheTransitionPreviewA244L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	// Its own tenant: its profiles are its own.
	const tenant = "a2440002-24a2-4a24-8a24-0000a2440002"
	registerServedTenantID(t, h, tenant, "A244-L2 tenant")
	tok := seedScopedTokenSubject(t, h.store, tenant, "a244l2-operator", "owners:read", "owners:write", "identities:read",
		"identities:write", "certs:read", "certs:issue", "connectors:read", "connectors:write", "profiles:read", "profiles:write")
	create := func(path, key string, body any) map[string]any {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, path, tok, key, body)
		var out map[string]any
		if status != http.StatusCreated || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("POST %s = %d %s", path, status, raw)
		}
		return out
	}
	const hostAgent = "a2440002-0000-4000-8000-00000000a001"
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: hostAgent, TenantID: tenant, Name: "a244l2-host", Status: "active", Roles: []string{"host"}}); err != nil {
		t.Fatal(err)
	}
	profile := func(suffix, key string) {
		t.Helper()
		create("/api/v1/profiles", key, map[string]any{"name": "a244l2-names", "spec": map[string]any{
			"max_validity": "720h", "allowed_protocols": []string{"api"},
			"allowed_dns_suffixes": []string{suffix}, "allowed_key_algorithms": []string{"ECDSA"},
		}})
	}
	profile("permitted.example.test", "a244l2-profile-v1")
	owner := create("/api/v1/owners", "a244l2-owner", map[string]any{"kind": "workload", "name": "a244l2-orders"})
	target := create("/api/v1/connectors/targets", "a244l2-target", map[string]any{
		"name": "a244l2 orders", "connector": "nginx", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": hostAgent,
			"cert_path": "/app/tls/a244l2.crt", "key_path": "/app/tls/a244l2.key", "verify_address": "127.0.0.1:9443"},
	})
	identity := create("/api/v1/identities", "a244l2-identity", map[string]any{
		"owner_id": owner["id"], "kind": "x509", "name": "a244l2.orders.test",
		"attributes": map[string]any{"deployment_target_id": target["id"], "profile_name": "a244l2-names"},
	})
	id := identity["id"].(string)

	plan := func(stage string) map[string]a244l2Step {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/application", tok, nil)
		var view struct {
			ReviewPlan []a244l2Step `json:"review_plan"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &view) != nil {
			t.Fatalf("%s: application view = %d %s", stage, status, raw)
		}
		steps := map[string]a244l2Step{}
		order := []string{}
		for _, s := range view.ReviewPlan {
			steps[s.Action] = s
			order = append(order, s.Action)
		}
		if !slices.Equal(order, []string{"issue", "deploy", "verify"}) {
			t.Fatalf("%s: review plan steps = %v", stage, order)
		}
		return steps
	}
	effects := func() (uint64, int, uint64, string) {
		t.Helper()
		seq, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var queued int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1`, tenant).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		current, version, err := h.store.IdentityApprovalTarget(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return seq, queued, version, current.Status
	}

	// The profile refuses the name: the issuance is refused, and the plan
	// says so.
	const refusal = `profile "a244l2-names" v1 does not permit DNS SAN "a244l2.orders.test"`
	seq0, queued0, version0, status0 := effects()
	var off map[string]a244l2Step
	for range 3 {
		off = plan("the name refused")
	}
	if seq, queued, version, status := effects(); seq != seq0 || queued != queued0 || version != version0 || status != status0 {
		t.Fatalf("reading the plan had effects: events %d→%d, outbox %d→%d, version %d→%d, status %s→%s",
			seq0, seq, queued0, queued, version0, version, status0, status)
	}
	issue := off["issue"].Preview
	if issue.State != "previewed" || issue.From != "requested" || issue.To != "issued" || issue.EventType != "identity.issued" ||
		issue.Ready || issue.WaitsOn != "" || len(issue.Refusals) != 1 || !strings.Contains(issue.Refusals[0], refusal) {
		t.Fatalf("issue under a profile refusing the name = %+v, want previewed, refused naming %s", issue, refusal)
	}
	for _, w := range issue.Warnings {
		if w == issue.Refusals[0] {
			t.Fatalf("the refusal also reads as a warning: %v", issue.Warnings)
		}
	}
	deploy := off["deploy"].Preview
	if deploy.State != "later" || deploy.From != "issued" || deploy.To != "deployed" || deploy.EventType != "identity.deployed" ||
		deploy.Ready || deploy.WaitsOn != "issue" || !strings.Contains(strings.Join(deploy.Policy, " "), "connector.deploy") {
		t.Fatalf("deploy with the issuance refused = %+v, want later, waiting on issue, its intent named", deploy)
	}
	verify := off["verify"].Preview
	if verify.State != "later" || verify.From != "" || verify.Ready || verify.WaitsOn != "issue" ||
		!strings.Contains(strings.Join(verify.Readback, " "), "127.0.0.1:9443") {
		t.Fatalf("verify with the issuance refused = %+v, want later, waiting on issue, reading back its endpoint", verify)
	}
	// Execution refuses it the same way, recording nothing.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "a244l2-issue-refused",
		map[string]any{"to": "issued", "reason": "A244-L2"}); status != http.StatusConflict || !strings.Contains(string(body), "profile_refused") ||
		!strings.Contains(string(body), "a244l2.orders.test") {
		t.Fatalf("issue under a profile refusing the name = %d %s, want 409 as the plan said", status, body)
	}
	if seq, _, _, status := effects(); seq != seq0 || status != "requested" {
		t.Fatalf("the refused issue had effects: events %d→%d, status %s", seq0, seq, status)
	}

	// The profile's next version permits the name: the issuance would go
	// ahead.
	profile("orders.test", "a244l2-profile-v2")
	on := plan("the name permitted")
	issue = on["issue"].Preview
	policy, readback, warnings := strings.Join(issue.Policy, " "), strings.Join(issue.Readback, " "), strings.Join(issue.Warnings, " ")
	if issue.State != "previewed" || !issue.Ready || len(issue.Refusals) != 0 || issue.WaitsOn != "" ||
		!strings.Contains(policy, "Issuing authority:") || !strings.Contains(policy, "identities:write") ||
		!strings.Contains(readback, "/api/v1/identities/"+id) || !strings.Contains(readback, "identity.issued") ||
		!strings.Contains(warnings, "No issuing authority is pinned") {
		t.Fatalf("issue under a profile permitting the name = %+v, want previewed ready with its policy, readback and warnings", issue)
	}
	if d, v := on["deploy"].Preview, on["verify"].Preview; !d.Ready || d.WaitsOn != "" || !v.Ready || v.WaitsOn != "" {
		t.Fatalf("deploy/verify with the issuance ready = %+v / %+v, want neither waiting", d, v)
	}

	// The issue is accepted: issue reads accepted, deploy is previewed as the
	// standalone preview previews it.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "a244l2-issue",
		map[string]any{"to": "issued", "reason": "A244-L2"}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("issue under a profile permitting the name = %d %s", status, body)
	}
	accepted := plan("issue accepted")
	if a := accepted["issue"].Preview; a.State != "accepted" || a.From != "requested" || a.To != "issued" || !a.Ready ||
		!strings.Contains(strings.Join(a.Readback, " "), "confirm status is issued") {
		t.Fatalf("issue once accepted = %+v", a)
	}
	status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions/preview", tok, map[string]any{"to": "deployed", "reason": "A244-L2"})
	var standalone struct {
		Ready             bool     `json:"ready"`
		Prerequisites     []string `json:"prerequisites"`
		VerificationSteps []string `json:"verification_steps"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &standalone) != nil {
		t.Fatalf("standalone deploy preview = %d %s", status, raw)
	}
	deploy = accepted["deploy"].Preview
	if deploy.State != "previewed" || deploy.From != "issued" || deploy.To != "deployed" || deploy.Ready != standalone.Ready ||
		!slices.Equal(deploy.Policy, standalone.Prerequisites) || !slices.Equal(deploy.Readback, standalone.VerificationSteps) {
		t.Fatalf("deploy once issued = %+v, want the standalone preview's %+v", deploy, standalone)
	}
	t.Log("A244L2_OK")
}
