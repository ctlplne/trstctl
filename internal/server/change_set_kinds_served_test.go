// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

// TestServedChangeSetKindsPlanApplyAndRollBackA248L3 is A248-L3's Done-when
// (served): the lifecycle policy, notification channels, report schedules,
// agent role grants and secrets projects are change set kinds. Each plans
// with what applying would do, binds the plan digest, applies through the
// operator's own command, reads back from the tenant's records and plans
// unchanged afterwards. Each apply returns the change set that puts back what
// it updated, and names what it created (which a change set does not
// remove); planning and applying that rollback restores every updated
// object. A secret value in any new kind is refused, and a draft holding one
// is withheld, never echoed.
func TestServedChangeSetKindsPlanApplyAndRollBackA248L3(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	model := &draftingModel{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.AuditArchiveDir = archiveRoot
		d.EnableSecretsAPI = true
		d.EnableAISurface = true
		d.AIModel = aimodel.New(model, nil)
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(&reportWorkerSigner{key: key}))
	})
	ctx := t.Context()
	// Its own tenant: its policy module, channels and projects are its own.
	const tenant = "a2480003-48a3-4a48-8a48-0000a2480003"
	registerServedTenantID(t, h, tenant, "A248-L3 tenant")
	author := seedScopedTokenSubject(t, h.store, tenant, "a248l3-author", "changes:write", "policy:write", "policy:read",
		"notifications:write", "audit:write", "agents:relay.grant", "access:write", "secrets:read", "owners:read")
	const agentID = "a2480003-0000-4000-8000-00000000a003"
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: agentID, TenantID: tenant, Name: "a248l3-edge", Status: "active", Roles: []string{"host"}}); err != nil {
		t.Fatal(err)
	}

	plan := func(set api.ChangeSet) (int, api.ChangePlan, string) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/plan", author, "", set)
		var p api.ChangePlan
		if code == http.StatusOK {
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
		}
		return code, p, string(body)
	}
	apply := func(key string, set api.ChangeSet, digest string) api.ChangeApplication {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/apply", author, key, api.ChangeApplyRequest{ChangeSet: set, PlanDigest: digest})
		var out api.ChangeApplication
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil || !out.Complete {
			t.Fatalf("apply %s = %d %s", key, code, body)
		}
		for _, r := range out.Results {
			if !r.Verified {
				t.Fatalf("apply %s: %s %s did not read back: %+v", key, r.Kind, r.Key, r)
			}
		}
		return out
	}
	items := func(p api.ChangePlan) map[string]api.ChangePlanItem {
		out := map[string]api.ChangePlanItem{}
		for _, item := range p.Items {
			out[item.Kind] = item
		}
		return out
	}
	enabled := true
	module := policy.BaseModule + `
certificate_posture contains {"rule": "a248l3-rule", "severity": "low", "reason": "A248-L3"} if {
	input.action == "certificate_posture"
	input.certificate.issuer == "CN=A248-L3 Example CA"
}
`
	first := api.ChangeSet{
		Name:                 "a248l3 platform",
		Policy:               &api.BaselinePolicy{Module: module, Description: "A248-L3 policy"},
		NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: "https://hooks.example.com/a248l3", CredentialRef: "secret://notifications/a248l3", Enabled: &enabled}},
		ReportSchedules: []api.BaselineReportSchedule{{Key: "weekly-risk", Name: "weekly crypto risk", Framework: "nist-800-53", ReportType: "crypto_risk",
			IntervalSeconds: 7 * 24 * 3600, Dispatch: &store.ComplianceReportDispatch{Channels: []string{"webhook"}}}},
		AgentRoles: []api.ChangeAgentRoles{{AgentID: agentID, Roles: []string{"network", "host"}}},
		SecretProjects: []api.ChangeSecretProject{{Slug: "a248l3-pay", Name: "Payments", Environments: []api.ChangeSecretEnvironment{
			{Slug: "dev"}, {Slug: "prod", Restricted: true}},
			Members: []api.ChangeSecretProjectMember{{Subject: "dev@a248l3.example", Role: "developer", Environments: []string{"dev"}}}}},
	}
	// The policy step reads the module the tenant enforces now.
	if code, _, body := plan(api.ChangeSet{Name: "probe", Policy: &api.BaselinePolicy{Module: module}}); code != http.StatusOK {
		t.Fatalf("plan a policy alone = %d %s", code, body)
	}
	// The channel's credential reference must name a stored secret the author can read.
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", seedScopedTokenSubject(t, h.store, tenant, "a248l3-writer", "secrets:write"),
		"a248l3-cred", map[string]any{"name": "notifications/a248l3", "value": "a248l3-webhook-key-value"}); code != http.StatusCreated {
		t.Fatalf("store the webhook's credential = %d %s", code, body)
	}

	// Plan: every kind says what applying does.
	code, planned, body := plan(first)
	if code != http.StatusOK || planned.Changes != 5 || len(planned.Items) != 5 {
		t.Fatalf("plan = %d %s", code, body)
	}
	got := items(planned)
	if p := got[api.BaselineKindPolicy]; p.Action != api.ChangeUpdate || !slices.Contains(p.Effects, "policy.version.activated") {
		t.Fatalf("policy item = %+v", p)
	}
	if c := got[api.BaselineKindNotificationChannel]; c.Action != api.ChangeCreate || len(c.Destinations) != 1 ||
		!strings.Contains(c.Destinations[0], "https://hooks.example.com/a248l3") || len(c.Credentials) != 1 ||
		!strings.Contains(c.Credentials[0], "secret://notifications/a248l3") {
		t.Fatalf("channel item = %+v", c)
	}
	if s := got[api.BaselineKindReportSchedule]; s.Action != api.ChangeCreate || len(s.Destinations) != 1 || !strings.Contains(s.Destinations[0], "webhook") {
		t.Fatalf("schedule item = %+v", s)
	}
	scheduleID := got[api.BaselineKindReportSchedule].ObjectID
	if a := got[api.ChangeKindAgentRoles]; a.Action != api.ChangeUpdate || len(a.Grants) != 1 || a.Grants[0] != "roles host, network (now host)" ||
		!slices.Contains(a.Effects, "agent.roles.granted") {
		t.Fatalf("agent roles item = %+v", a)
	}
	if p := got[api.ChangeKindSecretProject]; p.Action != api.ChangeCreate || !slices.Contains(p.Effects, "secret.project.created") ||
		!slices.Contains(p.Grants, "dev@a248l3.example developer on dev (now no grant)") {
		t.Fatalf("secrets project item = %+v", p)
	}

	// Apply: each kind written and read back; the rollback puts back what
	// was updated and names what was created.
	applied := apply("a248l3-apply-1", first, planned.PlanDigest)
	if applied.Rollback == nil || applied.Rollback.Policy == nil || len(applied.Rollback.AgentRoles) != 1 ||
		!slices.Equal(applied.Rollback.AgentRoles[0].Roles, []string{"host"}) || len(applied.Rollback.NotificationChannels) != 0 {
		t.Fatalf("first rollback = %+v", applied.Rollback)
	}
	created := map[string]string{}
	for _, n := range applied.NotRestored {
		created[n.Kind] = n.Reason
	}
	if !strings.Contains(created[api.BaselineKindNotificationChannel], "DELETE /api/v1/notification-channels/webhook") ||
		!strings.Contains(created[api.BaselineKindReportSchedule], "/pause") || !strings.Contains(created[api.ChangeKindSecretProject], "created by this apply") {
		t.Fatalf("not restored = %+v", applied.NotRestored)
	}
	if c, err := h.store.GetNotificationChannel(ctx, tenant, "webhook"); err != nil || c.EndpointURL != "https://hooks.example.com/a248l3" || c.CredentialRef != "secret://notifications/a248l3" {
		t.Fatalf("channel read back = %+v %v", c, err)
	}
	if grant, found, err := h.store.AgentRoleGrant(ctx, tenant, agentID); err != nil || !found || !slices.Equal(grant.Roles, []string{"host", "network"}) {
		t.Fatalf("agent role grant = %+v %v %v", grant, found, err)
	}
	if _, envs, members, err := h.store.GetSecretProject(ctx, tenant, "a248l3-pay"); err != nil || len(envs) != 2 || !envs[1].Restricted ||
		len(members) != 1 || members[0].Role != "developer" || !slices.Equal(members[0].Environments, []string{"dev"}) {
		t.Fatalf("secrets project = %+v %+v %v", envs, members, err)
	}
	if code, again, body := plan(first); code != http.StatusOK || again.Changes != 0 {
		t.Fatalf("re-plan after apply = %d %s", code, body)
	}

	// Update every kind but the policy; the rollback puts each back.
	second := first
	second.Name, second.Policy = "a248l3 changes", nil
	second.NotificationChannels = []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: "https://hooks.example.com/a248l3-v2", CredentialRef: "secret://notifications/a248l3", Enabled: &enabled}}
	second.ReportSchedules = []api.BaselineReportSchedule{{Key: "weekly-risk", Name: "weekly crypto risk", Framework: "nist-800-53", ReportType: "crypto_risk",
		IntervalSeconds: 24 * 3600, Dispatch: &store.ComplianceReportDispatch{Channels: []string{"webhook"}}}}
	second.AgentRoles = []api.ChangeAgentRoles{{AgentID: agentID, Roles: []string{"network"}}}
	second.SecretProjects = []api.ChangeSecretProject{{Slug: "a248l3-pay", Environments: []api.ChangeSecretEnvironment{
		{Slug: "dev", Name: "Development"}, {Slug: "prod", Restricted: true}, {Slug: "stage"}},
		Members: []api.ChangeSecretProjectMember{{Subject: "dev@a248l3.example", Role: "viewer"}, {Subject: "ops@a248l3.example", Role: "admin", Environments: []string{"prod"}}}}}
	code, planned, body = plan(second)
	if code != http.StatusOK || planned.Changes != 4 {
		t.Fatalf("plan the changes = %d %s", code, body)
	}
	if p := items(planned)[api.ChangeKindSecretProject]; p.Action != api.ChangeUpdate || !slices.Contains(p.Destinations, "adds environment stage (open)") ||
		!slices.Contains(p.Destinations, "renames environment dev to Development") || !slices.Contains(p.Grants, "dev@a248l3.example viewer on every environment (now developer on dev)") {
		t.Fatalf("secrets project update item = %+v", p)
	}
	changed := apply("a248l3-apply-2", second, planned.PlanDigest)
	rb := changed.Rollback
	if rb == nil || len(rb.NotificationChannels) != 1 || rb.NotificationChannels[0].EndpointURL != "https://hooks.example.com/a248l3" ||
		len(rb.ReportSchedules) != 1 || rb.ReportSchedules[0].IntervalSeconds != 7*24*3600 || len(rb.AgentRoles) != 1 ||
		!slices.Equal(rb.AgentRoles[0].Roles, []string{"host", "network"}) || len(rb.SecretProjects) != 1 || rb.Policy != nil {
		t.Fatalf("second rollback = %+v", rb)
	}
	if len(changed.NotRestored) != 1 || changed.NotRestored[0].Kind != api.ChangeKindSecretProject ||
		!strings.Contains(changed.NotRestored[0].Reason, "environment stage added by this apply stays") ||
		!strings.Contains(changed.NotRestored[0].Reason, "the name given to environment dev stays") {
		t.Fatalf("second not restored = %+v", changed.NotRestored)
	}
	if strings.Contains(mustJSON(t, changed), "a248l3-webhook-key-value") {
		t.Fatal("the apply's response carries the credential's value")
	}
	if c, _ := h.store.GetNotificationChannel(ctx, tenant, "webhook"); c.EndpointURL != "https://hooks.example.com/a248l3-v2" {
		t.Fatalf("the channel was not updated: %+v", c)
	}

	// The rollback plans and applies like any other change set.
	code, planned, body = plan(*rb)
	if code != http.StatusOK || planned.Changes != 4 {
		t.Fatalf("plan the rollback = %d %s", code, body)
	}
	apply("a248l3-rollback-2", *rb, planned.PlanDigest)
	if c, _ := h.store.GetNotificationChannel(ctx, tenant, "webhook"); c.EndpointURL != "https://hooks.example.com/a248l3" {
		t.Fatalf("the rollback left the channel at %+v", c)
	}
	if s, err := h.store.GetComplianceReportSchedule(ctx, tenant, scheduleID); err != nil || s.IntervalSeconds != 7*24*3600 {
		t.Fatalf("the rollback left the schedule at %+v %v", s, err)
	}
	if grant, _, _ := h.store.AgentRoleGrant(ctx, tenant, agentID); !slices.Equal(grant.Roles, []string{"host", "network"}) {
		t.Fatalf("the rollback left the agent's roles at %v", grant.Roles)
	}
	// The environment the second apply added, and the name it gave dev, stay
	// (as its not-restored note said).
	if _, envs, members, err := h.store.GetSecretProject(ctx, tenant, "a248l3-pay"); err != nil || len(envs) != 3 || envs[0].Name != "Development" ||
		len(members) != 1 || members[0].Subject != "dev@a248l3.example" || members[0].Role != "developer" || !slices.Equal(members[0].Environments, []string{"dev"}) {
		t.Fatalf("the rollback left the project at %+v %+v %v", envs, members, err)
	}
	// The first apply's rollback puts back the policy the tenant enforced
	// before (the boot module) and the agent's roles.
	probe := api.ChangeSet{Name: "probe", Policy: &api.BaselinePolicy{Module: module}}
	if _, p, body := plan(probe); items(p)[api.BaselineKindPolicy].Action != api.ChangeUnchanged {
		t.Fatalf("the A248-L3 module is not the enforced one before the rollback: %s", body)
	}
	code, planned, body = plan(*applied.Rollback)
	if code != http.StatusOK {
		t.Fatalf("plan the first rollback = %d %s", code, body)
	}
	apply("a248l3-rollback-1", *applied.Rollback, planned.PlanDigest)
	if grant, _, _ := h.store.AgentRoleGrant(ctx, tenant, agentID); !slices.Equal(grant.Roles, []string{"host"}) {
		t.Fatalf("the first rollback left the agent's roles at %v", grant.Roles)
	}
	if _, p, body := plan(probe); items(p)[api.BaselineKindPolicy].Action != api.ChangeUpdate {
		t.Fatalf("the first rollback left the A248-L3 module enforced: %s", body)
	}

	// A secret value in a new kind never plans, and a draft holding one is
	// withheld.
	token := "trst_" + strings.Repeat("W", 40)
	for name, set := range map[string]api.ChangeSet{
		"a channel credential": {Name: "leak", NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: "https://hooks.example.com/x", CredentialRef: "secret://" + token}}},
		"an agent role":        {Name: "leak", AgentRoles: []api.ChangeAgentRoles{{AgentID: agentID, Roles: []string{token}}}},
		"a project member":     {Name: "leak", SecretProjects: []api.ChangeSecretProject{{Slug: "leak", Environments: []api.ChangeSecretEnvironment{{Slug: "dev"}}, Members: []api.ChangeSecretProjectMember{{Subject: token, Role: "viewer"}}}}},
	} {
		if code, _, body := plan(set); code != http.StatusUnprocessableEntity || !strings.Contains(body, "never secret values") || strings.Contains(body, token) {
			t.Fatalf("%s holding a secret = %d %s", name, code, body)
		}
	}
	leak, err := json.Marshal(api.ChangeSet{Name: "drafted channel", NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook",
		EndpointURL: "https://hooks.example.com/drafted", CredentialRef: token}}})
	if err != nil {
		t.Fatal(err)
	}
	model.answer = string(leak)
	code, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/draft", author, "", map[string]any{"request": "add a webhook channel for alerts"})
	var drafted api.ChangeDraft
	if code != http.StatusOK || json.Unmarshal(raw, &drafted) != nil || drafted.Plan != nil || !strings.Contains(drafted.Refused, "withheld") ||
		strings.Contains(string(raw), token) || len(drafted.ChangeSet.NotificationChannels) != 0 {
		t.Fatalf("a draft holding a secret = %d %s", code, raw)
	}
	prompts := model.take()
	if len(prompts) != 1 || !strings.Contains(prompts[0], "a248l3-edge ("+agentID+")") || !strings.Contains(prompts[0], "a248l3-pay") ||
		!strings.Contains(prompts[0], "notification_channels") {
		t.Fatalf("the draft prompt lacks the new kinds or their catalog names: %q", prompts)
	}
	t.Log("A248L3_OK")
}
