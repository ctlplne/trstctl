// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
)

// draftingModel answers every prompt with one fixed text and keeps the
// prompts it was sent.
type draftingModel struct {
	mu      sync.Mutex
	answer  string
	prompts []string
}

func (m *draftingModel) Name() string { return "stub-drafter" }

func (m *draftingModel) Complete(_ context.Context, prompt string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prompts = append(m.prompts, prompt)
	return m.answer, nil
}

func (m *draftingModel) take() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.prompts
	m.prompts = nil
	return out
}

func draftableChangeSet() api.ChangeSet {
	return api.ChangeSet{
		Name:     "onboard billing",
		Profiles: []api.BaselineProfile{{Name: "billing-web", Spec: json.RawMessage(`{"allowed_key_algorithms":["ECDSA"],"allowed_protocols":["acme"],"max_validity":"720h"}`)}},
		Members:  []api.BaselineMember{{Subject: "dev@billing.example", Roles: []string{"viewer"}}},
		Owners:   []api.ChangeOwner{{Key: "billing", Kind: "team", Name: "Billing", ApplicationID: "app-7", Environment: "staging"}},
	}
}

// A248: an AI draft is the same typed change set a form or an API call
// writes, and goes through the same plan: the same objects plan to the same
// digests. The model is sent the request and the tenant's names, never a
// spec, a config, an email or a secret; a request carrying a secret is
// refused before the model is called, and anything secret-shaped the guard
// lets through is redacted before it leaves.
func TestServedChangeSetDraftsA248(t *testing.T) {
	model := &draftingModel{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableAISurface = true
		d.AIModel = aimodel.New(model, nil)
	})
	author := seedScopedTokenSubject(t, h.store, h.tenant, "draft-author", "changes:write",
		"profiles:write", "owners:write", "access:role.assign", "connectors:write")
	// Names the catalog shows, next to values it must never send.
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", author, "a248-existing-profile",
		map[string]any{"name": "existing-web", "spec": map[string]any{"allowed_protocols": []string{"acme"}, "max_validity": "1h", "description": "canary-spec-value"}}); code != http.StatusCreated {
		t.Fatalf("seed profile = %d %s", code, body)
	}
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", author, "a248-existing-owner",
		map[string]any{"kind": "team", "name": "existing-platform-team", "email": "owner-canary@example.com"}); code != http.StatusCreated {
		t.Fatalf("seed owner = %d %s", code, body)
	}
	set := draftableChangeSet()
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	model.answer = "Here is the change set:\n```json\n" + string(raw) + "\n```"
	draft := func(request string) (int, api.ChangeDraft, string) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/draft", author, "", map[string]any{"request": request})
		var d api.ChangeDraft
		if code == http.StatusOK {
			if err := json.Unmarshal(body, &d); err != nil {
				t.Fatal(err)
			}
		}
		return code, d, string(body)
	}

	// A request carrying a secret never reaches the model.
	for _, request := range []string{
		"onboard billing with this key -----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
		"onboard billing; the deploy token is trst_" + strings.Repeat("Z", 40),
		"onboard billing using password=hunter2 for the load balancer",
	} {
		if code, _, body := draft(request); code != http.StatusUnprocessableEntity || !strings.Contains(body, "never paste one") {
			t.Fatalf("a secret-bearing request = %d %s", code, body)
		}
	}
	if sent := model.take(); len(sent) != 0 {
		t.Fatalf("the model was called %d times for secret-bearing requests", len(sent))
	}

	// A draft plans like the API: same intent, same digests.
	code, drafted, body := draft("onboard billing: a billing team owner for app-7 in staging, a billing-web profile, and viewer for dev@billing.example")
	if code != http.StatusOK || drafted.Plan == nil || drafted.Refused != "" || drafted.Model != "stub-drafter" {
		t.Fatalf("draft = %d %s", code, body)
	}
	pcode, pbody := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/plan", author, "", set)
	var planned api.ChangePlan
	if pcode != http.StatusOK || json.Unmarshal(pbody, &planned) != nil {
		t.Fatalf("API plan = %d %s", pcode, pbody)
	}
	if drafted.Plan.ChangeSetDigest != planned.ChangeSetDigest || drafted.Plan.PlanDigest != planned.PlanDigest {
		t.Fatalf("the draft and the API planned the same set differently: %s/%s vs %s/%s",
			drafted.Plan.ChangeSetDigest, drafted.Plan.PlanDigest, planned.ChangeSetDigest, planned.PlanDigest)
	}
	prompts := model.take()
	if len(prompts) != 1 {
		t.Fatalf("the model was called %d times for one draft", len(prompts))
	}
	prompt := prompts[0]
	// Names that read as people's are redacted at the model boundary (the
	// adapter's PII policy); these are not.
	for _, name := range []string{"existing-web", "existing-platform-team", "viewer", "onboard billing"} {
		if !strings.Contains(prompt, name) {
			t.Fatalf("the prompt lacks the catalog name %q:\n%s", name, prompt)
		}
	}
	for _, value := range []string{"canary-spec-value", "owner-canary@example.com"} {
		if strings.Contains(prompt, value) {
			t.Fatalf("the prompt carried %q, a value the catalog never sends:\n%s", value, prompt)
		}
	}

	// A secret-shaped run the guard lets through is redacted before it leaves.
	raw32 := "q8Zt3VnC1LkP0aYwR7sHf2JdXm9GbE4u"
	if code, _, body := draft("onboard billing; the ticket attachment checksum is " + raw32); code != http.StatusOK {
		t.Fatalf("draft with a high-entropy run = %d %s", code, body)
	}
	if sent := model.take(); len(sent) != 1 || strings.Contains(sent[0], raw32) {
		t.Fatalf("the high-entropy run reached the model: %q", sent)
	}

	// An answer that is not a change set does not plan.
	model.answer = `{"name": "x", "secret_values": ["nope"]}`
	if code, _, body := draft("onboard billing"); code != http.StatusUnprocessableEntity || !strings.Contains(body, "not a change set") {
		t.Fatalf("a malformed draft = %d %s", code, body)
	}
}

// A248: with no model configured, drafting answers 503 and the form, API and
// GitOps paths plan and apply as before.
func TestServedChangeSetsWorkWithoutAModelA248(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	author := seedScopedTokenSubject(t, h.store, h.tenant, "plain-author", "changes:write",
		"profiles:write", "owners:write", "access:role.assign")
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/draft", author, "", map[string]any{"request": "onboard billing"}); code != http.StatusServiceUnavailable || !strings.Contains(string(body), "form, API or GitOps") {
		t.Fatalf("draft without a model = %d %s", code, body)
	}
	set := draftableChangeSet()
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/plan", author, "", set)
	var plan api.ChangePlan
	if code != http.StatusOK || json.Unmarshal(body, &plan) != nil || plan.Changes != 3 {
		t.Fatalf("plan without a model = %d %s", code, body)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/apply", author, "a248-no-model-apply", api.ChangeApplyRequest{ChangeSet: set, PlanDigest: plan.PlanDigest})
	var applied api.ChangeApplication
	if code != http.StatusOK || json.Unmarshal(body, &applied) != nil || !applied.Complete {
		t.Fatalf("apply without a model = %d %s", code, body)
	}
}
