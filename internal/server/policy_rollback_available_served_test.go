// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestServedPolicyRollbackAvailabilityFollowsActualPredecessor(t *testing.T) {
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) { d.EnablePolicyGate = true })
	token := seedScopedTokenSubject(t, h.store, h.tenant, "rollback-reviewer", "policy:read", "policy:write")
	type version struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Active    bool   `json:"active"`
		Available bool   `json:"rollback_available"`
		From      string `json:"rollback_from_id"`
	}
	write := func(path, key string, body any, want int) version {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, path, token, key, body)
		if status != want {
			t.Fatalf("%s: %d %s", path, status, raw)
		}
		if status >= 400 {
			var problem struct {
				Status int    `json:"status"`
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(raw, &problem); err != nil || problem.Status != want || problem.Detail != "active policy version has no rollback target" {
				t.Fatalf("expected terminal rollback problem: %s", raw)
			}
			return version{}
		}
		var v version
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	active := func() version {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/policy/versions", token, nil)
		if status != 200 {
			t.Fatalf("list: %d %s", status, raw)
		}
		var list struct {
			Active version `json:"active"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		return list.Active
	}
	action := func(id, verb, key string, want int) version {
		return write("/api/v1/policy/versions/"+id+"/"+verb, key, map[string]any{"reason": "reviewed rollback availability"}, want)
	}
	draft := write("/api/v1/policy/versions", "draft", map[string]any{"module": "package trstctl.policy\ndefault allow := false"}, 201)
	if draft.Available {
		t.Fatal("draft claims a rollback predecessor")
	}
	first := action(draft.ID, "activate", "activate-first", 200)
	if !first.Available || !active().Available {
		t.Fatal("activated version hides its real rollback predecessor")
	}
	rolled := action(draft.ID, "rollback", "rollback-first", 200)
	if rolled.Available || rolled.Active {
		t.Fatal("inactive version offers rollback")
	}
	restored := active()
	if restored.ID == draft.ID || restored.From != draft.ID || restored.Available {
		t.Fatalf("restored version invents a predecessor: %+v", restored)
	}
	action(restored.ID, "rollback", "terminal-rollback", 409)
	if active().ID != restored.ID {
		t.Fatal("refused rollback changed authority")
	}
	action(draft.ID, "activate", "activate-second", 200)
	// The same restored record becomes reversible after a later activation.
	// Its historical rollback_from_id is not an authority test.
	again := action(restored.ID, "activate", "activate-restored", 200)
	if again.From != draft.ID || !again.Available || !active().Available {
		t.Fatalf("reactivated restored version lost its new predecessor: %+v", again)
	}
	action(restored.ID, "rollback", "rollback-restored", 200)
	if active().Available {
		t.Fatal("new restored record again has no predecessor")
	}
}
