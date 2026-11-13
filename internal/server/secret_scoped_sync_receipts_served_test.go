// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// pushOnlyTarget is a destination that takes writes but can't list, read
// back or delete its keys, as a CI variable store or a webhook does.
type pushOnlyTarget struct {
	mu   sync.Mutex
	data map[string]string
}

func (p *pushOnlyTarget) Push(_ context.Context, key string, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data[key] = string(value)
	return nil
}

func (p *pushOnlyTarget) value(key string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.data[key]
	return v, ok
}

// A237-L2 Done-when: a scoped sync can target a destination that can't list
// its keys, from its delivery receipts only. Defining it without
// adopt_existing is refused (a key the sync didn't write can't be seen and
// would be replaced), as is a delete scope (the target can't delete). The
// first plan creates both keys, saying so; applying delivers them, replacing
// the key the destination already held. The next plan reads both unchanged
// from their receipts; a rotated source plans an update and delivers it; a
// source deleted since plans its key orphaned, kept.
func TestServedScopedSyncToATargetThatCantListKeysA237L2(t *testing.T) {
	target := &pushOnlyTarget{data: map[string]string{"rcpt/b": "foreign-a237l2"}}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"hook": secretsync.NewTarget("hook", target)}}
	})
	registerServedTenant(t, h, "A237-L2 receipt-only scoped sync")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "a237l2-operator", "secrets:read", "secrets:write")
	request := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
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
	request(http.MethodPost, "/api/v1/secrets/store", "a237l2-a", map[string]any{"name": "rc237/prod/a", "value": "a-one-a237l2"}, http.StatusCreated)
	request(http.MethodPost, "/api/v1/secrets/store", "a237l2-b", map[string]any{"name": "rc237/prod/b", "value": "b-one-a237l2"}, http.StatusCreated)

	definition := map[string]any{"name": "rc237-prod", "source_prefix": "rc237/prod/", "target": "hook", "destination_prefix": "rcpt"}
	if raw := request(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l2-define-1", definition, http.StatusBadRequest); !strings.Contains(string(raw), "can't list its keys") ||
		!strings.Contains(string(raw), "adopt_existing") {
		t.Fatalf("a definition without adopt_existing was refused without naming why: %s", raw)
	}
	definition["adopt_existing"] = true
	definition["delete_scope"] = "managed"
	if raw := request(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l2-define-2", definition, http.StatusBadRequest); !strings.Contains(string(raw), "delete_scope is none") {
		t.Fatalf("a delete scope on a receipt-only target was refused without naming why: %s", raw)
	}
	delete(definition, "delete_scope")
	var def struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(request(http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l2-define-3", definition, http.StatusCreated), &def); err != nil || def.ID == "" {
		t.Fatalf("define: %v", err)
	}
	base := "/api/v1/secrets/scoped-syncs/" + def.ID
	type plan struct {
		PlanDigest string `json:"plan_digest"`
		Items      []struct {
			Key    string `json:"key"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"items"`
	}
	preview := func() (plan, string) {
		t.Helper()
		raw := request(http.MethodPost, base+"/preview", "", nil, http.StatusOK)
		var p plan
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "-a237l2") {
			t.Fatalf("the plan carries a value: %s", raw)
		}
		return p, string(raw)
	}
	expect := func(p plan, raw string, want map[string]string, reason string) {
		t.Helper()
		if len(p.Items) != len(want) {
			t.Fatalf("plan %s; want %v", raw, want)
		}
		for _, item := range p.Items {
			if want[item.Key] != item.Action || !strings.Contains(item.Reason, reason) {
				t.Fatalf("plan item %+v; want %v with a reason naming %q (plan %s)", item, want, reason, raw)
			}
		}
	}
	apply := func(key string, p plan) {
		t.Helper()
		request(http.MethodPost, base+"/apply", key, map[string]any{"plan_digest": p.PlanDigest}, http.StatusCreated)
		drain()
	}

	first, raw := preview()
	expect(first, raw, map[string]string{"rcpt/a": "create", "rcpt/b": "create"}, "receipt-only")
	apply("a237l2-apply-1", first)
	for key, want := range map[string]string{"rcpt/a": "a-one-a237l2", "rcpt/b": "b-one-a237l2"} {
		if got, _ := target.value(key); got != want {
			t.Fatalf("destination %s = %q, want %q", key, got, want)
		}
	}
	again, raw := preview()
	expect(again, raw, map[string]string{"rcpt/a": "unchanged", "rcpt/b": "unchanged"}, "receipt-only")

	request(http.MethodPut, "/api/v1/secrets/store/rc237/prod/a", "a237l2-rotate", map[string]any{"value": "a-two-a237l2"}, http.StatusOK)
	rotated, raw := preview()
	if len(rotated.Items) != 2 || rotated.Items[0].Key != "rcpt/a" || rotated.Items[0].Action != "update" || rotated.Items[1].Action != "unchanged" {
		t.Fatalf("after a rotation the plan = %s; want rcpt/a updated, rcpt/b unchanged", raw)
	}
	apply("a237l2-apply-2", rotated)
	if got, _ := target.value("rcpt/a"); got != "a-two-a237l2" {
		t.Fatalf("destination rcpt/a = %q after the update", got)
	}

	request(http.MethodDelete, "/api/v1/secrets/store/rc237/prod/b", "a237l2-delete-b", nil, http.StatusNoContent)
	gone, raw := preview()
	if len(gone.Items) != 2 || gone.Items[1].Key != "rcpt/b" || gone.Items[1].Action != "orphaned" ||
		!strings.Contains(gone.Items[1].Reason, "can't delete keys") {
		t.Fatalf("after the source went the plan = %s; want rcpt/b orphaned, kept", raw)
	}
	if _, ok := target.value("rcpt/b"); !ok {
		t.Fatal("the destination lost a key the sync can't delete")
	}
	if h.logContains(t, "a-two-a237l2") || h.logContains(t, "foreign-a237l2") {
		t.Fatal("the event log carries a value (AN-8)")
	}
}
