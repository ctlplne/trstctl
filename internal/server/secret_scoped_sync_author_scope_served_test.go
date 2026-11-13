// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// drainServedOutbox advances the projection checkpoint past the log head and
// drains the harness's due outbox work, three rounds, as the served sync
// tests do (this harness runs no live projector).
func drainServedOutbox(t *testing.T, h *servedHarness) {
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

// A237-L6 Done-when: the reconciler reads a source as the definition's author,
// and a grant change re-plans the definition like a source change. An author
// granted a restricted environment defines two auto syncs — one of that
// environment, one of the whole project — and the reconciler delivers both.
// Once the grant is revoked, the next pass (no source changed) records the
// first sync blocked, naming why; after the restricted secret is rotated and
// an open one added, the next pass delivers the open secret only: neither sync
// carries the restricted environment's new value.
func TestServedScopedSyncReconcilerReadsAsTheAuthorA237L6(t *testing.T) {
	target := &pushOnlyTarget{data: map[string]string{}}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"hook": secretsync.NewTarget("hook", target)}}
	})
	registerServedTenant(t, h, "A237-L6 author scope")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a237l6-admin", "access:write", "secrets:read", "secrets:write")
	author := seedScopedTokenSubject(t, h.store, h.tenant, "a237l6-author", "secrets:read", "secrets:write")
	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "a237l6-project", map[string]any{"slug": "a237l6vault", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "prod", "restricted": true}}}, http.StatusCreated)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/a237l6vault/members/a237l6-admin", "a237l6-grant-admin",
		map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/a237l6vault/members/a237l6-author", "a237l6-grant",
		map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(admin, http.MethodPost, "/api/v1/secrets/store", "a237l6-dev-api", map[string]any{"name": "a237l6vault/dev/api", "value": "dev-api-a237l6"}, http.StatusCreated)
	call(admin, http.MethodPost, "/api/v1/secrets/store", "a237l6-prod-db", map[string]any{"name": "a237l6vault/prod/db", "value": "prod-one-a237l6"}, http.StatusCreated)

	define := func(name, source, dest string) string {
		t.Helper()
		var def struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(call(author, http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l6-define-"+name, map[string]any{
			"name": name, "source_prefix": source, "target": "hook", "destination_prefix": dest, "adopt_existing": true, "mode": "auto",
		}, http.StatusCreated), &def); err != nil || def.ID == "" {
			t.Fatalf("define %s: %v", name, err)
		}
		return def.ID
	}
	prodSync := define("l6-prod", "a237l6vault/prod/", "prod")
	define("l6-all", "a237l6vault/", "all")
	reconcile := func() {
		t.Helper()
		if _, err := h.srv.ReconcileScopedSyncsOnce(t.Context()); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		drainServedOutbox(t, h)
	}
	reconcile()
	for key, want := range map[string]string{"prod/db": "prod-one-a237l6", "all/prod/db": "prod-one-a237l6", "all/dev/api": "dev-api-a237l6"} {
		if got, _ := target.value(key); got != want {
			t.Fatalf("after the first pass %s = %q, want %q", key, got, want)
		}
	}

	// The grant goes; nothing under the source changes.
	call(admin, http.MethodDelete, "/api/v1/secrets/projects/a237l6vault/members/a237l6-author", "a237l6-revoke", nil, http.StatusOK)
	reconcile()
	var view struct {
		ReconcileStatus string `json:"reconcile_status"`
		ReconcileReason string `json:"reconcile_reason"`
	}
	if err := json.Unmarshal(call(admin, http.MethodGet, "/api/v1/secrets/scoped-syncs/"+prodSync, "", nil, http.StatusOK), &view); err != nil {
		t.Fatal(err)
	}
	if view.ReconcileStatus != "blocked" || !strings.Contains(view.ReconcileReason, "no longer reads") {
		t.Fatalf("after the grant went the prod sync reads %+v; want blocked, naming the author's lost access", view)
	}

	call(admin, http.MethodPut, "/api/v1/secrets/store/a237l6vault/prod/db", "a237l6-rotate", map[string]any{"value": "prod-two-a237l6"}, http.StatusOK)
	call(admin, http.MethodPost, "/api/v1/secrets/store", "a237l6-dev-web", map[string]any{"name": "a237l6vault/dev/web", "value": "dev-web-a237l6"}, http.StatusCreated)
	reconcile()
	for key, want := range map[string]string{"prod/db": "prod-one-a237l6", "all/prod/db": "prod-one-a237l6", "all/dev/web": "dev-web-a237l6"} {
		if got, _ := target.value(key); got != want {
			t.Fatalf("after the source changed %s = %q, want %q", key, got, want)
		}
	}
}
