// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
)

type discoveryIntentProbeA267 struct {
	dynsecret.Provider
	calls  atomic.Int32
	verify func()
}

func (*discoveryIntentProbeA267) Name() string                      { return "owned-intent-ad" }
func (*discoveryIntentProbeA267) DynamicSecretProviderType() string { return "ldap" }
func (p *discoveryIntentProbeA267) DynamicSecretDiscoverAccounts(context.Context) ([]pamdiscovery.Account, error) {
	p.calls.Add(1)
	if p.verify != nil {
		p.verify()
	}
	return []pamdiscovery.Account{{Key: "user:reader", Name: "reader", Kind: pamdiscovery.KindDirectoryUser, Privileges: []string{"member:operators"}}}, nil
}
func TestServedADDiscoveryQueuesIntentBeforeProviderReadA267(t *testing.T) {
	provider := &discoveryIntentProbeA267{}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: []dynsecret.Provider{provider}}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	ctx := t.Context()
	token := seedScopedTokenSubject(t, h.store, h.tenant, "discovery-operator", "access:read", "access:targets.write")
	root := "/api/v1/access/discovery/sources/" + provider.Name()
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPut, root, token, "save-durable-ad-source", map[string]any{"interval_seconds": 0}); code != http.StatusOK {
		t.Fatalf("discovery source not saved: %d %s", code, body)
	}
	code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/runs", token, "queue-durable-ad-read", nil)
	var queued struct{ ID, Status string }
	if code != http.StatusAccepted || json.Unmarshal(raw, &queued) != nil || queued.Status != "queued" || queued.ID == "" || provider.calls.Load() != 0 {
		t.Fatalf("AD read ran in request path or has no queued identity: HTTP=%d body=%s reads=%d", code, raw, provider.calls.Load())
	}
	replayCode, replayRaw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/runs", token, "queue-durable-ad-read", nil)
	var replay struct{ ID, Status string }
	if replayCode != http.StatusAccepted || json.Unmarshal(replayRaw, &replay) != nil || replay.ID != queued.ID || replay.Status != "queued" || provider.calls.Load() != 0 {
		t.Fatal("queued scan idempotency performed a read or changed its identity")
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/runs", token, "another-pending-read", nil); code != http.StatusConflict {
		t.Fatal("same source admitted concurrent queued reads")
	}
	provider.verify = func() {
		t.Helper()
		var count int
		err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='pam.discovery.scan' AND idempotency_key=$2`, h.tenant, "pam-discovery:"+queued.ID).Scan(&count)
		if err != nil || count != 1 {
			t.Fatal("provider read has no exact committed outbox intent", err)
		}
	}
	if _, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("worker reads=%d want1", provider.calls.Load())
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+queued.ID, token, nil)
	var done struct {
		ID, Status string
		Accounts   int
	}
	if code != http.StatusOK || json.Unmarshal(raw, &done) != nil || done.ID != queued.ID || done.Status != "completed" || done.Accounts != 1 {
		t.Fatalf("queued read did not finish through source projection: %d %s", code, raw)
	}
	if _, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("completed read repeated")
	}
	intent, jobID, err := h.store.GetPAMDiscoveryScanIntent(ctx, h.tenant, queued.ID)
	if err != nil || jobID == nil {
		t.Fatal("completed scan lost its original request", err)
	}
	if _, err = h.store.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, *jobID); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(h.store)
	if err = projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal("source scan did not recover after exact operational-row loss", err)
	}
	if _, err = h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("replayed completed source repeated the provider read")
	}
	retained, ok, err := h.log.EventByID(ctx, intent.CompletionEventID)
	if err != nil || !ok || retained.Type != projections.EventPAMDiscoveryRunCompleted {
		t.Fatal("completed scan is not tied to its retained event", err)
	}

	// Derived bytes cannot change the provider read authorized by the source.
	queue := func(key string) string {
		t.Helper()
		code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/runs", token, key, nil)
		var value struct{ ID, Status string }
		if code != http.StatusAccepted || json.Unmarshal(raw, &value) != nil || value.Status != "queued" {
			t.Fatalf("queue after completion: %d %s", code, raw)
		}
		return value.ID
	}
	tamperedRun := queue("tampered-discovery-payload")
	frozen, currentJob, err := h.store.GetPAMDiscoveryScanIntent(ctx, h.tenant, tamperedRun)
	if err != nil || currentJob == nil {
		t.Fatal(err)
	}
	forged := []byte(`{"provider_id":"foreign-provider"}`)
	if _, err = h.store.SystemPool().Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, *currentJob, forged); err != nil {
		t.Fatal(err)
	}
	terminalWorker := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
	if _, err = terminalWorker.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("derived payload substituted a provider read")
	}
	code, failedRaw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+frozen.RunID, token, nil)
	var failed struct{ Status, Failure string }
	if code != http.StatusOK || json.Unmarshal(failedRaw, &failed) != nil || failed.Status != "failed" || failed.Failure != "delivery_failed" {
		t.Fatal("terminal discovery stayed queued")
	}
	if provider.calls.Load() != 1 {
		t.Fatal("terminal failure retried provider I/O")
	}
	// Saving the source after admission invalidates that request before I/O.
	changedRun := queue("source-revision-changed")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root, token, "change-discovery-source", map[string]any{"interval_seconds": 3600}); code != http.StatusOK {
		t.Fatal("source revision not updated")
	}
	if _, err = h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	code, changedRaw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+changedRun, token, nil)
	var changed struct{ Status, Failure string }
	if code != http.StatusOK || json.Unmarshal(changedRaw, &changed) != nil || changed.Status != "failed" || changed.Failure != "source_changed" || provider.calls.Load() != 1 {
		t.Fatalf("stale source read ran or lost its failure: %d %s", code, changedRaw)
	}

}

// A stock operator polls the admitted run. This test driver explicitly runs the
// real outbox worker; provider reads never occur in the HTTP request callback.
func awaitQueuedDiscoveryProofA267(t *testing.T, h *servedHarness, token, id string) a260Run {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
			t.Fatal(err)
		}
		code, raw := secretsReq(t, h, http.MethodGet, "/api/v1/access/discovery/runs/"+id, token, nil)
		var run a260Run
		if code != http.StatusOK || json.Unmarshal(raw, &run) != nil {
			t.Fatalf("queued discovery readback: %d %s", code, raw)
		}
		if run.Status != "queued" {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatal("queued source did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
