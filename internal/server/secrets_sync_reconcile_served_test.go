// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// kvV2LossyFixture is a Vault KV v2 receiver whose response to the first write
// is lost after the write committed, and whose next read also fails, so the
// worker's first attempt ends ambiguous and its second attempt must prove the
// receiver state by reading it back.
type kvV2LossyFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
	ver    map[string]int
	// loseWrite drops the response of the next committed write.
	loseWrite bool
	// failReads fails this many reads after a lost write before recovering.
	failReads int
	writes    int
	reads     int
}

func newKVV2LossyFixture(t *testing.T) *kvV2LossyFixture {
	t.Helper()
	f := &kvV2LossyFixture{values: map[string]string{}, ver: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *kvV2LossyFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != "vault-token" {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	const prefix = "/v1/kv/data/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		f.reads++
		if f.failReads > 0 {
			f.failReads--
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		value, ok := f.values[path]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": map[string]string{"value": value}, "metadata": map[string]int{"version": f.ver[path]},
		}})
	case http.MethodPost:
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(raw, &req); err != nil || req.Data["value"] == "" {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		if req.Options.CAS != f.ver[path] {
			http.Error(w, `{"errors":["check-and-set parameter did not match the current version"]}`, http.StatusBadRequest)
			return
		}
		f.writes++
		f.values[path] = req.Data["value"]
		f.ver[path]++
		if f.loseWrite {
			f.loseWrite = false
			http.Error(w, "upstream timeout", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]int{"version": f.ver[path]}})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (f *kvV2LossyFixture) value(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[path]
}

// ciLossyFixture is a generic CI JSON receiver with no readable state: its
// first write commits but loses its response. trstctl can never read it back,
// so only an operator who checked the destination can settle the command.
type ciLossyFixture struct {
	server    *httptest.Server
	mu        sync.Mutex
	values    map[string]string
	loseWrite bool
	writes    int
}

func newCILossyFixture(t *testing.T) *ciLossyFixture {
	t.Helper()
	f := &ciLossyFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *ciLossyFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer ci-token" {
		http.Error(w, "refused", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Provider     string `json:"provider"`
		Key          string `json:"key"`
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Key == "" {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.EncodedValue)
	if err != nil {
		http.Error(w, "encoded_value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	f.values[req.Key] = string(decoded)
	if f.loseWrite {
		f.loseWrite = false
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *ciLossyFixture) value(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[key]
}

// drainSecretSyncUntil runs the outbox until the job leaves the pending state or
// the attempt budget runs out, rearming backoff between passes the way elapsed
// wall time would.
func drainSecretSyncUntil(t *testing.T, h *servedHarness, jobID string, want store.SecretSyncJobStatus, passes int) store.SecretSyncJob {
	t.Helper()
	var job store.SecretSyncJob
	for i := 0; i < passes; i++ {
		catchUpServedProjection(t, h)
		drainCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		err := h.srv.Drain(drainCtx)
		cancel()
		if err != nil {
			t.Fatalf("drain pass %d: %v", i+1, err)
		}
		var loadErr error
		job, loadErr = h.store.GetSecretSyncJob(t.Context(), h.tenant, jobID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if job.Status == want {
			return job
		}
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`, h.tenant, job.OutboxID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return job
}

// Run 1 lead defect:secret-sync-v6-predecessor-receipt: a later version stayed
// queued behind a predecessor whose receiver call may have started without a
// bound receipt proving its outcome. The worker must reconcile the exact
// receiver operation and release the lane without duplicate delivery; a target
// that cannot read itself back must offer the operator a served reconciliation.
func TestServedSecretSyncReconcilesLostReceiverResultAndReleasesSuccessor(t *testing.T) {
	vault := newKVV2LossyFixture(t)
	ci := newCILossyFixture(t)
	vaultPusher, err := secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
		Endpoint: vault.server.URL, HTTPClient: vault.server.Client(), Token: []byte("vault-token"), Mount: "kv", Field: "value",
	})
	if err != nil {
		t.Fatal(err)
	}
	ciPusher, err := secretsync.NewCIPusher(secretsync.CIPusherConfig{Endpoint: ci.server.URL, HTTPClient: ci.server.Client(), BearerToken: []byte("ci-token")})
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {
			"vault": secretsync.NewVaultKVV2Target(vaultPusher),
			"ci":    secretsync.NewCITarget(ciPusher),
		}}
	})
	registerServedTenant(t, h, "secret-sync reconciliation tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "sync-reconciler", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "sync/db", "value": "sync-v1"}); status != http.StatusCreated {
		t.Fatalf("create secret: %d %s", status, body)
	}
	queueSync := func(target, remote, idem string) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, idem, map[string]any{"name": "sync/db", "target": target, "remote_key": remote})
		if status != http.StatusOK {
			t.Fatalf("queue %s sync: %d %s", target, status, body)
		}
		return currentSecretSyncJobIDForTest(t, h.store, h.tenant, idem)
	}
	readJob := func(id string) map[string]any {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/syncs/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read job %s: %d %s", id, status, body)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	authority := func(id string) store.SecretSyncReceiverAuthority {
		t.Helper()
		a, err := h.store.SecretSyncReceiverAuthority(t.Context(), h.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// Vault: the first write commits but its response is lost and the readback
	// right after it fails too, so attempt one ends ambiguous. Attempt two reads
	// the value back, delivers without a second write, and settles the lane.
	vault.loseWrite, vault.failReads = true, 1
	v1 := queueSync("vault", "db/password", "vault-v1")
	job := drainSecretSyncUntil(t, h, v1, store.SecretSyncJobDelivered, 4)
	if job.Status != store.SecretSyncJobDelivered {
		t.Fatalf("vault v1 = %+v, want delivered after the lost result", job)
	}
	if got := vault.value("db/password"); got != "sync-v1" || vault.writes != 1 {
		t.Fatalf("vault holds %q after %d writes; want sync-v1 from exactly one write", got, vault.writes)
	}
	if a := authority(v1); a.ReceiverIOStarts < 2 || a.EffectState != store.SecretSyncReceiverEffectSettled {
		settleErr := h.srv.secretIntegrations.settleSecretSyncAfterDelivery(t.Context(), h.tenant, v1)
		t.Fatalf("vault v1 authority = %+v, want a settled multi-start delivery; reads=%d writes=%d settle=%v", a, vault.reads, vault.writes, settleErr)
	}
	if !h.hasEvent(t, "secret.sync.receiver_settled") {
		t.Fatal("settlement left no retained receipt")
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/sync/db", tok, map[string]any{"value": "sync-v2"}); status != http.StatusOK {
		t.Fatalf("rotate secret: %d %s", status, body)
	}
	v2 := queueSync("vault", "db/password", "vault-v2")
	if job := drainSecretSyncUntil(t, h, v2, store.SecretSyncJobDelivered, 2); job.Status != store.SecretSyncJobDelivered {
		predecessor, found, predErr := h.store.SecretSyncBlockingPredecessor(t.Context(), h.tenant, v2)
		v2Outbox, _ := h.srv.outbox.Get(t.Context(), h.tenant, job.OutboxID)
		t.Fatalf("vault v2 status=%s attempts=%d outbox=%s/%s; v1 authority=%+v; predecessor=%q found=%v err=%v",
			job.Status, job.Attempts, v2Outbox.Status, v2Outbox.LastError, authority(v1), predecessor, found, predErr)
	}
	if got := vault.value("db/password"); got != "sync-v2" {
		t.Fatalf("vault holds %q, want the later version", got)
	}
	read := readJob(v1)
	if read["receiver_effect_state"] != "effect_settled" || read["reconcilable"] != true {
		t.Fatalf("vault v1 read = %v", read)
	}

	// Generic CI JSON: no readable state. The lost first result delivers on the
	// retry, but nothing can prove the receiver, so the next version waits and
	// the read says which command blocks it and that it cannot read back.
	ci.loseWrite = true
	c1 := queueSync("ci", "DB_PASSWORD", "ci-v1")
	if job := drainSecretSyncUntil(t, h, c1, store.SecretSyncJobDelivered, 4); job.Status != store.SecretSyncJobDelivered {
		t.Fatalf("ci v1 = %+v, want delivered on retry", job)
	}
	if a := authority(c1); a.ReceiverIOStarts < 2 || a.EffectState != store.SecretSyncReceiverEffectPossible {
		t.Fatalf("ci v1 authority = %+v, want an unsettled multi-start delivery", a)
	}
	c2 := queueSync("ci", "DB_PASSWORD", "ci-v2")
	if job := drainSecretSyncUntil(t, h, c2, store.SecretSyncJobDelivered, 2); job.Status != store.SecretSyncJobPending {
		t.Fatalf("ci v2 = %+v, want pending behind the unproven predecessor", job)
	}
	read = readJob(c2)
	if read["blocked_by_job_id"] != c1 || read["status"] != "pending" {
		t.Fatalf("ci v2 read = %v, want blocked by %s", read, c1)
	}
	read = readJob(c1)
	if read["reconcilable"] != false || read["receiver_effect_state"] != "effect_possible" {
		t.Fatalf("ci v1 read = %v", read)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs/"+c1+"/reconcile", tok, "ci-v1-reconcile-blind", map[string]any{})
	if status != http.StatusConflict || !bytes.Contains(body, []byte("unknown")) {
		t.Fatalf("blind reconcile of a target without readback = %d %s, want 409 unknown", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs/"+c1+"/reconcile", tok, "ci-v1-reconcile-absent", map[string]any{"operator_verified": true, "observed": "value_absent"})
	if status != http.StatusConflict {
		t.Fatalf("marking a delivered command absent = %d %s, want 409", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs/"+c1+"/reconcile", tok, "ci-v1-reconcile", map[string]any{"operator_verified": true, "observed": "value_present"})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"outcome":"settled"`)) || !bytes.Contains(body, []byte(`"receiver_effect_state":"effect_settled"`)) {
		t.Fatalf("operator settlement = %d %s", status, body)
	}
	replayStatus, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs/"+c1+"/reconcile", tok, "ci-v1-reconcile", map[string]any{"operator_verified": true, "observed": "value_present"})
	if replayStatus != http.StatusOK || !bytes.Equal(replayBody, body) {
		t.Fatalf("replayed settlement = %d %s, want the cached result", replayStatus, replayBody)
	}
	if job := drainSecretSyncUntil(t, h, c2, store.SecretSyncJobDelivered, 2); job.Status != store.SecretSyncJobDelivered {
		t.Fatalf("ci v2 = %+v, want delivered after the operator settled v1", job)
	}
	if got := ci.value("DB_PASSWORD"); got != "sync-v2" || ci.writes != 3 {
		t.Fatalf("ci holds %q after %d writes; want sync-v2 after v1's lost write, its retry and v2", got, ci.writes)
	}

	// Every receipt survives a rebuild from the event log.
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{v1, c1} {
		if a := authority(id); a.EffectState != store.SecretSyncReceiverEffectSettled || a.JobStatus != store.SecretSyncJobDelivered {
			t.Fatalf("rebuilt %s authority = %+v", id, a)
		}
	}
	for _, id := range []string{v2, c2} {
		if job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant, id); err != nil || job.Status != store.SecretSyncJobDelivered {
			t.Fatalf("rebuilt %s = %+v, %v", id, job, err)
		}
	}
	if h.logContains(t, "sync-v1") || h.logContains(t, "sync-v2") {
		t.Fatal("reconciliation leaked a secret value into the event log")
	}
}
