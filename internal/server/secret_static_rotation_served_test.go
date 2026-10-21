// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

// staticRotationProviderDouble is a configured provider that allows static
// rotation for one role. It records every mint, verification and revocation
// so the test can prove the worker's phase order and that nothing leaks.
type staticRotationProviderDouble struct {
	name       string
	role       string
	verifyFail bool

	mu       sync.Mutex
	minted   []dynsecret.GenerateRequest
	revoked  []string
	verified int
	serial   int
}

func (p *staticRotationProviderDouble) Name() string { return p.name }

func (p *staticRotationProviderDouble) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !req.Static {
		return dynsecret.Credential{}, errors.New("double: only static requests are expected here")
	}
	p.minted = append(p.minted, req)
	p.serial++
	ref := "role:" + req.Role + "#" + strings.Repeat("x", p.serial)
	return dynsecret.Credential{BackendRef: ref, Secret: []byte("dsn-for-" + ref), Metadata: map[string]string{"provider_type": "double"}}, nil
}

func (p *staticRotationProviderDouble) Revoke(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, ref)
	return nil
}

func (p *staticRotationProviderDouble) AllowsStaticRotation(role string) bool { return role == p.role }

func (p *staticRotationProviderDouble) VerifyStaticCredential(context.Context, string, []byte) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verified++
	if p.verifyFail {
		return "connected", errors.New("double: staged credential refused")
	}
	return "connected", nil
}

func (p *staticRotationProviderDouble) snapshot() (minted []dynsecret.GenerateRequest, revoked []string, verified int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]dynsecret.GenerateRequest(nil), p.minted...), append([]string(nil), p.revoked...), p.verified
}

type staticRotationCommandView struct {
	ID              string `json:"id"`
	Phase           string `json:"phase"`
	Terminal        bool   `json:"terminal"`
	OldRef          string `json:"old_ref"`
	NewRef          string `json:"new_ref"`
	ResultVersion   int    `json:"result_version"`
	RestoredVersion int    `json:"restored_version"`
	VerifyMode      string `json:"verify_mode"`
	Error           string `json:"error"`
	ScheduleID      string `json:"schedule_id"`
}

// A static-provider rotation is one durable command: the request commits it
// and returns queued evidence; the outbox worker mints the successor, publishes
// it as the next secret version, verifies it and retires the predecessor, each
// phase an immutable event. A failing verification restores the predecessor
// and revokes the successor. Schedules queue the same command per due edge and
// chain the predecessor from the last completed command.
func TestServedStaticSecretRotationRunsThroughDurableWorker(t *testing.T) {
	provider := &staticRotationProviderDouble{name: "pg-main", role: "db/reporting"}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := context.Background()

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-reporting",
		map[string]any{"name": "db/reporting", "value": "dsn-for-role:old"}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	readValue := func() (string, int) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/db/reporting", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read secret: %d %s", status, body)
		}
		var out struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		_ = json.Unmarshal(body, &out)
		return out.Value, out.Version
	}
	command := func(id string) staticRotationCommandView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read command %s: %d %s", id, status, body)
		}
		var view staticRotationCommandView
		_ = json.Unmarshal(body, &view)
		return view
	}
	awaitTerminal := func(id string, within time.Duration) staticRotationCommandView {
		t.Helper()
		deadline := time.Now().Add(within)
		for {
			h.srv.dispatchOnce(ctx)
			view := command(id)
			if view.Terminal {
				return view
			}
			if time.Now().After(deadline) {
				var lastError string
				var attempts int
				_ = h.store.SystemPool().QueryRow(ctx,
					`SELECT coalesce(last_error, ''), attempts FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id DESC LIMIT 1`,
					h.tenant, "secret.static-rotation").Scan(&lastError, &attempts)
				direct := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, id, 1)
				t.Fatalf("command %s never became terminal: %+v (outbox attempts=%d last_error=%q direct=%v)", id, view, attempts, lastError, direct)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Unconfigured provider: refused before any effect.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "static-nope",
		map[string]any{"provider": "nope", "key": "db/reporting", "old_ref": "role:old"}); status != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), "static rotation is not configured for this provider") {
		t.Fatalf("unconfigured provider: %d %s", status, body)
	}

	// Happy path: queued → staged → cutover → verified → completed.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "static-1",
		map[string]any{"provider": "pg-main", "key": "db/reporting", "old_ref": "role:old"})
	if status != http.StatusOK {
		t.Fatalf("queue static rotation: %d %s", status, body)
	}
	var queued struct {
		Queued    bool   `json:"queued"`
		CommandID string `json:"command_id"`
		Phase     string `json:"phase"`
		NewRef    string `json:"new_ref"`
	}
	_ = json.Unmarshal(body, &queued)
	if !queued.Queued || queued.CommandID == "" || queued.Phase != "queued" || queued.NewRef != "" {
		t.Fatalf("queued receipt: %s", body)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "static-1",
		map[string]any{"provider": "pg-main", "key": "db/reporting", "old_ref": "role:old"}); status != http.StatusOK || string(replay) != string(body) {
		t.Fatalf("idempotent replay differs: %d %s vs %s", status, replay, body)
	}
	done := awaitTerminal(queued.CommandID, 15*time.Second)
	if done.Phase != "completed" || done.NewRef == "" || done.ResultVersion != 2 || done.VerifyMode != "connected" || done.Error != "" {
		t.Fatalf("completed command: %+v", done)
	}
	if value, version := readValue(); version != 2 || value != "dsn-for-"+done.NewRef {
		t.Fatalf("secret after cutover: version=%d value=%q", version, value)
	}
	minted, revoked, verified := provider.snapshot()
	if len(minted) != 1 || !minted[0].Static || minted[0].Role != "db/reporting" || minted[0].LeaseID != queued.CommandID {
		t.Fatalf("mint requests: %+v", minted)
	}
	if verified != 1 || len(revoked) != 1 || revoked[0] != "role:old" {
		t.Fatalf("verify/retire: verified=%d revoked=%v", verified, revoked)
	}
	firstRef := done.NewRef
	for _, ev := range []string{"secret.static_rotation.queued", "secret.static_rotation.advanced", "secret.rotated"} {
		if !h.hasEvent(t, ev) {
			t.Fatalf("event %s missing from the log", ev)
		}
	}
	if h.logContains(t, "dsn-for-"+firstRef) {
		t.Fatal("the staged credential appeared in plaintext in the event log")
	}

	// Verification failure: the predecessor is restored and the successor revoked.
	provider.verifyFail = true
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "static-2",
		map[string]any{"provider": "pg-main", "key": "db/reporting", "old_ref": firstRef})
	if status != http.StatusOK {
		t.Fatalf("queue second rotation: %d %s", status, body)
	}
	_ = json.Unmarshal(body, &queued)
	rolled := awaitTerminal(queued.CommandID, 40*time.Second)
	if rolled.Phase != "rolled_back" || rolled.RestoredVersion != 4 || !strings.Contains(rolled.Error, "predecessor restored") {
		t.Fatalf("rolled-back command: %+v", rolled)
	}
	if value, version := readValue(); version != 4 || value != "dsn-for-"+firstRef {
		t.Fatalf("secret after rollback: version=%d value=%q", version, value)
	}
	_, revoked, verified = provider.snapshot()
	if verified < 3 || len(revoked) != 2 || revoked[1] != rolled.NewRef {
		t.Fatalf("rollback effects: verified=%d revoked=%v want successor %s revoked", verified, revoked, rolled.NewRef)
	}
	for _, ref := range revoked {
		if ref == firstRef {
			t.Fatal("rollback retired the live predecessor")
		}
	}
	provider.verifyFail = false

	// Schedules: a due edge queues one command and chains the predecessor
	// from the last completed command, not the schedule's original old_ref.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "static-sched",
		map[string]any{"name": "reporting-hourly", "provider": "pg-main", "key": "db/reporting", "old_ref": "role:old",
			"interval_seconds": 3600, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)})
	if status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("create static schedule: %d %s", status, body)
	}
	var sched struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &sched)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, "static-run-due", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
		t.Fatalf("run-due: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key=db/reporting", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list commands: %d %s", status, body)
	}
	var list struct {
		Items []staticRotationCommandView `json:"items"`
	}
	_ = json.Unmarshal(body, &list)
	if len(list.Items) != 3 || list.Items[0].ScheduleID != sched.ID || list.Items[0].OldRef != firstRef {
		rows, listErr := h.store.ListSecretStaticRotationCommandsPage(ctx, h.tenant, "db/reporting", "", 50)
		_, all := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations", tok, nil)
		_, esc := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key=db%2Freporting&limit=10", tok, nil)
		t.Fatalf("scheduled command chain: %+v (body=%s all=%s esc=%s schedule=%s store rows=%d err=%v)", list.Items, body, all, esc, sched.ID, len(rows), listErr)
	}
	final := awaitTerminal(list.Items[0].ID, 15*time.Second)
	if final.Phase != "completed" || final.ResultVersion != 5 {
		t.Fatalf("scheduled command: %+v", final)
	}
	_, revoked, _ = provider.snapshot()
	if revoked[len(revoked)-1] != firstRef {
		t.Fatalf("scheduled rotation did not retire the chained predecessor: %v", revoked)
	}
}
