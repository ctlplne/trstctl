// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// CR-1015: a lagged durable consumer replays events already projected inline
// after the feed has advanced across multiple batches.

type cr1015Rig struct {
	t     *testing.T
	bind  func(*Deps)
	token string
	es    *p5Elastic
}

func newCR1015Rig(t *testing.T) (*cr1015Rig, *servedHarness) {
	t.Helper()
	es := newP5Elastic(t)
	bind := bindOutboundEnvCredentialRefs("audit_feed", []string{es.server.URL}, "env:TRSTCTL_P5_ES_KEY")
	h := newOperatingServedHarness(t, config.Protocols{}, bind)
	t.Setenv("TRSTCTL_P5_ES_KEY", "p5-es-key")
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "cr1015-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	putAuditFeedAUD52(t, h, token, p5ElasticFeedID, map[string]any{
		"name": "search", "provider": "elastic", "endpoint_url": es.server.URL + "/trstctl-audit/_bulk",
		"token_ref":        "env:TRSTCTL_P5_ES_KEY", // #nosec G101 -- locator, not a secret
		"interval_seconds": 300, "batch_size": 100, "enabled": true,
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
	})
	return &cr1015Rig{t: t, bind: bind, token: token, es: es}, h
}

// restart re-runs the production composition (Build) over the same store and log.
func (r *cr1015Rig) restart(prev *servedHarness) (*servedHarness, error) {
	r.t.Helper()
	prev.ts.Close()
	deps := Deps{
		Store: prev.store, Log: prev.log, Signer: prev.signer, SignAuthorizer: prev.authz,
		CACertFile: prev.caFile, KEK: prev.kek,
	}
	r.bind(&deps)
	srv, err := Build(context.Background(), deps)
	if err != nil {
		return nil, err
	}
	cleanupServedServer(r.t, srv)
	ts := httptest.NewServer(srv.Handler())
	r.t.Cleanup(ts.Close)
	return &servedHarness{srv: srv, ts: ts, tenant: prev.tenant, caPEM: srv.CACertPEM(), log: prev.log,
		store: prev.store, signer: prev.signer, authz: prev.authz, caFile: prev.caFile, kek: prev.kek}, nil
}

// batch writes audit records, queues one feed batch and dispatches it.
func (r *cr1015Rig) batch(h *servedHarness) {
	t := r.t
	t.Helper()
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("CR1015 team %d", time.Now().UnixNano())
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", r.token, "cr1015-"+name, map[string]any{
			"kind": "team", "name": name, "email": "cr1015@example.test",
		}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed: HTTP %d %s", status, body)
		}
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("scheduler queued %d (err %v), want 1", n, err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

func (r *cr1015Rig) cursor(h *servedHarness) string {
	cp, err1 := h.store.ProjectionCheckpoint(r.t.Context())
	head, err2 := h.log.LastSequence(r.t.Context())
	var status string
	var last int64
	if err := h.store.SystemPool().QueryRow(r.t.Context(),
		`SELECT last_status, last_delivered_sequence FROM audit_feed_destinations WHERE tenant_id = $1`, h.tenant).Scan(&status, &last); err != nil {
		status = "err:" + err.Error()
	}
	return fmt.Sprintf("checkpoint=%d head=%d (%v %v) feed=%s last_delivered=%d es=%v", cp, head, err1, err2, status, last, r.es.sequences())
}

func (r *cr1015Rig) noDuplicates() {
	got := r.es.sequences()
	c := slices.Clone(got)
	slices.Sort(c)
	if len(slices.Compact(c)) != len(got) {
		r.t.Errorf("collector holds duplicate sequences: %v", got)
	}
}

// An unstarted tail leaves the durable checkpoint behind two delivered batches.
// Build must catch up without rejecting the older, already projected batch.
func TestCR1015AuditFeedRestartWithLaggedTail(t *testing.T) {
	r, h := newCR1015Rig(t)
	r.batch(h)
	r.batch(h)
	t.Logf("before restart: %s", r.cursor(h))
	h2, err := r.restart(h)
	if err != nil {
		t.Fatalf("boot catch-up refused a replayed batch: %v", err)
	}
	cp, err := h2.store.ProjectionCheckpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	head, err := h2.log.LastSequence(t.Context())
	if err != nil || cp != head {
		t.Fatalf("boot did not catch up: checkpoint=%d head=%d err=%v", cp, head, err)
	}
	// Rebuild uses the same immutable log and must preserve exact delivery rows.
	if err := projections.New(h2.store).Rebuild(t.Context(), h2.log); err != nil {
		t.Fatalf("full-log rebuild: %v", err)
	}
	h3, err := r.restart(h2)
	if err != nil {
		t.Fatalf("restart after rebuild: %v", err)
	}
	r.batch(h3)
	if err := h3.srv.proj.ProjectCatchUp(t.Context(), h3.log); err != nil {
		t.Fatalf("third batch replay: %v", err)
	}
	r.noDuplicates()
}

// Production composition: RunProjectionTail runs (run.go:1531) and is caught
// up between batches, as it is when batches are interval_seconds apart.
func TestCR1015AuditFeedRestartWithTailCaughtUp(t *testing.T) {
	r, h := newCR1015Rig(t)
	for cycle := 1; cycle <= 2; cycle++ {
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); h.srv.RunProjectionTail(ctx) }()
		waitCaughtUp := func() {
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				cp, _ := h.store.ProjectionCheckpoint(t.Context())
				head, _ := h.log.LastSequence(t.Context())
				if cp >= head {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Errorf("cycle %d: tail did not catch up: %s", cycle, r.cursor(h))
		}
		r.batch(h)
		waitCaughtUp()
		r.batch(h)
		waitCaughtUp()
		stop()
		<-done
		t.Logf("cycle %d before restart: %s", cycle, r.cursor(h))
		h2, err := r.restart(h)
		if err != nil {
			t.Fatalf("cycle %d: restart with the tail caught up: FAILED: %v", cycle, err)
		}
		t.Logf("cycle %d restart: ok", cycle)
		h = h2
	}
	r.noDuplicates()
}
