// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestServedDefaultWindowRenewalBurstConvergesWithLiveTail is the assembled
// AUD-103 regression. The shipped 720-hour renewal window can make several
// identities due in one sweep. Each renewal writes running and terminal evidence
// inline while the durable tail can observe the same events, so the read model
// must converge without a unique-key poison, a process restart, or a stranded
// unrelated event behind the burst.
func TestServedDefaultWindowRenewalBurstConvergesWithLiveTail(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 720 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read",
	)

	tailCtx, cancelTail := context.WithCancel(t.Context())
	tailDone := make(chan struct{})
	go func() {
		defer close(tailDone)
		h.srv.RunProjectionTail(tailCtx)
	}()
	t.Cleanup(func() {
		cancelTail()
		select {
		case <-tailDone:
		case <-time.After(5 * time.Second):
			t.Error("projection tail did not stop after cancellation")
		}
	})

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "aud-103-renewal-burst-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	const burstSize = 6
	identityIDs := make([]string, 0, burstSize)
	for i := 0; i < burstSize; i++ {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"kind":     "x509_certificate",
			"name":     fmt.Sprintf("aud-103-%d.served.test", i),
			"owner_id": owner.ID,
			"attributes": map[string]any{
				"connector": "nginx",
				"target":    fmt.Sprintf("edge-%d", i),
			},
		})
		if status != http.StatusCreated {
			t.Fatalf("create identity %d: status %d body %s", i, status, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ident); err != nil {
			t.Fatalf("decode identity %d: %v", i, err)
		}
		identityIDs = append(identityIDs, ident.ID)
		transitionBurstIdentity(t, h, tok, ident.ID, "issued", "AUD-103 initial issue")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain burst issuance: %v", err)
	}
	for _, identityID := range identityIDs {
		transitionBurstIdentity(t, h, tok, identityID, "deployed", "AUD-103 initial deploy")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain burst deployment: %v", err)
	}

	// Fresh 30-day leaves must not renew merely because the default lead is
	// also 30 days. Exercise the actual served store/outbox path twice before
	// advancing only this test's evaluation clock into the real ARI window.
	for i := 0; i < 2; i++ {
		if queued, err := h.srv.RunLifecycleOnce(t.Context()); err != nil || queued != 0 {
			t.Fatalf("fresh sweep %d queued %d renewals: %v", i, queued, err)
		}
	}
	queued, err := h.srv.runLifecycleOnceAt(t.Context(), time.Now().UTC().Add(21*24*time.Hour))
	if err != nil {
		t.Fatalf("run default-window lifecycle sweep: %v", err)
	}
	if queued != burstSize {
		t.Fatalf("default-window renewals queued = %d, want %d", queued, burstSize)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal burst: %v", err)
	}
	for _, identityID := range identityIDs {
		runs := rotationRunsForIdentity(t, h, tok, identityID)
		if len(runs.Items) != 1 {
			t.Fatalf("identity %s rotation runs = %d, want 1 (%s)", identityID, len(runs.Items), runs.Raw)
		}
		if runs.Items[0].Status != "succeeded" {
			t.Fatalf("identity %s rotation run = %+v, want one succeeded terminal row", identityID, runs.Items[0])
		}
	}
	if queued, err := h.srv.RunLifecycleOnce(t.Context()); err != nil || queued != 0 {
		t.Fatalf("fresh successors reentered the scheduler: queued=%d err=%v", queued, err)
	}

	// This event is intentionally outside the request's inline projector. It can
	// advance only if the live tail moved through every lifecycle evidence event
	// before it, which is the exact liveness property AUD-103 found missing.
	trailingOwnerID := "00000000-0000-0000-0000-000000000103"
	trailingPayload, err := json.Marshal(projections.OwnerCreated{
		ID: trailingOwnerID, Kind: "workload", Name: "aud-103-trailing-owner",
	})
	if err != nil {
		t.Fatalf("marshal trailing owner: %v", err)
	}
	trailing, err := h.log.Append(t.Context(), events.Event{
		Type: projections.EventOwnerCreated, TenantID: h.tenant, Data: trailingPayload,
	})
	if err != nil {
		t.Fatalf("append trailing event: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		health, healthErr := h.store.ProjectionTailHealth(t.Context())
		_, ownerErr := h.store.GetOwner(t.Context(), h.tenant, trailingOwnerID)
		if healthErr == nil && ownerErr == nil &&
			health.AppliedSequence >= trailing.Sequence && health.FailedSequence == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	health, healthErr := h.store.ProjectionTailHealth(t.Context())
	_, ownerErr := h.store.GetOwner(t.Context(), h.tenant, trailingOwnerID)
	t.Fatalf("projection tail did not converge past renewal burst: health=%+v health_err=%v trailing_owner_err=%v want_applied>=%d",
		health, healthErr, ownerErr, trailing.Sequence)
}

func transitionBurstIdentity(t *testing.T, h *servedHarness, token, identityID, to, reason string) {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, map[string]any{
		"to": to, "reason": reason,
	})
	if to == "deployed" && status == http.StatusConflict && strings.Contains(string(body), "deployed") {
		return
	}
	if status != http.StatusOK {
		t.Fatalf("transition identity %s to %s: status %d body %s", identityID, to, status, body)
	}
}
