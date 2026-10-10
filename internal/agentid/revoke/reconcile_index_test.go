// SPDX-License-Identifier: BUSL-1.1

package revoke_test

import (
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/revoke"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestRevoke_ReconcileIndexedDirectiveHealsColdAppendGap(t *testing.T) {
	h := newHarness(t, "revoke_reconcile_indexed_cold")
	h.seedChainCredential(t, tenantA, "crash-chain", "crash-root", "crash-child", "crash-root", "crash-credential")
	if _, err := h.log.Append(t.Context(), events.Event{TenantID: tenantB,
		Type: "unrelated.audit.fact", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	watermark, err := h.log.CheckedHead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a process death after the durable directive append and before
	// its directive/job/outbox PostgreSQL transaction. Recovery must derive the
	// exact descendant from the recorded watermark rather than current state.
	directive := h.appendEvent(t, delegation.RevocationDirectiveV1{
		TenantID: tenantA, SubjectID: "crash-root", Reason: string(revoke.ReasonCompromise), Watermark: watermark,
	})
	jobKey := revoke.JobIdempotencyKey(directive.ID, credID("crash-credential"))
	if h.outboxHasKey(t, tenantA, jobKey) {
		t.Fatal("fixture did not leave the append-to-enqueue crash gap")
	}
	if err := h.log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: h.eventDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	h.log = reopened
	c := h.cascade(t)
	if healed, err := c.Reconcile(t.Context(), directive.Sequence+1); err != nil || healed != 0 {
		t.Fatalf("cursor past directive healed=%d err=%v", healed, err)
	}
	if healed, err := c.Reconcile(t.Context(), 1); err != nil || healed != 1 {
		t.Fatalf("cold indexed reconciliation healed=%d err=%v", healed, err)
	}
	if !h.outboxHasKey(t, tenantA, jobKey) {
		t.Fatal("reconciliation did not restore the exact descendant job")
	}
	if healed, err := c.Reconcile(t.Context(), 1); err != nil || healed != 0 {
		t.Fatalf("repeated reconciliation duplicated an outbox job: healed=%d err=%v", healed, err)
	}
}
