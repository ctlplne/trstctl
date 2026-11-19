// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestSecretRotationScheduleTickAuthorityUsesVerifiedRegistrationSequenceNotEventID(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		rawKey   = "customer-visible-idempotency-key/alice"
		route    = "route-binding"
	)
	first := orchestrator.TenantRegistrationAuthority{
		EventID: "15500000-0000-4000-8000-000000000001", EventSequence: 41,
	}
	idDrift := orchestrator.TenantRegistrationAuthority{
		EventID: "different-audit-event-id", EventSequence: first.EventSequence,
	}
	nextLifecycle := orchestrator.TenantRegistrationAuthority{
		EventID: first.EventID, EventSequence: first.EventSequence + 1,
	}

	firstKey, firstBinding, err := secretRotationScheduleTickAuthority(
		tenantID, first, rawKey, route)
	if err != nil {
		t.Fatal(err)
	}
	driftKey, driftBinding, err := secretRotationScheduleTickAuthority(
		tenantID, idDrift, rawKey, route)
	if err != nil {
		t.Fatal(err)
	}
	if driftKey != firstKey || driftBinding != firstBinding {
		t.Fatalf("same verified registration sequence forked authority: first=(%q,%q) drift=(%q,%q)",
			firstKey, firstBinding, driftKey, driftBinding)
	}

	nextKey, nextBinding, err := secretRotationScheduleTickAuthority(
		tenantID, nextLifecycle, rawKey, route)
	if err != nil {
		t.Fatal(err)
	}
	if nextKey == firstKey || nextBinding == firstBinding {
		t.Fatalf("new registration sequence reused old authority: first=(%q,%q) next=(%q,%q)",
			firstKey, firstBinding, nextKey, nextBinding)
	}
	if strings.Contains(firstKey, rawKey) || strings.Contains(firstBinding, rawKey) ||
		strings.Contains(nextKey, rawKey) || strings.Contains(nextBinding, rawKey) {
		t.Fatal("raw Idempotency-Key leaked into persisted scheduler authority")
	}
}

func TestReconciledLegacyStaticRunKeepsReceiptWithoutUnprovedSuccessor(t *testing.T) {
	const oldRef = "none"
	const marker = "unlimited/fixture-earlier-result"
	sched := store.SecretRotationSchedule{
		ID: "fixture-schedule", Provider: "fixture-reconfigured-provider",
		Key: "fixture/rotation", OldRef: oldRef,
	}
	run := store.SecretRotationScheduleRun{RunID: "fixture-run", Status: "queued", NewRef: marker}
	view := secretRotationScheduleRunResponseFromReceipt(sched, run, true)
	if view.Rotation.NewRef != "" || view.Rotation.OldRef != oldRef || !view.Rotation.Queued ||
		view.RunID != run.RunID || !view.Reconciled {
		t.Fatal("retained result must keep its identity, status and explicit predecessor while omitting an unproved successor")
	}
}
