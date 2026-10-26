// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"bytes"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/store"
)

const (
	rotationTestTenant = "11111111-1111-4111-8111-111111111111"
	rotationTestDomain = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

// A rotation pass moves only containers of the previous generation, keeps the
// payload ciphertext byte-identical, leaves next-generation containers alone,
// and refuses every other domain, including an unlabeled deployment container.
func TestRotationRewrapperMovesOnlyThePreviousGenerationAndKeepsPayloadBytes(t *testing.T) {
	previous, next, deployment := testKEK(t, 0x41), testKEK(t, 0x42), testKEK(t, 0x43)
	g1, err := DomainBinding(rotationTestTenant, rotationTestDomain, 1)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := DomainBinding(rotationTestTenant, rotationTestDomain, 2)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("row-aad-the-rotation-never-sees")
	old, err := seal.SealDomain(previous, []byte("generation one row"), aad, g1)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := seal.SealDomain(next, []byte("sealed during the rotation"), aad, g2)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := seal.Seal(deployment, []byte("deployment row"), aad)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := seal.SealDomain(previous, []byte("another domain"), aad, []byte("tenant=other;domain=x;generation=1"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewRotationRewrapper(previous, g1, next, g1); err == nil {
		t.Fatal("a rotation onto its own source domain was accepted")
	}
	if _, err := NewRotationRewrapper(nil, g1, next, g2); err == nil {
		t.Fatal("a rotation without a source key was accepted")
	}
	rewriter, err := NewRotationRewrapper(previous, g1, next, g2)
	if err != nil {
		t.Fatal(err)
	}

	moved, changed, err := rewriter.Transform("postgres.secret_store.sealed", 1, old)
	if err != nil || !changed {
		t.Fatalf("previous-generation container did not move: changed=%t err=%v", changed, err)
	}
	if label, err := seal.Domain(moved); err != nil || !bytes.Equal(label, g2) {
		t.Fatalf("moved container label = %q, %v; want generation 2", label, err)
	}
	if plain, err := seal.OpenDomain(next, moved, aad, g2); err != nil || string(plain) != "generation one row" {
		t.Fatalf("moved container does not open under the next generation: %q %v", plain, err)
	}
	if _, err := seal.OpenDomain(previous, moved, aad, g1); err == nil {
		t.Fatal("moved container still opens under the previous generation")
	}
	before, err := seal.PayloadCiphertext(old)
	if err != nil {
		t.Fatal(err)
	}
	after, err := seal.PayloadCiphertext(moved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rotation re-encrypted the payload instead of re-wrapping its data key")
	}

	kept, changed, err := rewriter.Transform("postgres.secret_store.sealed", 1, fresh)
	if err != nil || changed || !bytes.Equal(kept, fresh) {
		t.Fatalf("next-generation container was rewritten: changed=%t err=%v", changed, err)
	}
	for name, container := range map[string][]byte{"deployment": legacy, "foreign": foreign} {
		if _, _, err := rewriter.Transform("postgres.secret_store.sealed", 1, container); !errors.Is(err, ErrUnexpectedDomain) {
			t.Fatalf("%s container = %v, want ErrUnexpectedDomain", name, err)
		}
	}

	event := mustJSON(t, map[string]any{
		"sealed": old, "nested": mustJSON(t, map[string]any{"sealed": old}), "public": "unchanged",
	})
	rewritten, changed, err := rewriter.Transform("secret.version.written", 1, event)
	if err != nil || !changed {
		t.Fatalf("history event did not move: changed=%t err=%v", changed, err)
	}
	if err := rewriter.ValidatePair("secret.version.written", 1, event, rewritten); err != nil {
		t.Fatalf("pair validator refused the exact rewrap: %v", err)
	}
	// A container labeled with the next generation but still wrapped by the
	// previous key is not a rotation, and a deployment container is not this
	// pass's source.
	forged, err := seal.RewrapDomain(previous, previous, old, g2)
	if err != nil {
		t.Fatal(err)
	}
	if err := rewriter.ValidatePair("secret.version.written", 1,
		mustJSON(t, map[string]any{"sealed": old}), mustJSON(t, map[string]any{"sealed": forged})); err == nil {
		t.Fatal("pair validator accepted a next-generation label over the previous key")
	}
	legacyMoved, err := seal.RewrapDomain(deployment, next, legacy, g2)
	if err != nil {
		t.Fatal(err)
	}
	if err := rewriter.ValidatePair("secret.version.written", 1,
		mustJSON(t, map[string]any{"sealed": legacy}), mustJSON(t, map[string]any{"sealed": legacyMoved})); err == nil {
		t.Fatal("pair validator accepted a deployment container as the rotation's source")
	}
}

// While a rotation runs, tenant crypto routes to both generations, a seal
// cannot be queued, and a record whose next generation is incomplete or stray
// fails closed as corrupt.
func TestRotatingDomainResolvesBothGenerationsAndRefusesSeal(t *testing.T) {
	operationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	rotating := store.TenantKeyDomain{
		TenantID: rotationTestTenant, DomainID: rotationTestDomain,
		Generation: 1, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStateRotating,
		WrapperKind: WrapperKindLocalFile, WrapperID: "operator-wrapper",
		WrappedDomainKEK: []byte("opaque wrapped generation one"),
		NextGeneration:   2, NextWrapperKind: WrapperKindLocalFile, NextWrapperID: "operator-wrapper",
		NextWrappedDomainKEK: []byte("opaque wrapped generation two"),
		OperationID:          &operationID, OperationKind: store.TenantKeyOperationRotate,
		OperationStatus:   store.TenantKeyOperationRunning,
		ProgressCompleted: 4, ProgressTotal: 13,
		LegacyHistoryExposure: store.TenantKeyLegacyExternalArchivesPossible,
	}
	if mode, status := resolveDomainAccessMode(rotationTestTenant, rotating); mode != domainAccessDualRotation {
		t.Fatalf("running rotation = %v/%q, want dual rotation", mode, status)
	}
	if tenantKeyDomainCanQueueSeal(rotationTestTenant, rotating) {
		t.Fatal("a seal could be queued in the middle of a rotation")
	}
	failed := rotating
	failed.OperationStatus = store.TenantKeyOperationFailed
	failed.Retryable = true
	if mode, _ := resolveDomainAccessMode(rotationTestTenant, failed); mode != domainAccessDualRotation {
		t.Fatal("a failed rotation stopped reading both generations")
	}

	completedYetRotating := rotating
	completedYetRotating.OperationStatus = store.TenantKeyOperationCompleted
	if mode, status := resolveDomainAccessMode(rotationTestTenant, completedYetRotating); mode != domainAccessDenied || status != StatusRotating {
		t.Fatalf("completed operation still rotating = %v/%q, want denied rotating", mode, status)
	}
	missingNext := rotating
	missingNext.NextWrappedDomainKEK = nil
	skipped := rotating
	skipped.NextGeneration = 3
	stray := rotating
	stray.State = store.TenantKeyDomainStateUnsealed
	stray.OperationStatus = store.TenantKeyOperationCompleted
	for name, domain := range map[string]store.TenantKeyDomain{
		"missing next KEK": missingNext, "skipped generation": skipped, "next outside a rotation": stray,
	} {
		if mode, status := resolveDomainAccessMode(rotationTestTenant, domain); mode != domainAccessDenied || status != StatusCorrupt {
			t.Fatalf("%s = %v/%q, want denied corrupt", name, mode, status)
		}
	}

	rotated := rotating
	rotated.Generation, rotated.WrappedDomainKEK = 2, rotating.NextWrappedDomainKEK
	rotated.NextGeneration, rotated.NextWrapperKind, rotated.NextWrapperID, rotated.NextWrappedDomainKEK = 0, "", "", nil
	rotated.State = store.TenantKeyDomainStateUnsealed
	rotated.OperationStatus = store.TenantKeyOperationCompleted
	if mode, _ := resolveDomainAccessMode(rotationTestTenant, rotated); mode != domainAccessTenantOnly {
		t.Fatal("a completed rotation is not tenant-only")
	}
	if !tenantKeyDomainCanQueueSeal(rotationTestTenant, rotated) {
		t.Fatal("a rotated domain cannot be sealed")
	}
}
