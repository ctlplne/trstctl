// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// B5-2: the identity whose delivered leaf a migration replaces is the
// replacement's predecessor on that target. The lookup names only an active
// identity bound to the same target that owns the exact fingerprint, never
// the replacement itself and never an identity on another target.
func TestIdentityHoldingCertificateOnTargetNamesTheDeployedPredecessor(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "b5200000-0000-4000-8000-0000000000aa"
	seedTenant(t, s, tenant)
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: "b5-2 owner"})
	if err != nil {
		t.Fatal(err)
	}
	const target, otherTarget = "b5200000-0000-4000-8000-0000000000bb", "b5200000-0000-4000-8000-0000000000cc"
	identity := func(name, targetID, status string) string {
		t.Helper()
		attrs, _ := json.Marshal(map[string]string{"deployment_target_id": targetID})
		created, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenant, Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		created.Status = status
		if err := s.UpsertIdentity(ctx, created); err != nil {
			t.Fatal(err)
		}
		return created.ID
	}
	leaf := strings.Repeat("d", 64)
	// The ownership binding is anchored on the inventory row trstctl keeps for
	// every leaf it issued or observed.
	if _, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenant, Subject: "CN=b52.example.test", Issuer: "CN=Lab Issuer", Serial: "52", Fingerprint: leaf, KeyAlgorithm: "ECDSA", Source: "issuance"}); err != nil {
		t.Fatal(err)
	}
	classical := identity("b52.example.test", target, "deployed")
	replacement := identity("b52.example.test", target, "requested")
	elsewhere := identity("other.example.test", otherTarget, "deployed")
	receipt := func(id, identityID, fingerprint string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: id, TenantID: tenant, IdentityID: &identityID, Destination: "connector.deploy", Connector: "nginx",
				Target: "lab/site", Fingerprint: fingerprint, Status: "delivered", Attempts: 1, Reason: "native_delivered", IdempotencyKey: id,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	receipt("b5200000-0000-4000-8000-0000000000d1", classical, leaf)
	receipt("b5200000-0000-4000-8000-0000000000d2", elsewhere, leaf)

	holder, err := s.IdentityHoldingCertificateOnTarget(ctx, tenant, target, replacement, leaf)
	if err != nil || holder != classical {
		t.Fatalf("holder = %q, %v; want the deployed classical identity %s", holder, err, classical)
	}
	// The replacement never names itself, and a leaf nobody on this target
	// delivered has no predecessor even when another target serves it.
	if holder, err := s.IdentityHoldingCertificateOnTarget(ctx, tenant, target, classical, leaf); err != nil || holder != "" {
		t.Fatalf("holder excluding the classical identity = %q, %v; want none", holder, err)
	}
	if holder, err := s.IdentityHoldingCertificateOnTarget(ctx, tenant, target, replacement, strings.Repeat("e", 64)); err != nil || holder != "" {
		t.Fatalf("holder for an undelivered leaf = %q, %v; want none", holder, err)
	}
	if holder, err := s.IdentityHoldingCertificateOnTarget(ctx, tenant, otherTarget, replacement, leaf); err != nil || holder != elsewhere {
		t.Fatalf("holder on the other target = %q, %v; want %s", holder, err, elsewhere)
	}
}
