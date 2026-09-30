// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestTargetConflictAllowsReplacementAncestorsButRejectsUnrelatedWriter(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "replacement chain owner"})
	if err != nil {
		t.Fatal(err)
	}
	targetID := "71111111-1111-4111-8111-111111111111"
	create := func(name, parent string) store.Identity {
		t.Helper()
		attrs, err := json.Marshal(map[string]string{
			"deployment_target_id": targetID, "endpoint_replaces_identity_id": parent,
		})
		if err != nil {
			t.Fatal(err)
		}
		identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA,
			Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		identity.Status = "deployed"
		if err := s.UpsertIdentity(ctx, identity); err != nil {
			t.Fatal(err)
		}
		return identity
	}
	grandparent := create("chain.example.test", "")
	parent := create("chain.example.test", grandparent.ID)
	// A new successor can replace the currently serving parent even when the
	// retained grandparent is still deployed in its historical read model.
	conflicts, err := s.ConflictingTargetBindings(ctx, tenantA, targetID,
		"72222222-2222-4222-8222-222222222222", parent.ID, true)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("replacement ancestors treated as competitors: %v, %v", conflicts, err)
	}
	unrelated := create("unrelated.example.test", "")
	conflicts, err = s.ConflictingTargetBindings(ctx, tenantA, targetID,
		"72222222-2222-4222-8222-222222222222", parent.ID, true)
	if err != nil || len(conflicts) != 1 || conflicts[0] != unrelated.ID {
		t.Fatalf("unrelated writer was not blocked: %v, %v", conflicts, err)
	}
	// A fresh enrollment has no reviewed predecessor; every deployed writer
	// still conflicts, including the whole replacement chain.
	conflicts, err = s.ConflictingTargetBindings(ctx, tenantA, targetID,
		"73333333-3333-4333-8333-333333333333", "", true)
	if err != nil || len(conflicts) != 3 {
		t.Fatalf("fresh enrollment lost its destination guard: %v, %v", conflicts, err)
	}
}
