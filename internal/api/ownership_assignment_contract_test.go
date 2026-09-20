// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

func TestOwnershipAssignmentRouteIsGuardedIdempotentMutation(t *testing.T) {
	route := findRoute(New(nil, nil, nil).Routes(), http.MethodPost, "/api/v1/ownership/assignments")
	if route.OperationID != "assignOwnership" {
		t.Fatalf("ownership assignment operationId = %q, want assignOwnership", route.OperationID)
	}
	if !route.Mutation {
		t.Fatal("ownership assignment must be marked as a mutation so Idempotency-Key is enforced")
	}
	if route.Permission != authz.OwnersWrite {
		t.Fatalf("ownership assignment permission = %q, want %q", route.Permission, authz.OwnersWrite)
	}
}

func TestOwnershipAssignmentOverrideWinsBeforeNativeOwner(t *testing.T) {
	idx := newOwnershipOwnerIndex([]store.Owner{
		{ID: "owner-native", TenantID: "tenant-1", Kind: store.OwnerTeam, Name: "Native team"},
		{ID: "owner-decided", TenantID: "tenant-1", Kind: store.OwnerService, Name: "Incident service"},
	})
	item := nhiInventoryItem{
		ID: "identity/asset-1", TenantID: "tenant-1", Kind: "api_key", Source: "identity",
		DisplayName: "deployer key", OwnerID: "owner-native", CreatedAt: time.Now().UTC(),
	}
	owner, source, evidence := resolveOwnershipAttribution(item, idx, store.OwnershipAssignment{
		TenantID: "tenant-1", InventoryID: item.ID, OwnerID: "owner-decided", SourceEventID: "event-42",
	})
	if owner == nil || owner.ID != "owner-decided" {
		t.Fatalf("effective owner = %#v, want owner-decided", owner)
	}
	if source != "asset_override" {
		t.Fatalf("attribution source = %q, want asset_override", source)
	}
	if len(evidence) != 1 || evidence[0] != "ownership.assignment:event-42" {
		t.Fatalf("attribution evidence = %v, want immutable source event", evidence)
	}
}
