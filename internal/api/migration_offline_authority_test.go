// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A migration may name an imported offline root as its new authority (A36).
// The root cannot sign, so successors are issued by its one active
// signer-backed intermediate while the root stays the anchor hosts receive.
func TestMigrationIssuingAuthorityResolvesOfflineRootToItsIntermediate(t *testing.T) {
	t.Parallel()
	ref := func(s string) *string { return &s }
	root := store.CAAuthority{ID: "root", Kind: "root", Status: "active", SignerHandle: ""}
	inter := store.CAAuthority{ID: "inter", Kind: "intermediate", Status: "active", SignerHandle: "h-inter", ParentID: ref("root")}
	superseded := store.CAAuthority{ID: "old", Kind: "intermediate", Status: "superseded", SignerHandle: "h-old", ParentID: ref("root")}
	foreign := store.CAAuthority{ID: "other", Kind: "intermediate", Status: "active", SignerHandle: "h-other", ParentID: ref("elsewhere")}
	signerRoot := store.CAAuthority{ID: "signer-root", Kind: "root", Status: "active", SignerHandle: "h-root"}

	got, err := migrationIssuingAuthority(signerRoot, []store.CAAuthority{signerRoot, inter})
	if err != nil || got.ID != "signer-root" {
		t.Fatalf("signer-backed authority = %+v %v; want itself", got, err)
	}
	got, err = migrationIssuingAuthority(root, []store.CAAuthority{root, inter, superseded, foreign})
	if err != nil || got.ID != "inter" {
		t.Fatalf("offline root = %+v %v; want its one active signer-backed intermediate", got, err)
	}
	if _, err := migrationIssuingAuthority(root, []store.CAAuthority{root, superseded, foreign}); err == nil || !strings.Contains(err.Error(), "signer-backed intermediate") {
		t.Fatalf("offline root without an issuing intermediate = %v; want an actionable refusal", err)
	}
	second := inter
	second.ID = "inter-2"
	if _, err := migrationIssuingAuthority(root, []store.CAAuthority{root, inter, second}); err == nil || !strings.Contains(err.Error(), "name the issuing intermediate") {
		t.Fatalf("offline root with two issuing intermediates = %v; want a refusal that says which to name", err)
	}
	offlineInter := store.CAAuthority{ID: "ghost", Kind: "intermediate", Status: "active", SignerHandle: ""}
	if _, err := migrationIssuingAuthority(offlineInter, []store.CAAuthority{offlineInter}); err == nil {
		t.Fatal("an intermediate without a signer key was accepted as an issuing authority")
	}
	revokedRoot := root
	revokedRoot.Status = "revoked"
	if _, err := migrationIssuingAuthority(revokedRoot, []store.CAAuthority{revokedRoot, inter}); err == nil {
		t.Fatal("a revoked root was accepted as the new authority")
	}
}
