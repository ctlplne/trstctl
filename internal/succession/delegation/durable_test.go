// SPDX-License-Identifier: BUSL-1.1

package delegation_test

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession/delegation"
)

func TestDurableDelegationTenantAndFirstWriterFences(t *testing.T) {
	dir := t.TempDir()
	store := delegation.NewDurableScopeStore(dir)
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(_ string, body []byte) ([]byte, []byte, error) {
		sig, err := key.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
		return key.Public().DER, sig, err
	}
	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"
	root := delegation.Command{TenantID: tenantA, OperationID: "root-1", Kind: "scope", ScopeID: "root", EpochFloor: 2}
	first, err := store.Apply(root, sign)
	if err != nil {
		t.Fatal(err)
	}
	second, err := delegation.NewDurableScopeStore(dir).Apply(root, sign)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("exact retry changed signed receipt")
	}
	bad := root
	bad.EpochFloor = 1
	if _, err := store.Apply(bad, sign); err == nil || !strings.Contains(err.Error(), "operation id reused") {
		t.Fatalf("conflicting operation = %v", err)
	}
	bad.OperationID = "root-lower"
	if _, err := store.Apply(bad, sign); err == nil || !strings.Contains(err.Error(), "cannot decrease") {
		t.Fatalf("floor regression = %v", err)
	}
	bad = root
	bad.OperationID, bad.ParentScopeID = "root-reparent", "other"
	if _, err := store.Apply(bad, sign); err == nil || !strings.Contains(err.Error(), "parent is immutable") {
		t.Fatalf("reparent = %v", err)
	}
	if _, err := store.Apply(delegation.Command{TenantID: tenantB, OperationID: "other-tenant", Kind: "scope", ScopeID: "root", EpochFloor: 0}, sign); err != nil {
		t.Fatalf("another tenant may own same scope id: %v", err)
	}
	child := delegation.Command{TenantID: tenantA, OperationID: "child", Kind: "scope", ScopeID: "app", ParentScopeID: "root"}
	if _, err := store.Apply(child, sign); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CheckAndBind(tenantA, "app", 1); err == nil {
		t.Fatal("ancestor floor did not refuse tenant A")
	}
	if _, err := store.CheckAndBind(tenantB, "root", 1); err != nil {
		t.Fatalf("tenant B inherited tenant A floor: %v", err)
	}
	if _, err := store.CheckAndBind(tenantB, "app", 1); err == nil {
		t.Fatal("tenant B borrowed tenant A child scope")
	}
	floor := delegation.Command{TenantID: tenantA, OperationID: "floor-3", Kind: "floor", ScopeID: "app", EpochFloor: 3}
	receipt, err := store.Apply(floor, sign)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AppliedParentScopeID != "root" || receipt.AppliedFloor != 3 {
		t.Fatalf("floor receipt omitted signer-held parent/state: %+v", receipt)
	}
	restarted := delegation.NewDurableScopeStore(dir)
	if _, err := restarted.CheckAndBind(tenantA, "app", 2); err == nil {
		t.Fatal("restart lost floor")
	}
	if _, err := restarted.CheckAndBind(tenantA, "app", 3); err != nil {
		t.Fatalf("compliant epoch after restart: %v", err)
	}
}

func TestDelegationRejectsUnprojectableFloorBeforeSigning(t *testing.T) {
	store := delegation.NewDurableScopeStore(t.TempDir())
	called := false
	_, err := store.Apply(delegation.Command{
		TenantID: "11111111-1111-1111-1111-111111111111", OperationID: "overflow",
		Kind: "scope", ScopeID: "root", EpochFloor: uint64(math.MaxInt64) + 1,
	}, func(string, []byte) ([]byte, []byte, error) {
		called = true
		return nil, nil, nil
	})
	if err == nil || called {
		t.Fatalf("unprojectable floor reached signing: err=%v signed=%v", err, called)
	}
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Apply(delegation.Command{
		TenantID: "11111111-1111-1111-1111-111111111111", OperationID: "maximum",
		Kind: "scope", ScopeID: "root", EpochFloor: uint64(math.MaxInt64),
	}, func(_ string, body []byte) ([]byte, []byte, error) {
		sig, err := key.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
		return key.Public().DER, sig, err
	})
	if err != nil || receipt.AppliedFloor != uint64(math.MaxInt64) {
		t.Fatalf("projectable boundary floor refused: receipt=%+v err=%v", receipt, err)
	}
}
