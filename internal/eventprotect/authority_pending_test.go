// SPDX-License-Identifier: BUSL-1.1
package eventprotect

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestPendingDestructionProbeRefusesUnexplainedLossAndForeignCreation(t *testing.T) {
	authority, _, request, grant, _ := destructionFixture(t)
	creation, err := authority.CreationEvidence(t.Context(), request.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if got, pending, err := authority.PendingDestruction(t.Context(), creation); err != nil || pending || got != (DestructionRequest{}) || grant.calls != 0 {
		t.Fatalf("active material became a pending grant: %v", err)
	}
	foreign := creation
	foreign.Probe = bytes.Clone(creation.Probe)
	foreign.Probe[0] ^= 1
	if _, pending, err := authority.PendingDestruction(t.Context(), foreign); err == nil || pending {
		t.Fatal("foreign creation accepted")
	}
	if err := authority.root.Remove(keyName(request.Ref)); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := authority.PendingDestruction(t.Context(), creation); !errors.Is(err, ErrKey) || pending || grant.calls != 0 {
		t.Fatalf("unexplained key loss entered recovery: %v", err)
	}
}

func TestPendingDestructionProbeIsReadOnlyWithoutSignerOrRemovalAuthority(t *testing.T) {
	authority, cfg, request, grant, _ := destructionFixture(t)
	creation, err := authority.CreationEvidence(t.Context(), request.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	locked, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Destroy)
	local, err := jose.NewDigestSigningKey("pending-read-component-fixture", locked)
	if err != nil {
		t.Fatal(err)
	}
	remote := &interruptibleEvidenceSigner{key: local, fail: true}
	cfg.EvidenceKey, err = jose.NewArtifactSigningKey("pending-read-component-fixture", locked.Public(), remote)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	interrupted.now = authority.now
	if receipt, err := interrupted.Destroy(t.Context(), request); err == nil || receipt != "" {
		t.Fatal("fixture did not interrupt after removal")
	}
	before, err := os.ReadFile(cfg.Directory + string(os.PathSeparator) + recordName(request.Ref))
	if err != nil {
		t.Fatal(err)
	}
	if err := interrupted.Close(); err != nil {
		t.Fatal(err)
	}
	calls := grant.calls
	cfg.EvidenceKey = nil
	cfg.DestructionAuthority = nil
	cfg.VerificationKeys = local.JWKS()
	reader, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	got, pending, err := reader.PendingDestruction(t.Context(), creation)
	if err != nil || !pending || !sameDestructionRequest(got, request) || grant.calls != calls {
		t.Fatalf("read-only pending identity missing or authorized new removal: %v", err)
	}
	after, err := os.ReadFile(cfg.Directory + string(os.PathSeparator) + recordName(request.Ref))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("pending read changed durable journal")
	}
	if _, err := reader.root.Lstat(keyName(request.Ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending read recreated material")
	}
	if receipt, erased, err := reader.DestructionReceipt(t.Context(), request.Ref); err == nil || erased || receipt != "" {
		t.Fatal("pending probe became completed erasure proof")
	}
}

func TestPendingDestructionProbePreservesMaterialBeforeUnlinkAndRejectsFalseRemovalTime(t *testing.T) {
	authority, _, request, grant, _ := destructionFixture(t)
	creation, err := authority.CreationEvidence(t.Context(), request.Ref)
	if err != nil {
		t.Fatal(err)
	}
	record, found, err := authority.readRecord(request.Ref)
	if err != nil || !found {
		t.Fatal(err)
	}
	record.Phase = "destroying"
	record.Destruction = &fileDestruction{Request: request}
	if err := authority.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	if got, pending, err := authority.PendingDestruction(t.Context(), creation); err != nil || !pending || !sameDestructionRequest(got, request) || grant.calls != 0 {
		t.Fatalf("before-unlink journal lost its read-only identity: %v", err)
	}
	if _, err := authority.root.Lstat(keyName(request.Ref)); err != nil {
		t.Fatal("pending probe removed original material")
	}
	record.Destruction.RemovedAt = request.NotBefore
	if err := authority.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := authority.PendingDestruction(t.Context(), creation); !errors.Is(err, ErrKey) || pending || grant.calls != 0 {
		t.Fatalf("present material accepted recorded absence: %v", err)
	}
}
