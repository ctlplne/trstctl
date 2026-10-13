// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/breakglass/offline"
	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestOfflineVaultSignerCustodyAndColdReplay(t *testing.T) {
	wrapper := inPackageTestKEK(t)
	dir := t.TempDir()
	vault, err := NewOfflineBreakglassVault(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	pubA, signA, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	policy := offline.OfflinePolicy{TenantID: "tenant-a", DeploymentID: "lab-a", Epoch: 3,
		Threshold: 2, MaxTTLSeconds: 900, PermittedDNSSuffixes: []string{"example.test"},
		Custodians: []offline.OfflineCustodian{{ID: "alice", PublicKeyDER: pubA}, {ID: "bob", PublicKeyDER: pubB}}}
	kit, err := vault.Provision(policy, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflineBreakglassKit(kit); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Provision(policy, 24*time.Hour); err == nil {
		t.Fatal("reprovisioned committed recovery authority")
	}

	// Even if the offline store is mistakenly opened as a generic gRPC signer,
	// socket access plus the known handle cannot use the recovery CA.
	generic, err := NewPersistentServer(NewKeyStore(dir, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	_, err = generic.Sign(context.Background(), &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: offlineBreakglassHandle},
		Digest: bytes.Repeat([]byte{0x42}, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("generic Sign code=%s err=%v", status.Code(err), err)
	}

	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "recovery.example.test", DNSNames: []string{"recovery.example.test"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	req := offline.OfflineRequest{ID: "operation-1", TenantID: policy.TenantID, DeploymentID: policy.DeploymentID,
		Epoch: policy.Epoch, CAKeySHA256: crypto.SHA256Hex(kit.PublicKeyDER), Requester: "incident-commander", Subject: "recovery.example.test",
		CSRDER: csr, Reason: "restore workload", TTLSeconds: 600, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	message, err := req.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	approvals := []offline.OfflineApproval{{CustodianID: "alice", Signature: signA(message)}, {CustodianID: "bob", Signature: signB(message)}}
	if _, _, err := vault.Issue(req, approvals[:1]); err == nil {
		t.Fatal("one custodian issued a certificate")
	}
	first, replayed, err := vault.Issue(req, approvals)
	if err != nil || replayed {
		t.Fatalf("first offline issue replayed=%v err=%v", replayed, err)
	}
	if err := offline.VerifyDisconnected(first, policy, kit.CACertDER, kit.PublicKeyDER); err != nil {
		t.Fatal(err)
	}
	// Replacing a kit while retaining the same roster, policy epoch and request
	// must not let another CA use approvals obtained for the first CA.
	other, err := NewOfflineBreakglassVault(t.TempDir(), wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Provision(policy, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.Issue(req, approvals); err == nil {
		t.Fatal("second recovery CA reused approvals signed for the first CA")
	}

	// A new process opens the same sealed key and journal after the first process
	// has exited. It must return the byte-identical randomized certificate.
	restarted, err := NewOfflineBreakglassVault(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	second, replayed, err := restarted.Issue(req, approvals)
	if err != nil || !replayed {
		t.Fatalf("cold replay replayed=%v err=%v", replayed, err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("cold replay returned different bundle bytes")
	}
	changed := req
	changed.Reason = "different reason"
	if _, _, err := restarted.Issue(changed, approvals); err == nil {
		t.Fatal("changed operation ID tuple was accepted")
	}

	// The journal is sealed, while the public kit can be copied to recovery.
	journal, err := os.ReadFile(vault.journalPath(req.ID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(journal, []byte("restore workload")) {
		t.Fatal("journal disclosed incident text")
	}
}

func TestOfflineVaultResumesExecutingMarkerAfterCrash(t *testing.T) {
	wrapper := inPackageTestKEK(t)
	dir := t.TempDir()
	vault, err := NewOfflineBreakglassVault(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	pubA, signA, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	policy := offline.OfflinePolicy{TenantID: "tenant-a", DeploymentID: "lab-a", Epoch: 1,
		Threshold: 2, MaxTTLSeconds: 900, PermittedDNSSuffixes: []string{"example.test"},
		Custodians: []offline.OfflineCustodian{{ID: "alice", PublicKeyDER: pubA}, {ID: "bob", PublicKeyDER: pubB}}}
	kit, err := vault.Provision(policy, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "recovery.example.test", DNSNames: []string{"recovery.example.test"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	req := offline.OfflineRequest{ID: "crashed-operation", TenantID: policy.TenantID,
		DeploymentID: policy.DeploymentID, Epoch: policy.Epoch,
		CAKeySHA256: crypto.SHA256Hex(kit.PublicKeyDER), Requester: "commander",
		Subject: "recovery.example.test", CSRDER: csr, Reason: "recovery",
		TTLSeconds: 600, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	message, err := req.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	approvals := []offline.OfflineApproval{{CustodianID: "alice", Signature: signA(message)},
		{CustodianID: "bob", Signature: signB(message)}}
	intent, err := json.Marshal(struct {
		Request   offline.OfflineRequest    `json:"request"`
		Approvals []offline.OfflineApproval `json:"approvals"`
	}{req, approvals})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vault.journalPath(req.ID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := vault.writeOfflineJournal(offlineJournalRecord{Version: 1, OperationID: req.ID,
		RequestHash: crypto.SHA256Hex(intent), State: "executing"}, false); err != nil {
		t.Fatal(err)
	}
	// A process can die after the executing marker but before a completed
	// result. The replacement must resume with the same signed intent.
	restarted, err := NewOfflineBreakglassVault(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	first, replayed, err := restarted.Issue(req, approvals)
	if err != nil || replayed {
		t.Fatalf("resume executing marker replayed=%v err=%v", replayed, err)
	}
	second, replayed, err := restarted.Issue(req, approvals)
	if err != nil || !replayed {
		t.Fatalf("replay completed result replayed=%v err=%v", replayed, err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("completed crash recovery changed certificate bytes")
	}
}
