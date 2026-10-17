// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/recovery"
)

func TestOfflinePCASRecoveryDistinctCustodiansAndExactSuccessor(t *testing.T) {
	dir := t.TempDir()
	key := func(id string) (string, recovery.Approver) {
		t.Helper()
		priv := filepath.Join(dir, id+".key")
		pub := filepath.Join(dir, id+".json")
		if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "keygen", ID: id, PrivateOut: priv, PublicOut: pub}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(priv)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key must be owner-only: %v", err)
		}
		var approver recovery.Approver
		readTestJSON(t, pub, &approver)
		if approver.ID != id || len(approver.PubDER) == 0 {
			t.Fatalf("public roster entry not bound to ID %q", id)
		}
		return priv, approver
	}
	rootKey, root := key("root")
	aKey, a := key("custodian-a")
	bKey, b := key("custodian-b")
	policyPath := filepath.Join(dir, "policy.json")
	policy := pcasOfflinePolicy{IdentityID: "identity-1", Threshold: 2, Roster: []recovery.Approver{a, b}, TrustRootDER: root.PubDER}
	writeTestJSON(t, policyPath, policy)
	chainPath := filepath.Join(dir, "chain.json")
	rootRaw, err := os.ReadFile(rootKey) // #nosec G304 -- path is under t.TempDir from this test's keygen (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootRaw)
	if block == nil {
		t.Fatal("keygen did not write PKCS#8 PEM")
	}
	rootSigner, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP384, block.Bytes)
	secret.Wipe(rootRaw)
	secret.Wipe(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer rootSigner.Destroy()
	genesis := succession.GenesisRecord{IdentityID: "identity-1", TenantID: "tenant-1", DeploymentScope: "qa-scope",
		Algorithm: crypto.ECDSAP384, PublicKey: root.PubDER, Epoch: 0}
	digest, err := succession.GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	genesis.TrustRootAtt, err = crypto.SignMessage(rootSigner, digest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, chainPath, map[string]any{"identity_id": "identity-1", "genesis": genesis,
		"trust_root_public_der": root.PubDER, "records": [][]byte{}, "count": 0})
	successorPath := filepath.Join(dir, "successor.json")
	prepared := succession.RecoverySuccessorPreparedV1{TenantID: "tenant-1", IdentityID: "identity-1",
		DeploymentScope: "qa-scope", Epoch: 1, Algorithm: "ECDSA-P384", PublicKeyDER: root.PubDER,
		Handle: succession.TenantKeyHandle("tenant-1", "identity-1", 1), RequestID: "prepare-1"}
	message, err := succession.RecoverySuccessorSigningMessage(prepared)
	if err != nil {
		t.Fatal(err)
	}
	prepared.SignerSignature, err = crypto.SignMessage(rootSigner, message)
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, successorPath, map[string]any{
		"tenant_id": prepared.TenantID, "identity_id": prepared.IdentityID,
		"deployment_scope": prepared.DeploymentScope, "epoch": prepared.Epoch,
		"algorithm": prepared.Algorithm, "public_key_der": prepared.PublicKeyDER, "handle": prepared.Handle,
		"request_id": prepared.RequestID, "signer_signature": prepared.SignerSignature,
		"event_id": succession.RecoverySuccessorEventID("tenant-1", "identity-1", 1),
	})
	statementPath := filepath.Join(dir, "statement.json")
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "statement", ChainFile: chainPath, SuccessorFile: successorPath,
		PinnedRootFile: filepath.Join(dir, "root.json"), Nonce: "incident-unique-1", Output: statementPath}); err != nil {
		t.Fatal(err)
	}
	var statement recovery.RecoveryStatement
	readTestJSON(t, statementPath, &statement)
	if statement.TenantID != "tenant-1" || statement.IdentityID != "identity-1" || statement.Epoch != 1 || statement.Nonce != "incident-unique-1" {
		t.Fatalf("statement did not bind the live public artifacts: %+v", statement)
	}
	rosterPath := filepath.Join(dir, "roster-sig.json")
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "roster", PolicyFile: policyPath, PrivateKey: rootKey, Output: rosterPath}); err != nil {
		t.Fatal(err)
	}
	aApproval := filepath.Join(dir, "a-approval.json")
	bApproval := filepath.Join(dir, "b-approval.json")
	for _, tc := range []struct{ key, id, out string }{{aKey, a.ID, aApproval}, {bKey, b.ID, bApproval}} {
		if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "approve", StatementFile: statementPath, PrivateKey: tc.key,
			ID: tc.id, PolicyFile: policyPath, ChainFile: chainPath, SuccessorFile: successorPath,
			PinnedRootFile: filepath.Join(dir, "root.json"), Output: tc.out}); err != nil {
			t.Fatal(err)
		}
	}
	var approvals []recovery.Approval
	for _, path := range []string{aApproval, bApproval} {
		var approval recovery.Approval
		readTestJSON(t, path, &approval)
		approvals = append(approvals, approval)
	}
	approvalsPath := filepath.Join(dir, "approvals.json")
	writeTestJSON(t, approvalsPath, approvals)
	assembledPath := filepath.Join(dir, "authorization.json")
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "assemble", PolicyFile: policyPath, StatementFile: statementPath,
		RosterSignatureFile: rosterPath, ApprovalsFile: approvalsPath, Output: assembledPath}); err != nil {
		t.Fatal(err)
	}
	var assembled recovery.RecoveryAuthorization
	readTestJSON(t, assembledPath, &assembled)
	if err := recovery.VerifyAuthorization(assembled, root.PubDER, recovery.Expected{IdentityID: "identity-1", TenantID: "tenant-1", Epoch: 1, SuccessorAlg: "ECDSA-P384", SuccessorPub: root.PubDER}); err != nil {
		t.Fatalf("assembled authorization not independently verifiable: %v", err)
	}
	assembled.Approvals = assembled.Approvals[:1]
	writeTestJSON(t, filepath.Join(dir, "one-approval.json"), assembled.Approvals)
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "assemble", PolicyFile: policyPath, StatementFile: statementPath,
		RosterSignatureFile: rosterPath, ApprovalsFile: filepath.Join(dir, "one-approval.json"), Output: filepath.Join(dir, "invalid.json")}); err == nil {
		t.Fatal("one custodian cannot satisfy a 2-of-2 recovery")
	}
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "approve", StatementFile: statementPath, PrivateKey: rootKey,
		ID: a.ID, PolicyFile: policyPath, ChainFile: chainPath, SuccessorFile: successorPath,
		PinnedRootFile: filepath.Join(dir, "root.json"), Output: filepath.Join(dir, "wrong-key.json")}); err == nil {
		t.Fatal("root key cannot impersonate a rostered custodian")
	}
	writeTestJSON(t, successorPath+".wrong", map[string]any{
		"identity_id": "identity-1", "deployment_scope": "wrong-scope", "epoch": 1,
		"algorithm": "ECDSA-P384", "public_key_der": root.PubDER, "signer_signature": []byte("signed-receipt"), "event_id": "prepared-event",
	})
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "statement", ChainFile: chainPath, SuccessorFile: successorPath + ".wrong",
		PinnedRootFile: filepath.Join(dir, "root.json"), Nonce: "x", Output: filepath.Join(dir, "wrong-statement.json")}); err == nil {
		t.Fatal("statement must reject another deployment scope")
	}
	writeTestJSON(t, successorPath+".forged", map[string]any{
		"tenant_id": prepared.TenantID, "identity_id": prepared.IdentityID,
		"deployment_scope": prepared.DeploymentScope, "epoch": prepared.Epoch,
		"algorithm": prepared.Algorithm, "public_key_der": prepared.PublicKeyDER, "handle": prepared.Handle,
		"request_id": prepared.RequestID, "signer_signature": []byte("forged-signature"),
		"event_id": succession.RecoverySuccessorEventID("tenant-1", "identity-1", 1),
	})
	if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: "statement", ChainFile: chainPath, SuccessorFile: successorPath + ".forged",
		PinnedRootFile: filepath.Join(dir, "root.json"), Nonce: "incident-unique-1", Output: filepath.Join(dir, "forged-statement.json")}); err == nil {
		t.Fatal("statement must verify the prepared successor's signer signature")
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test helper reads only t.TempDir fixture paths (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}
