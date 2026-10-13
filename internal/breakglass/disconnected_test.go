// SPDX-License-Identifier: BUSL-1.1

package breakglass

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestDisconnectedApprovalBindsExactRequestAndDistinctCustodians(t *testing.T) {
	pubA, signA, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	policy := OfflinePolicy{
		TenantID: "tenant-a", DeploymentID: "lab-a", Epoch: 7,
		Threshold: 2, MaxTTLSeconds: 900, PermittedDNSSuffixes: []string{"example.test"},
		Custodians: []OfflineCustodian{{ID: "alice", PublicKeyDER: pubA}, {ID: "bob", PublicKeyDER: pubB}},
	}
	req := OfflineRequest{
		ID: "emergency-1", TenantID: "tenant-a", DeploymentID: "lab-a", Epoch: 7,
		CAKeySHA256: crypto.SHA256Hex([]byte("test recovery CA public key")),
		Requester:   "requester", Subject: "recovery.example.test", CSRDER: emergencyDNSCSR(t, "recovery.example.test"),
		Reason: "restore service", TTLSeconds: 600, ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	canonical, err := req.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	approvals := []OfflineApproval{{CustodianID: "alice", Signature: signA(canonical)}, {CustodianID: "bob", Signature: signB(canonical)}}
	if err := VerifyOfflineApprovals(policy, req, approvals, time.Now()); err != nil {
		t.Fatalf("valid two-custodian request: %v", err)
	}
	for name, change := range map[string]func(*OfflineRequest){
		"tenant":     func(r *OfflineRequest) { r.TenantID = "tenant-b" },
		"deployment": func(r *OfflineRequest) { r.DeploymentID = "lab-b" },
		"epoch":      func(r *OfflineRequest) { r.Epoch++ },
		"ca_key":     func(r *OfflineRequest) { r.CAKeySHA256 = crypto.SHA256Hex([]byte("other recovery CA")) },
		"subject":    func(r *OfflineRequest) { r.Subject = "other.example.test" },
		"reason":     func(r *OfflineRequest) { r.Reason = "other" },
		"ttl":        func(r *OfflineRequest) { r.TTLSeconds++ },
		"requester":  func(r *OfflineRequest) { r.Requester = "alice" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := req
			change(&altered)
			if VerifyOfflineApprovals(policy, altered, approvals, time.Now()) == nil {
				t.Fatal("accepted altered signed request")
			}
		})
	}
	if VerifyOfflineApprovals(policy, req, approvals[:1], time.Now()) == nil {
		t.Fatal("accepted one custodian")
	}
	if VerifyOfflineApprovals(policy, req, []OfflineApproval{approvals[0], approvals[0]}, time.Now()) == nil {
		t.Fatal("accepted duplicate custodian")
	}
	if VerifyOfflineApprovals(policy, req, approvals, req.ExpiresAt.Add(time.Second)) == nil {
		t.Fatal("accepted expired request")
	}
	self := req
	self.Requester = "alice"
	selfBytes, err := self.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyOfflineApprovals(policy, self, []OfflineApproval{{CustodianID: "alice", Signature: signA(selfBytes)}, {CustodianID: "bob", Signature: signB(selfBytes)}}, time.Now()) == nil {
		t.Fatal("accepted requester self-approval")
	}
}

func TestDisconnectedBundleCarriesVerifiableCustodianEvidence(t *testing.T) {
	svc, caDER := newService(t)
	pubA, signA, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	policy := OfflinePolicy{TenantID: "t1", DeploymentID: "qa-deployment", Epoch: 1,
		Threshold: 2, MaxTTLSeconds: 900, PermittedDNSSuffixes: []string{"example.test"},
		Custodians: []OfflineCustodian{{ID: "op1", PublicKeyDER: pubA}, {ID: "op2", PublicKeyDER: pubB}}}
	req := OfflineRequest{ID: "offline-1", TenantID: "t1", DeploymentID: "qa-deployment", Epoch: 1,
		CAKeySHA256: crypto.SHA256Hex(svc.PublicKeyDER()),
		Requester:   "incident-commander", Subject: "recovery.example.test", CSRDER: emergencyDNSCSR(t, "recovery.example.test"),
		Reason: "control plane outage", TTLSeconds: 600, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	message, err := req.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	approvals := []OfflineApproval{{CustodianID: "op1", Signature: signA(message)}, {CustodianID: "op2", Signature: signB(message)}}
	bundle, err := svc.IssueDisconnected(policy, req, approvals)
	if err != nil {
		t.Fatalf("sign two-custodian offline request: %v", err)
	}
	if err := VerifyDisconnected(bundle, policy, caDER, svc.PublicKeyDER()); err != nil {
		t.Fatalf("verify signed offline bundle: %v", err)
	}
	altered := bundle
	altered.OfflineApprovals = append([]OfflineApproval(nil), bundle.OfflineApprovals...)
	altered.OfflineApprovals[0].Signature = []byte("forged")
	if err := VerifyDisconnected(altered, policy, caDER, svc.PublicKeyDER()); err == nil {
		t.Fatal("accepted tampered approval evidence")
	}
	other := policy
	other.TenantID = "another-tenant"
	if err := VerifyDisconnected(bundle, other, caDER, svc.PublicKeyDER()); err == nil {
		t.Fatal("accepted other tenant's bundle")
	}
}

func emergencyDNSCSR(t *testing.T, name string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: name, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
