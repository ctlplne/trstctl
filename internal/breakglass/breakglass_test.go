// SPDX-License-Identifier: BUSL-1.1

package breakglass

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func newService(t *testing.T) (*Service, []byte) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Break-glass CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{
		TenantID: "t1", CACertDER: caDER, CASigner: ca,
		Quorum: Quorum{Threshold: 2, Operators: []string{"op1", "op2", "op3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, caDER
}

func emergencyCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	wl, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wl.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName}, wl)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestBreakglassQuorumIssuesAndVerifies(t *testing.T) {
	svc, caDER := newService(t)
	b, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "emergency-svc", CSRDer: emergencyCSR(t, "emergency-svc"), Reason: "control plane down",
		Approvals: []string{"op1", "op2"},
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("IssueOffline: %v", err)
	}
	if err := Verify(b, caDER, svc.PublicKeyDER()); err != nil {
		t.Fatalf("bundle does not verify: %v", err)
	}
}

func TestBreakglassOfflineSignerRejectsMisleadingSubject(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "identity-mismatch", Subject: "reviewed.example", CSRDer: emergencyCSR(t, "signed.example"),
		Reason: "recovery", Approvals: []string{"op1", "op2"},
	}, time.Minute); err == nil {
		t.Fatal("offline signer issued a certificate for a name other than the reviewed subject")
	}
}

func TestBreakglassSubQuorumRefused(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "x", CSRDer: emergencyCSR(t, "x"), Reason: "outage", Approvals: []string{"op1"},
	}, time.Hour); err == nil {
		t.Error("issued below the m-of-n quorum")
	}
}

func TestBreakglassUnauthorizedOperatorRefused(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "x", CSRDer: emergencyCSR(t, "x"), Reason: "outage", Approvals: []string{"op1", "intruder"},
	}, time.Hour); err == nil {
		t.Error("issued with an unauthorized operator in the quorum")
	}
}

func TestBreakglassTamperDetected(t *testing.T) {
	svc, caDER := newService(t)
	b, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "svc", CSRDer: emergencyCSR(t, "svc"), Reason: "outage", Approvals: []string{"op1", "op2"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tampered := b
	tampered.Reason = "exfiltrate" // change a manifest-covered field
	if err := Verify(tampered, caDER, svc.PublicKeyDER()); err == nil {
		t.Error("a tampered bundle verified")
	}
}

func TestBreakglassVerifyBatchAcceptsSignedBundlesAndRejectsTamper(t *testing.T) {
	svc, caDER := newService(t)
	mk := func(id string) Bundle {
		b, err := svc.IssueOffline(EmergencyRequest{
			ID: id, Subject: "svc-" + id, CSRDer: emergencyCSR(t, "svc-"+id), Reason: "outage", Approvals: []string{"op1", "op3"},
		}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := []Bundle{mk("e1"), mk("e2")}
	if err := VerifyBatch(good, caDER, svc.PublicKeyDER()); err != nil {
		t.Fatalf("verify signed bundle batch: %v", err)
	}

	bad := mk("e3")
	bad.Subject = "rewritten"
	if err := VerifyBatch([]Bundle{bad}, caDER, svc.PublicKeyDER()); err == nil {
		t.Error("batch verifier accepted a tampered bundle")
	}
}

func TestBreakglassVerifyBatchRejectsTamperedTail(t *testing.T) {
	svc, caDER := newService(t)
	makeBundle := func(id string) Bundle {
		t.Helper()
		b, err := svc.IssueOffline(EmergencyRequest{
			ID: id, Subject: "svc-" + id, CSRDer: emergencyCSR(t, "svc-"+id),
			Reason: "outage", Approvals: []string{"op1", "op2"},
		}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := makeBundle("first")
	tampered := makeBundle("second")
	tampered.Reason = "changed after signature"
	if err := VerifyBatch([]Bundle{valid, tampered}, caDER, svc.PublicKeyDER()); err == nil {
		t.Fatal("batch verifier accepted a tampered tail")
	}
}
