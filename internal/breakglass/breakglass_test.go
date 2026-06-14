package breakglass

import (
	"context"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
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

func emergencyCSR(t *testing.T) []byte {
	t.Helper()
	wl, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wl.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "emergency-svc"}, wl)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestBreakglassQuorumIssuesAndVerifies(t *testing.T) {
	svc, caDER := newService(t)
	b, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "emergency-svc", CSRDer: emergencyCSR(t), Reason: "control plane down",
		Approvals: []string{"op1", "op2"},
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("IssueOffline: %v", err)
	}
	if err := Verify(b, caDER, svc.PublicKeyDER()); err != nil {
		t.Fatalf("bundle does not verify: %v", err)
	}
}

func TestBreakglassSubQuorumRefused(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "x", CSRDer: emergencyCSR(t), Reason: "outage", Approvals: []string{"op1"},
	}, time.Hour); err == nil {
		t.Error("issued below the m-of-n quorum")
	}
}

func TestBreakglassUnauthorizedOperatorRefused(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "x", CSRDer: emergencyCSR(t), Reason: "outage", Approvals: []string{"op1", "intruder"},
	}, time.Hour); err == nil {
		t.Error("issued with an unauthorized operator in the quorum")
	}
}

func TestBreakglassTamperDetected(t *testing.T) {
	svc, caDER := newService(t)
	b, err := svc.IssueOffline(EmergencyRequest{
		ID: "e1", Subject: "svc", CSRDer: emergencyCSR(t), Reason: "outage", Approvals: []string{"op1", "op2"},
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

func TestBreakglassReconcilesCleanlyAndRejectsTamper(t *testing.T) {
	svc, caDER := newService(t)
	mk := func(id string) Bundle {
		b, err := svc.IssueOffline(EmergencyRequest{
			ID: id, Subject: "svc-" + id, CSRDer: emergencyCSR(t), Reason: "outage", Approvals: []string{"op1", "op3"},
		}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := []Bundle{mk("e1"), mk("e2")}
	rec := &auditsink.Recorder{}
	n, err := Reconcile(context.Background(), "t1", good, caDER, svc.PublicKeyDER(), rec)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 2 || rec.Count("breakglass.issued") != 2 {
		t.Errorf("reconciled=%d audited=%d, want 2/2", n, rec.Count("breakglass.issued"))
	}

	bad := mk("e3")
	bad.Subject = "rewritten"
	if _, err := Reconcile(context.Background(), "t1", []Bundle{bad}, caDER, svc.PublicKeyDER(), &auditsink.Recorder{}); err == nil {
		t.Error("reconcile accepted a tampered bundle")
	}
}
