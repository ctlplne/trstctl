package ssh

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
)

type sshStubAtt struct{}

func (sshStubAtt) Method() string { return "k8s_sat" }
func (sshStubAtt) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errors.New("forged")
	}
	return attest.Attestation{Subject: "ns/default/sa/web", Claims: map[string]string{"sa": "web"}}, nil
}

func newAttestedIssuer(t *testing.T, rec auditsink.Auditor) (*AttestedUserCertIssuer, *CA) {
	t.Helper()
	ca, _ := newCA(t, rec)
	v, err := attest.NewVerifier(attest.Config{TenantID: "t1", Attestors: []attest.Attestor{sshStubAtt{}}})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewAttestedUserCertIssuer(AttestedConfig{
		TenantID: "t1", CA: ca, Verifier: v,
		Profile: Profile{Name: "attested-user", MaxTTL: time.Hour, AllowUserCerts: true},
		TTL:     10 * time.Minute,
		Principals: func(a attest.Attestation) []string {
			return []string{a.Claims["sa"]}
		},
		Audit: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss, ca
}

func TestAttestedSSHIssuesOnlyWithValidAttestation(t *testing.T) {
	rec := &auditsink.Recorder{}
	iss, ca := newAttestedIssuer(t, rec)

	// Forged attestation -> refused, nothing issued.
	if _, _, err := iss.Issue(context.Background(), AttestedRequest{
		Method: "k8s_sat", Payload: []byte("forged"), SubjectPublicKey: subjectKey(t), Approver: "security-approver",
	}); err == nil {
		t.Fatal("issued an SSH user cert without a valid attestation")
	}

	// Genuine attestation -> issued, principal derived from the verified identity.
	issued, att, err := iss.Issue(context.Background(), AttestedRequest{
		Method: "k8s_sat", Payload: []byte("genuine"), SubjectPublicKey: subjectKey(t), Approver: "security-approver",
		Principals:      []string{"web"},
		CriticalOptions: map[string]string{"source-address": "10.0.0.0/24", "force-command": "/usr/local/bin/deploy"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if att.Subject != "ns/default/sa/web" {
		t.Errorf("attestation subject = %q", att.Subject)
	}
	caPub, _ := ca.AuthorityKey()
	caKey, _, _, _, _ := xssh.ParseAuthorizedKey(caPub)
	parsed, _, _, _, _ := xssh.ParseAuthorizedKey(issued.Certificate)
	cert := parsed.(*xssh.Certificate)
	chk := &xssh.CertChecker{
		SupportedCriticalOptions: []string{"source-address", "force-command"},
		IsUserAuthority:          func(a xssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) },
	}
	if err := chk.CheckCert("web", cert); err != nil {
		t.Fatalf("attested cert failed validation for derived principal: %v", err)
	}
	if got := cert.CriticalOptions["source-address"]; got != "10.0.0.0/24" {
		t.Fatalf("source-address critical option = %q", got)
	}
	if got := cert.CriticalOptions["force-command"]; got != "/usr/local/bin/deploy" {
		t.Fatalf("force-command critical option = %q", got)
	}
	// short TTL honored
	life := time.Until(issued.ValidBefore)
	if life < 8*time.Minute || life > 12*time.Minute {
		t.Errorf("ttl = %v, want ~10m", life)
	}
	if rec.Count("ssh.attested_cert.issued") != 1 {
		t.Error("attested issuance not audited")
	}
}

func TestAttestedSSHRejectsSelfApprovalAndUnboundPrincipal(t *testing.T) {
	rec := &auditsink.Recorder{}
	iss, _ := newAttestedIssuer(t, rec)
	base := AttestedRequest{Method: "k8s_sat", Payload: []byte("genuine"), SubjectPublicKey: subjectKey(t)}
	if _, _, err := iss.Issue(context.Background(), base); err == nil {
		t.Fatal("issued an SSH user cert without an approver")
	}
	self := base
	self.Approver = "ns/default/sa/web"
	if _, _, err := iss.Issue(context.Background(), self); err == nil {
		t.Fatal("issued an SSH user cert with self-approval")
	}
	unbound := base
	unbound.Approver = "security-approver"
	unbound.Principals = []string{"root"}
	if _, _, err := iss.Issue(context.Background(), unbound); err == nil {
		t.Fatal("issued an SSH user cert for a principal not bound to the attestation")
	}
	if rec.Count("ssh.attested_cert.issued") != 0 {
		t.Fatal("rejected attested SSH issuance should not emit issued event")
	}
}
