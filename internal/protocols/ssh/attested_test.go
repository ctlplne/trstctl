package ssh

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"trustctl.io/trustctl/internal/attest"
	"trustctl.io/trustctl/internal/auditsink"
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
		Method: "k8s_sat", Payload: []byte("forged"), SubjectPublicKey: subjectKey(t),
	}); err == nil {
		t.Fatal("issued an SSH user cert without a valid attestation")
	}

	// Genuine attestation -> issued, principal derived from the verified identity.
	issued, att, err := iss.Issue(context.Background(), AttestedRequest{
		Method: "k8s_sat", Payload: []byte("genuine"), SubjectPublicKey: subjectKey(t),
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
	chk := &xssh.CertChecker{IsUserAuthority: func(a xssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) }}
	if err := chk.CheckCert("web", cert); err != nil {
		t.Fatalf("attested cert failed validation for derived principal: %v", err)
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
