package crypto

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSignSSHUserAndHostCerts(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caPubB, err := SSHPublicKeyFromSigner(ca)
	if err != nil {
		t.Fatal(err)
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey(caPubB)
	if err != nil {
		t.Fatal(err)
	}
	subj, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Destroy()
	subjPub, err := SSHPublicKeyFromSigner(subj)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// User certificate, validated as stock OpenSSH would via CertChecker.
	userB, err := SignSSHCertificate(ca, SSHCertParams{
		SubjectPublicKey: subjPub, KeyID: "alice", Principals: []string{"alice"},
		CertType: SSHUserCert, ValidAfter: now.Add(-time.Minute), ValidBefore: now.Add(time.Hour),
		Extensions: map[string]string{"permit-pty": ""},
	})
	if err != nil {
		t.Fatalf("sign user cert: %v", err)
	}
	uparsed, _, _, _, err := ssh.ParseAuthorizedKey(userB)
	if err != nil {
		t.Fatal(err)
	}
	ucert, ok := uparsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("user: not a certificate")
	}
	ucheck := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) }}
	if err := ucheck.CheckCert("alice", ucert); err != nil {
		t.Fatalf("user cert failed validation: %v", err)
	}

	// Host certificate.
	hostB, err := SignSSHCertificate(ca, SSHCertParams{
		SubjectPublicKey: subjPub, KeyID: "host1", Principals: []string{"host1.example.com"},
		CertType: SSHHostCert, ValidAfter: now.Add(-time.Minute), ValidBefore: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	hparsed, _, _, _, err := ssh.ParseAuthorizedKey(hostB)
	if err != nil {
		t.Fatal(err)
	}
	hcert := hparsed.(*ssh.Certificate)
	hcheck := &ssh.CertChecker{IsHostAuthority: func(a ssh.PublicKey, _ string) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) }}
	if err := hcheck.CheckHostKey("host1.example.com:22", nil, hcert); err != nil {
		t.Fatalf("host cert failed validation: %v", err)
	}
}
