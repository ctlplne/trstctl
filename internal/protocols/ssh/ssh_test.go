package ssh

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func newCA(t *testing.T, rec auditsink.Auditor) (*CA, crypto.DigestSigner) {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	ca, err := New(Config{TenantID: "t1", Signer: caKey, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	return ca, caKey
}

func subjectKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	pub, err := crypto.SSHPublicKeyFromSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func validateWithOpenSSH(t *testing.T, cert []byte, wantPrincipal string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		// INTEROP-S3 (PROTECT): the stock-OpenSSH cross-check is the proof that
		// trstctl's SSH certs verify with the reference toolchain. Locally we skip
		// when ssh-keygen is absent, but CI sets TRSTCTL_REQUIRE_OPENSSH=1 so the
		// check is FORCED to run there (no skip-instead-of-fail on the gate) — a
		// runner without ssh-keygen then fails loudly instead of silently passing.
		if os.Getenv("TRSTCTL_REQUIRE_OPENSSH") != "" {
			t.Fatalf("TRSTCTL_REQUIRE_OPENSSH is set but ssh-keygen is not on PATH; the stock-OpenSSH SSH-cert cross-check cannot run (INTEROP-S3)")
		}
		t.Log("ssh-keygen not available; stock-OpenSSH check skipped (set TRSTCTL_REQUIRE_OPENSSH=1 to force, as CI does)")
		return
	}
	f := filepath.Join(t.TempDir(), "id-cert.pub")
	if err := os.WriteFile(f, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh-keygen", "-L", "-f", f).CombinedOutput()
	if err != nil {
		t.Fatalf("stock ssh-keygen rejected the certificate: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte(wantPrincipal)) {
		t.Errorf("ssh-keygen -L output missing principal %q:\n%s", wantPrincipal, out)
	}
}

func TestSSHCAIssuesValidUserCert(t *testing.T) {
	rec := &auditsink.Recorder{}
	ca, _ := newCA(t, rec)
	prof := Profile{Name: "user", MaxTTL: time.Hour, AllowUserCerts: true, DefaultExtensions: map[string]string{"permit-pty": ""}}
	iss, err := ca.IssueUserCert(context.Background(), prof, IssueRequest{
		SubjectPublicKey: subjectKey(t), KeyID: "alice@corp", Principals: []string{"alice"}, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueUserCert: %v", err)
	}
	caPub, _ := ca.AuthorityKey()
	caKey, _, _, _, _ := xssh.ParseAuthorizedKey(caPub)
	parsed, _, _, _, err := xssh.ParseAuthorizedKey(iss.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	cert := parsed.(*xssh.Certificate)
	chk := &xssh.CertChecker{IsUserAuthority: func(a xssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) }}
	if err := chk.CheckCert("alice", cert); err != nil {
		t.Fatalf("user cert failed validation: %v", err)
	}
	validateWithOpenSSH(t, iss.Certificate, "alice")
	if rec.Count("ssh.cert.issued") != 1 {
		t.Error("issuance not audited")
	}
}

func TestSSHCAIssuesValidHostCert(t *testing.T) {
	ca, _ := newCA(t, nil)
	prof := Profile{Name: "host", MaxTTL: time.Hour, AllowHostCerts: true}
	iss, err := ca.IssueHostCert(context.Background(), prof, IssueRequest{
		SubjectPublicKey: subjectKey(t), KeyID: "host1", Principals: []string{"host1.example.com"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueHostCert: %v", err)
	}
	caPub, _ := ca.AuthorityKey()
	caKey, _, _, _, _ := xssh.ParseAuthorizedKey(caPub)
	parsed, _, _, _, _ := xssh.ParseAuthorizedKey(iss.Certificate)
	cert := parsed.(*xssh.Certificate)
	chk := &xssh.CertChecker{IsHostAuthority: func(a xssh.PublicKey, _ string) bool { return bytes.Equal(a.Marshal(), caKey.Marshal()) }}
	if err := chk.CheckHostKey("host1.example.com:22", nil, cert); err != nil {
		t.Fatalf("host cert failed validation: %v", err)
	}
	validateWithOpenSSH(t, iss.Certificate, "host1.example.com")
}

func TestSSHProfileEnforcement(t *testing.T) {
	ca, _ := newCA(t, nil)
	sub := subjectKey(t)
	ctx := context.Background()
	userOnly := Profile{Name: "u", MaxTTL: time.Minute, AllowUserCerts: true}
	if _, err := ca.IssueUserCert(ctx, userOnly, IssueRequest{SubjectPublicKey: sub, Principals: []string{"a"}, TTL: time.Hour}); err == nil {
		t.Error("TTL over profile max was accepted")
	}
	if _, err := ca.IssueHostCert(ctx, userOnly, IssueRequest{SubjectPublicKey: sub, Principals: []string{"h"}, TTL: time.Minute}); err == nil {
		t.Error("host cert issued under a user-only profile")
	}
	if _, err := ca.IssueUserCert(ctx, userOnly, IssueRequest{SubjectPublicKey: sub, Principals: nil, TTL: time.Minute}); err == nil {
		t.Error("issued with no principals")
	}
}

func TestKRLRevocation(t *testing.T) {
	k := NewKRL()
	k.RevokeSerial(5)
	k.RevokeKeyID("bad@corp")
	if !k.IsRevoked(5, "x") {
		t.Error("serial 5 not revoked")
	}
	if !k.IsRevoked(99, "bad@corp") {
		t.Error("key id bad@corp not revoked")
	}
	if k.IsRevoked(1, "ok") {
		t.Error("false revocation")
	}
	snap := k.Distribute()
	if len(snap.Serials) != 1 || len(snap.KeyIDs) != 1 {
		t.Errorf("snapshot = %+v, want 1 serial + 1 key id", snap)
	}
}

func TestSSHCASerialsAreUnique(t *testing.T) {
	ca, _ := newCA(t, nil)
	prof := Profile{Name: "user", MaxTTL: time.Hour, AllowUserCerts: true}
	sub := subjectKey(t)
	a, _ := ca.IssueUserCert(context.Background(), prof, IssueRequest{SubjectPublicKey: sub, KeyID: "a", Principals: []string{"a"}, TTL: time.Minute})
	b, _ := ca.IssueUserCert(context.Background(), prof, IssueRequest{SubjectPublicKey: sub, KeyID: "b", Principals: []string{"b"}, TTL: time.Minute})
	if a.Serial == b.Serial {
		t.Errorf("serials not unique: %d == %d", a.Serial, b.Serial)
	}
}
