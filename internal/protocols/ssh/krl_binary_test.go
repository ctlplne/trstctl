package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// readSSHString reads an SSH wire string (uint32 length + bytes) from b, returning
// the body and the remainder. ok is false on truncation.
func readSSHString(b []byte) (body, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(len(b)-4) < uint64(n) {
		return nil, b, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// TestDistributeKRLBinaryStructure is the INTEROP-009 structural acceptance: the KRL
// must be the OpenSSH binary KRL format (magic + framed sections), not the old JSON
// snapshot. It decodes the header and the certificates section and confirms the
// revoked serial appears in the serial-list sub-section and the revoked key-id in
// the key-id sub-section — proving the wire framing, with no external tool needed.
func TestDistributeKRLBinaryStructure(t *testing.T) {
	k := NewKRL()
	k.RevokeSerial(0x1122334455667788)
	k.RevokeSerial(42)
	k.RevokeKeyID("compromised@corp")

	blob := k.DistributeKRL(7)

	// Magic.
	if !bytes.HasPrefix(blob, []byte(krlMagic)) {
		t.Fatalf("KRL does not start with the OpenSSH magic %q; got %q (still JSON?)", krlMagic, blob[:min(8, len(blob))])
	}
	p := blob[len(krlMagic):]

	if len(p) < 4 {
		t.Fatal("truncated after magic")
	}
	if v := binary.BigEndian.Uint32(p[:4]); v != krlFormatVersion {
		t.Errorf("format version = %d, want %d", v, krlFormatVersion)
	}
	p = p[4:]
	if len(p) < 8 || binary.BigEndian.Uint64(p[:8]) != 7 {
		t.Errorf("krl_version not 7")
	}
	p = p[8:]                    // krl_version
	p = p[8:]                    // generated_date
	p = p[8:]                    // flags
	_, p, ok := readSSHString(p) // reserved
	if !ok {
		t.Fatal("truncated reserved")
	}
	_, p, ok = readSSHString(p) // comment
	if !ok {
		t.Fatal("truncated comment")
	}

	// First (only) top-level section must be KRL_SECTION_CERTIFICATES.
	if len(p) < 1 || p[0] != krlSectionCertificates {
		t.Fatalf("first section type = %d, want KRL_SECTION_CERTIFICATES(%d)", p[0], krlSectionCertificates)
	}
	p = p[1:]
	cert, _, ok := readSSHString(p)
	if !ok {
		t.Fatal("truncated certificates section")
	}

	// Within the certificates section: ca_key (wildcard ""), reserved, then sub-sections.
	caKey, cert, ok := readSSHString(cert)
	if !ok {
		t.Fatal("truncated ca_key")
	}
	if len(caKey) != 0 {
		t.Errorf("ca_key is %q, want empty (wildcard, applies to all CAs)", caKey)
	}
	_, cert, ok = readSSHString(cert) // reserved
	if !ok {
		t.Fatal("truncated cert-section reserved")
	}

	sawSerials, sawKeyIDs := false, false
	for len(cert) > 0 {
		sub := cert[0]
		cert = cert[1:]
		body, rest, ok := readSSHString(cert)
		if !ok {
			t.Fatal("truncated cert sub-section")
		}
		cert = rest
		switch sub {
		case krlSectionCertSerialList:
			sawSerials = true
			var serials []uint64
			for len(body) >= 8 {
				serials = append(serials, binary.BigEndian.Uint64(body[:8]))
				body = body[8:]
			}
			if !containsU64(serials, 42) || !containsU64(serials, 0x1122334455667788) {
				t.Errorf("serial list %x missing a revoked serial", serials)
			}
		case krlSectionCertKeyID:
			sawKeyIDs = true
			var ids []string
			for len(body) > 0 {
				s, rest, ok := readSSHString(body)
				if !ok {
					t.Fatal("truncated key-id entry")
				}
				ids = append(ids, string(s))
				body = rest
			}
			if !containsStr(ids, "compromised@corp") {
				t.Errorf("key-id list %v missing the revoked key id", ids)
			}
		}
	}
	if !sawSerials || !sawKeyIDs {
		t.Errorf("KRL missing sub-sections (serials=%v keyIDs=%v)", sawSerials, sawKeyIDs)
	}
}

// TestDistributeKRLLoadsInOpenSSH is the INTEROP-009 end-to-end acceptance: stock
// `ssh-keygen -Q -f <krl> <cert>` must report a certificate as revoked using
// trstctl's distributed KRL. Pre-fix Distribute() returned JSON that sshd/ssh-keygen
// cannot parse, so revocation never reached hosts. Skips when ssh-keygen is absent
// (the structural test above still runs).
func TestDistributeKRLLoadsInOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available; OpenSSH KRL load checked on the CI backstop")
	}

	ca, _ := newCA(t, nil)
	prof := Profile{Name: "user", MaxTTL: time.Hour, AllowUserCerts: true}
	iss, err := ca.IssueUserCert(context.Background(), prof, IssueRequest{
		SubjectPublicKey: subjectKey(t), KeyID: "revoke-me@corp", Principals: []string{"alice"}, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueUserCert: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(certPath, iss.Certificate, 0o644); err != nil {
		t.Fatal(err)
	}

	// Build a KRL that revokes this cert's serial and write the binary artifact.
	krl := NewKRL()
	krl.RevokeSerial(iss.Serial)
	krlPath := filepath.Join(dir, "revoked.krl")
	if err := os.WriteFile(krlPath, krl.DistributeKRL(1), 0o644); err != nil {
		t.Fatal(err)
	}

	// ssh-keygen -Q -f <krl> <cert>: exit status is non-zero when the cert is revoked.
	out, err := exec.Command("ssh-keygen", "-Q", "-f", krlPath, certPath).CombinedOutput()
	if err == nil {
		t.Fatalf("ssh-keygen did not report the revoked certificate as revoked using trstctl's KRL:\n%s", out)
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("revoked")) {
		t.Errorf("ssh-keygen output does not mention revocation:\n%s", out)
	}

	// Sanity: a DIFFERENT, non-revoked cert is NOT reported revoked against the same KRL.
	iss2, err := ca.IssueUserCert(context.Background(), prof, IssueRequest{
		SubjectPublicKey: subjectKey(t), KeyID: "keep-me@corp", Principals: []string{"bob"}, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert2Path := filepath.Join(dir, "id2-cert.pub")
	if err := os.WriteFile(cert2Path, iss2.Certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ssh-keygen", "-Q", "-f", krlPath, cert2Path).CombinedOutput(); err != nil {
		t.Errorf("ssh-keygen wrongly reported a non-revoked cert as revoked:\n%s\n%v", out, err)
	}
}

func containsU64(xs []uint64, v uint64) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
