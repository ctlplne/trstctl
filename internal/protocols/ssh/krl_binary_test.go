// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	if uint64(len(b)-4) < uint64(n) { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
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

// TestDistributeKRLLoadsInOpenSSH checks revocation and non-revocation with the
// stock consumer. Test key IDs as well as serials: a correctly framed KRL can
// still contain an unsupported subsection type and deny every certificate.
func TestDistributeKRLLoadsInOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_OPENSSH") != "" {
			t.Fatal("TRSTCTL_REQUIRE_OPENSSH is set but ssh-keygen is unavailable")
		}
		t.Skip("ssh-keygen not available; OpenSSH KRL load checked on the CI backstop")
	}
	for _, kind := range []string{"host", "user"} {
		t.Run(kind, func(t *testing.T) {
			ca, _ := newCA(t, nil)
			profile := Profile{Name: kind, MaxTTL: time.Hour, AllowHostCerts: true, AllowUserCerts: true}
			issue := ca.IssueUserCert
			if kind == "host" {
				issue = ca.IssueHostCert
			}
			dir := t.TempDir()
			paths := make([]string, 3)
			serials := make([]uint64, 3)
			for i, keyID := range []string{"revoke-me@corp", "revoke-me@corp", "keep-me@corp"} {
				issued, err := issue(context.Background(), profile, IssueRequest{
					SubjectPublicKey: subjectKey(t), KeyID: keyID, Principals: []string{"qa.example.test"}, TTL: 30 * time.Minute,
				})
				if err != nil {
					t.Fatal(err)
				}
				serials[i] = issued.Serial
				paths[i] = filepath.Join(dir, fmt.Sprintf("certificate-%d.pub", i))
				if err := os.WriteFile(paths[i], issued.Certificate, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, tc := range []struct {
				name          string
				serial, keyID bool
			}{
				{name: "empty"},
				{name: "serial", serial: true},
				{name: "key-id", keyID: true},
				{name: "serial-and-key-id", serial: true, keyID: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					krl := NewKRL()
					if tc.serial {
						krl.RevokeSerial(serials[0])
					}
					if tc.keyID {
						krl.RevokeKeyID("revoke-me@corp")
					}
					krlPath := filepath.Join(t.TempDir(), "list.krl")
					if err := os.WriteFile(krlPath, krl.DistributeKRL(1), 0o600); err != nil {
						t.Fatal(err)
					}
					for i, certPath := range paths {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						out, err := exec.CommandContext(ctx, "ssh-keygen", "-Q", "-f", krlPath, certPath).CombinedOutput() // #nosec G204 -- fixed reference tool and task-owned test files (CWE-78)
						cancel()
						wantRevoked := (tc.serial && i == 0) || (tc.keyID && i < 2)
						if wantRevoked {
							var exitErr *exec.ExitError
							if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.HasSuffix(bytes.TrimSpace(out), []byte(": REVOKED")) {
								t.Errorf("certificate %d: want explicit OpenSSH revocation (exit 1), got %v: %s", i, err, out)
							}
						} else if err != nil || !bytes.HasSuffix(bytes.TrimSpace(out), []byte(": ok")) {
							t.Errorf("certificate %d: want accepted non-revoked certificate, got %v: %s", i, err, out)
						}
					}
				})
			}
		})
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
