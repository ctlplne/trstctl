// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFS lays out an exported-image filesystem under a temp root.
func writeFS(t *testing.T, files map[string][]byte, links map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func subjects(rep SystemRootsReport) []string {
	out := make([]string, 0, len(rep.Roots))
	for _, r := range rep.Roots {
		out = append(out, r.Subject)
	}
	return out
}

// The audit fails a root Mozilla does not trust for websites and anything on
// the distrust list (by key, so a cross-sign is caught), warns about a Mozilla
// root the image lacks, and refuses an image that redirects the store unless
// SSL_CERT_FILE names the shipped bundle.
func TestAuditComparesWithMozillaAndTheDistrustList(t *testing.T) {
	moz1 := newTestCA(t, "Mozilla Root 1", "m1.example.test")
	moz2 := newTestCA(t, "Mozilla Root 2", "m2.example.test")
	extra := newTestCA(t, "Vendor Root", "v.example.test")
	bad := newTestCA(t, "Distrusted Root", "bad.example.test")
	mozilla := append(append([]byte{}, moz1.rootPEM...), moz2.rootPEM...)
	list := listWith(t, Entry{Name: "Distrusted Root", Kind: KindRoot, SPKISHA256: SPKISHA256(bad.rootCert), CertSHA256: CertSHA256(bad.rootCert), Reason: "test", Sources: []string{"test"}, Since: "2026-10-23"})

	root := writeFS(t, map[string][]byte{"etc/ssl/certs/ca-certificates.crt": joinPEM(moz1.rootPEM, extra.rootPEM, bad.rootPEM)}, nil)
	rep, err := SystemRootsLike(root, map[string]string{"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Audit(rep, mozilla, list)
	if err != nil {
		t.Fatal(err)
	}
	var fails, warns []string
	for _, f := range findings {
		switch f.Level {
		case "fail":
			fails = append(fails, f.Subject+": "+f.Reason)
		case "warn":
			warns = append(warns, f.Subject+": "+f.Reason)
		}
	}
	// Findings are sorted by level, then subject.
	if len(fails) != 2 || !strings.Contains(fails[0], "CN=Distrusted Root") || !strings.Contains(fails[0], "distrusted: Distrusted Root") ||
		!strings.Contains(fails[1], "CN=Vendor Root") || !strings.Contains(fails[1], "not in Mozilla") {
		t.Fatalf("fails = %v", fails)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "CN=Mozilla Root 2") {
		t.Fatalf("warns = %v, want the missing Mozilla root", warns)
	}

	// Exactly Mozilla's list, the shipped SSL_CERT_FILE: clean.
	root = writeFS(t, map[string][]byte{"etc/ssl/certs/ca-certificates.crt": mozilla}, nil)
	rep, _ = SystemRootsLike(root, map[string]string{"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
	if findings, err = Audit(rep, mozilla, list); err != nil || len(findings) != 0 {
		t.Fatalf("clean image: findings %v err %v", findings, err)
	}
	// A redirected store fails even when its contents are right.
	root = writeFS(t, map[string][]byte{"opt/certs/bundle.pem": mozilla}, nil)
	rep, _ = SystemRootsLike(root, map[string]string{"SSL_CERT_FILE": "/opt/certs/bundle.pem", "SSL_CERT_DIR": "/opt/certs"})
	findings, _ = Audit(rep, mozilla, list)
	if len(findings) != 2 || findings[0].Level != "fail" || findings[1].Level != "fail" {
		t.Fatalf("redirected store: %v", findings)
	}
	if _, err := Audit(rep, []byte("no certificates"), list); err == nil {
		t.Fatal("an empty Mozilla list audited without error")
	}
}

func joinPEM(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
