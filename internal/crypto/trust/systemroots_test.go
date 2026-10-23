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

// Part 3: the audit reads an image the way Go's crypto/x509 does on Linux —
// the first readable file of its list (or SSL_CERT_FILE), then the cert
// directories, skipping a symlink to a file in the same directory.
func TestSystemRootsLikeFollowsGoLinuxRule(t *testing.T) {
	a := newTestCA(t, "Root A", "a.example.test")
	b := newTestCA(t, "Root B", "b.example.test")
	c := newTestCA(t, "Root C", "c.example.test")

	// Only the second file of Go's list exists; the bundle holds A. The directory
	// holds B as a regular file, a same-directory symlink to it (skipped: an alias
	// of what Go reads anyway) and a symlink to C outside the directory
	// (followed), plus a non-certificate file and a subdirectory (ignored).
	root := writeFS(t, map[string][]byte{
		"etc/pki/tls/certs/ca-bundle.crt": a.rootPEM,
		"etc/ssl/certs/b.pem":             b.rootPEM,
		"etc/ssl/certs/README":            []byte("not a certificate\n"),
		"etc/ssl/certs/sub/ignored.pem":   c.rootPEM,
		"usr/share/ca-certificates/c.crt": c.rootPEM,
	}, map[string]string{
		"etc/ssl/certs/alias.pem": "b.pem",
		"etc/ssl/certs/c.pem":     "/usr/share/ca-certificates/c.crt",
	})
	rep, err := SystemRootsLike(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(subjects(rep), ","); got != "CN=Root A,CN=Root B,CN=Root C" {
		t.Fatalf("roots = %v, want A from the bundle, B from the directory, C through the outside symlink", subjects(rep))
	}
	if strings.Join(rep.Sources, ",") != "/etc/pki/tls/certs/ca-bundle.crt,/etc/ssl/certs/b.pem,/etc/ssl/certs/c.pem" {
		t.Fatalf("sources = %v", rep.Sources)
	}

	// SSL_CERT_FILE replaces the file list; SSL_CERT_DIR replaces the directories.
	rep, err = SystemRootsLike(root, map[string]string{"SSL_CERT_FILE": "/usr/share/ca-certificates/c.crt", "SSL_CERT_DIR": "/nowhere"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(subjects(rep), ","); got != "CN=Root C" || rep.EnvFile == "" || rep.EnvDir == "" {
		t.Fatalf("with SSL_CERT_* = %v (file %q dir %q)", subjects(rep), rep.EnvFile, rep.EnvDir)
	}
	// Go's first file wins and the directory walk still runs, so a root present
	// in both is reported once.
	root = writeFS(t, map[string][]byte{"etc/ssl/certs/ca-certificates.crt": a.rootPEM, "etc/ssl/certs/a-again.pem": a.rootPEM}, nil)
	if rep, err = SystemRootsLike(root, nil); err != nil || len(rep.Roots) != 1 {
		t.Fatalf("duplicate root reported twice: %v %v", subjects(rep), err)
	}
	if _, err := SystemRootsLike(t.TempDir(), nil); err == nil {
		t.Fatal("an image with no trust store audited without error")
	}
	// Go's AppendCertsFromPEM skips what it cannot use; so does the audit, and
	// it counts them.
	junk := joinPEM(a.rootPEM,
		[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n"+strings.SplitN(string(b.rootPEM), "\n", 2)[1]),
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	rep, err = SystemRootsLike(writeFS(t, map[string][]byte{"etc/ssl/certs/ca-certificates.crt": junk}, nil), nil)
	if err != nil || strings.Join(subjects(rep), ",") != "CN=Root A" || rep.Skipped != 3 {
		t.Fatalf("junk blocks: roots %v skipped %d err %v, want A alone and 3 skipped", subjects(rep), rep.Skipped, err)
	}
}

// A symlink in the exported image resolves inside the image, the way the
// image's own kernel would resolve it: an absolute target is re-rooted, ".."
// stops at the root, a symlinked directory is followed, and a loop is
// abandoned. Nothing reads a file of the machine running the audit.
func TestSystemRootsLikeNeverLeavesTheImage(t *testing.T) {
	a := newTestCA(t, "Root A", "a.example.test")
	b := newTestCA(t, "Root B", "b.example.test")
	host := newTestCA(t, "Host Only Root", "host.example.test")
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "outside.pem"), host.rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	climb := strings.Repeat("../", 24) + strings.TrimPrefix(filepath.ToSlash(hostDir), "/") + "/outside.pem"
	root := writeFS(t, map[string][]byte{
		"opt/trust/bundle.pem": a.rootPEM,
		"opt/extra/b.pem":      b.rootPEM,
	}, map[string]string{
		// Alpine-style bundle link with an absolute target inside the image.
		"etc/ssl/cert.pem": "/opt/trust/bundle.pem",
		// A symlinked certificate directory (Fedora links one to the other).
		"etc/ssl/certs": "/opt/extra",
		// Links that would read the auditing machine's own files if followed there.
		"opt/extra/escape.pem": filepath.ToSlash(hostDir) + "/outside.pem",
		"opt/extra/climb.pem":  climb,
		// A loop.
		"opt/extra/loop-a.pem": "/opt/extra/loop-b.pem",
		"opt/extra/loop-b.pem": "/opt/extra/loop-a.pem",
	})
	rep, err := SystemRootsLike(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(subjects(rep), ","); got != "CN=Root A,CN=Root B" {
		t.Fatalf("roots = %v, want A through the bundle link and B through the linked directory, nothing from the host", subjects(rep))
	}
	if strings.Join(rep.Sources, ",") != "/etc/ssl/cert.pem,/etc/ssl/certs/b.pem" {
		t.Fatalf("sources = %v", rep.Sources)
	}
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
