// SPDX-License-Identifier: BUSL-1.1

// SystemRootsLike answers which roots Go would load inside a Linux image, and
// its only caller, trstctl-trustbundle, runs in Linux image builds and refuses
// on Windows (owner decision 2026-11-02, item 2g i).

//go:build !windows

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
