package embedded_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/est"
)

type allowAll struct{}

func (allowAll) Authenticate(*http.Request) bool { return true }

type signingEnroller struct {
	caCertDER []byte
	caSigner  *crypto.LockedSigner
}

func (e signingEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	return crypto.SignLeafFromCSR(e.caCertDER, e.caSigner, csrDER, time.Hour)
}

// TestEmbeddedESTClientEnrolls compiles the C EST client with cc and runs it end-to-end
// against the real EST server, proving a constrained-device enrollment works.
func TestEmbeddedESTClientEnrolls(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available; the embedded EST client is built on the CI backstop")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl CLI not available; required by the embedded client")
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "est_client")
	build := exec.Command("cc", "-O2", "-o", bin, filepath.Join("csrc", "est_client.c"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cc build failed: %v\n%s", err, out)
	}

	caSigner, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer caSigner.Destroy()
	caCertDER, err := crypto.SelfSignedCACert(caSigner, "EST C-client Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := est.New(est.Config{
		Enroller:    signingEnroller{caCertDER: caCertDER, caSigner: caSigner},
		Auth:        allowAll{},
		CAChainDER:  [][]byte{caCertDER},
		ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enrollDir := filepath.Join(tmp, "enroll")
	if err := os.MkdirAll(enrollDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, ts.URL, enrollDir)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("embedded EST client failed: %v\n%s", err, out)
	}

	cert, err := os.ReadFile(filepath.Join(enrollDir, "cert.pem"))
	if err != nil || !bytes.Contains(cert, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("client did not produce a certificate (err=%v)", err)
	}
}

// TestEmbeddedESTClientRejectsOversizedResponse is the CODE-003 regression: a
// response whose body exceeds the client's fixed ~64 KiB read buffer must be treated
// as an error — the client must exit NON-ZERO and write NO cert.pem — rather than
// base64-decoding a TRUNCATED PKCS#7 into a corrupt certificate. We drive the client
// against a raw TCP server that returns a well-formed HTTP/1.0 200 with a body far
// larger than the cap; pre-fix, the client silently truncated and tried to decode it.
func TestEmbeddedESTClientRejectsOversizedResponse(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available; the embedded EST client is built on the CI backstop")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl CLI not available; required by the embedded client to build the CSR")
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "est_client")
	build := exec.Command("cc", "-O2", "-o", bin, filepath.Join("csrc", "est_client.c"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cc build failed: %v\n%s", err, out)
	}

	// A raw listener that, regardless of the request, returns a 200 whose body is
	// ~256 KiB of base64 — well over the client's 64 KiB read cap. Using a raw
	// listener (not the real EST server) lets us deterministically force the
	// over-cap condition without depending on issuing a giant real chain.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	oversized := bytes.Repeat([]byte("QUFBQQ=="), 32*1024) // 8 bytes * 32Ki = 256 KiB
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain the request (best-effort) so the client's write completes.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		hdr := "HTTP/1.0 200 OK\r\nContent-Type: application/pkcs7-mime\r\n" +
			"Content-Transfer-Encoding: base64\r\nConnection: close\r\n\r\n"
		_, _ = conn.Write([]byte(hdr))
		_, _ = conn.Write(oversized)
	}()

	enrollDir := filepath.Join(tmp, "enroll")
	if err := os.MkdirAll(enrollDir, 0o755); err != nil {
		t.Fatal(err)
	}
	url := "http://" + ln.Addr().String()
	run := exec.Command(bin, url, enrollDir)
	out, err := run.CombinedOutput()
	<-done

	// The client must FAIL (non-zero exit) on the over-cap response.
	if err == nil {
		t.Fatalf("client exited 0 on an oversized response; it must reject truncation (CODE-003)\noutput: %s", out)
	}
	if !bytes.Contains(out, []byte("response too large")) {
		t.Errorf("client did not report 'response too large' on truncation (CODE-003); got: %s", out)
	}
	// And it must NOT have written a (corrupt) cert.pem.
	if _, statErr := os.Stat(filepath.Join(enrollDir, "cert.pem")); statErr == nil {
		t.Error("client wrote cert.pem from a truncated chain; it must produce no certificate on truncation (CODE-003)")
	}
}

// TestEmbeddedESTClientRejectsShellInjectionWorkdir is the FUZZ-005 acceptance: the
// client builds openssl commands by interpolating the operator-supplied workdir into
// a system() command line, so a workdir containing shell metacharacters must be
// rejected up front, not interpolated. The test passes a workdir crafted to write a
// sentinel file via command injection and asserts (a) the client exits non-zero with
// a "refusing unsafe workdir" message and (b) the injected command did NOT run (the
// sentinel was never created). Pre-fix the client interpolated the workdir verbatim
// and the injected command would execute.
func TestEmbeddedESTClientRejectsShellInjectionWorkdir(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available; the embedded EST client is built on the CI backstop")
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "est_client")
	build := exec.Command("cc", "-O2", "-o", bin, filepath.Join("csrc", "est_client.c"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cc build failed: %v\n%s", err, out)
	}

	sentinel := filepath.Join(tmp, "pwned")
	// A workdir that, if interpolated into `openssl req ... -keyout <wd>/key.pem ...`,
	// would close the openssl command and run `touch <sentinel>`.
	maliciousWD := tmp + "; touch " + sentinel + "; echo "
	run := exec.Command(bin, "http://127.0.0.1:9/", maliciousWD)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("client accepted a shell-metacharacter workdir (should have rejected it); output:\n%s", out)
	}
	if !bytes.Contains(out, []byte("unsafe workdir")) {
		t.Errorf("expected an 'unsafe workdir' rejection message, got:\n%s", out)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("command injection executed: sentinel file %s was created", sentinel)
	}

	// A clean workdir is still accepted past the validation gate (it then fails later
	// for network reasons against the unreachable URL, which is fine — we only assert
	// it was NOT rejected as unsafe).
	cleanWD := filepath.Join(tmp, "enroll")
	if err := os.MkdirAll(cleanWD, 0o755); err != nil {
		t.Fatal(err)
	}
	out2, _ := exec.Command(bin, "http://127.0.0.1:9/", cleanWD).CombinedOutput()
	if bytes.Contains(out2, []byte("unsafe workdir")) {
		t.Errorf("a clean workdir was wrongly rejected as unsafe:\n%s", out2)
	}
}
