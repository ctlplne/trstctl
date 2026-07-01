package cmp_test

import (
	"bytes"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
	"trstctl.com/trstctl/internal/testutil/openssltest"
)

// TestCMPOpenSSLClientP10CREnrollment is the INTEROP-003 external-client
// transcript guard: stock `openssl cmp` creates the p10cr request, posts it to the
// served /cmp endpoint, accepts the protected response, and writes request/response
// transcripts that CI archives.
func TestCMPOpenSSLClientP10CREnrollment(t *testing.T) {
	ossl := openssltest.RequireCMP(t)

	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	dir := t.TempDir()
	caFile := writePEMFile(t, dir, "ca.pem", "CERTIFICATE", ca.certDER)
	clientCertFile := writePEMFile(t, dir, "client.pem", "CERTIFICATE", clientCert)
	clientKeyFile := writePEMFile(t, dir, "client.key", "PRIVATE KEY", clientKey)
	csrFile := writePEMFile(t, dir, "client.csr", "CERTIFICATE REQUEST", csrDER)
	reqOut := filepath.Join(dir, "openssl-cmp-p10cr-request.der")
	rspOut := filepath.Join(dir, "openssl-cmp-p10cr-response.der")
	certOut := filepath.Join(dir, "openssl-cmp-issued.pem")
	logOut := filepath.Join(dir, "openssl-cmp.log")

	cmd := exec.Command(ossl, "cmp",
		"-config", "",
		"-cmd", "p10cr",
		"-server", ts.URL,
		"-path", "/cmp",
		"-csr", csrFile,
		"-cert", clientCertFile,
		"-key", clientKeyFile,
		"-extracerts", clientCertFile,
		"-srvcert", caFile,
		"-ignore_keyusage",
		"-disable_confirm",
		"-certout", certOut,
		"-reqout", reqOut,
		"-rspout", rspOut,
		"-batch",
		"-verbosity", "7",
	)
	out, err := cmd.CombinedOutput()
	if werr := os.WriteFile(logOut, out, 0o600); werr != nil {
		t.Fatalf("write openssl cmp log: %v", werr)
	}
	if err != nil {
		t.Fatalf("openssl cmp p10cr enrollment failed: %v\n%s", err, out)
	}
	for _, p := range []string{reqOut, rspOut, certOut} {
		if stat, err := os.Stat(p); err != nil {
			t.Fatalf("openssl cmp did not write %s: %v\n%s", p, err, out)
		} else if stat.Size() == 0 {
			t.Fatalf("openssl cmp wrote empty %s\n%s", p, out)
		}
	}
	issuedPEM, err := os.ReadFile(certOut)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issuedPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("openssl cmp certout is not a certificate PEM:\n%s", issuedPEM)
	}
	if err := crypto.VerifyLeafSignedByCA(block.Bytes, ca.certDER); err != nil {
		t.Fatalf("openssl cmp issued certificate does not verify against the served CA: %v", err)
	}
	archiveConformanceTranscripts(t, "cmp-openssl-p10cr", reqOut, rspOut, certOut, logOut)
}

func TestOpenSSLCMPP10CRRequestParses(t *testing.T) {
	ossl := openssltest.RequireCMP(t)
	if !opensslCMPSupportsReqoutOnly(t, ossl) {
		t.Skip("openssl cmp does not support -reqout_only; the end-to-end OpenSSL CMP test still exercises request parsing")
	}
	_, reqDER := opensslCMPRequest(t, ossl)
	if _, err := crypto.ParseCMPRequest(reqDER); err != nil {
		t.Fatalf("crypto.ParseCMPRequest rejected stock openssl cmp p10cr request: %v", err)
	}
}

func opensslCMPRequest(t *testing.T, ossl string) (dir string, reqDER []byte) {
	t.Helper()
	dir = t.TempDir()
	clientCert, clientKey, csrDER := newClient(t)
	clientCertFile := writePEMFile(t, dir, "client.pem", "CERTIFICATE", clientCert)
	clientKeyFile := writePEMFile(t, dir, "client.key", "PRIVATE KEY", clientKey)
	csrFile := writePEMFile(t, dir, "client.csr", "CERTIFICATE REQUEST", csrDER)
	reqOut := filepath.Join(dir, "openssl-cmp-p10cr-request.der")
	logOut := filepath.Join(dir, "openssl-cmp-reqout.log")
	cmd := exec.Command(ossl, "cmp",
		"-config", "",
		"-cmd", "p10cr",
		"-csr", csrFile,
		"-cert", clientCertFile,
		"-key", clientKeyFile,
		"-extracerts", clientCertFile,
		"-recipient", "/CN=trstctl CMP Test CA",
		"-reqout_only", reqOut,
		"-batch",
		"-verbosity", "7",
	)
	out, err := cmd.CombinedOutput()
	if werr := os.WriteFile(logOut, out, 0o600); werr != nil {
		t.Fatalf("write openssl cmp reqout log: %v", werr)
	}
	if err != nil {
		t.Fatalf("openssl cmp reqout_only failed: %v\n%s", err, out)
	}
	reqDER, err = os.ReadFile(reqOut)
	if err != nil {
		t.Fatalf("read openssl cmp request: %v\n%s", err, out)
	}
	if len(reqDER) == 0 {
		t.Fatalf("openssl cmp wrote empty request\n%s", out)
	}
	archiveConformanceTranscripts(t, "cmp-openssl-p10cr", reqOut, logOut)
	return dir, reqDER
}

func opensslCMPSupportsReqoutOnly(t *testing.T, ossl string) bool {
	t.Helper()
	out, err := exec.Command(ossl, "cmp", "-help").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cmp -help failed: %v\n%s", err, out)
	}
	return bytes.Contains(out, []byte("-reqout_only"))
}

func writePEMFile(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func archiveConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("create transcript archive dir: %v", err)
	}
	for _, src := range paths {
		in, err := os.Open(src)
		if err != nil {
			t.Fatalf("open transcript %s: %v", src, err)
		}
		defer func() { _ = in.Close() }()
		dst := filepath.Join(dstDir, prefix+"-"+filepath.Base(src))
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("create archived transcript %s: %v", dst, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			t.Fatalf("copy transcript %s: %v", src, err)
		}
		if err := out.Close(); err != nil {
			t.Fatalf("close archived transcript %s: %v", dst, err)
		}
	}
}

func TestArchiveConformanceTranscriptsWritesAllFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR", dir)
	src := filepath.Join(t.TempDir(), "request.der")
	if err := os.WriteFile(src, []byte("transcript"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveConformanceTranscripts(t, "unit", src)
	got, err := os.ReadFile(filepath.Join(dir, "unit-request.der"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("transcript")) {
		t.Fatalf("archived transcript = %q", got)
	}
}
