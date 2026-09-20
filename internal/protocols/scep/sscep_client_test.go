// SPDX-License-Identifier: BUSL-1.1

package scep_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// TestSCEPSSCEPClientEnrollment is the INTEROP-003 external-client transcript
// guard: stock `sscep` fetches the served CA certificate, sends a PKIOperation to
// the served /scep endpoint, accepts the CertRep response, and writes request /
// response transcripts that CI archives.
func TestSCEPSSCEPClientEnrollment(t *testing.T) {
	sscep, err := exec.LookPath("sscep")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_SSCEP") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_SSCEP is set but sscep is not on PATH: %v", err)
		}
		t.Skip("sscep not on PATH; set TRSTCTL_REQUIRE_SSCEP=1 in CI to make the external SCEP client mandatory")
	}

	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	recorder := newSCEPTranscriptRecorder(t.TempDir(), srv.Handler())
	ts := httptest.NewServer(recorder)
	defer ts.Close()

	_, clientKey, csrDER := newClient(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "sscep-ca.crt")
	clientKeyFile := writeSCEPPEMFile(t, dir, "sscep-client.key", "PRIVATE KEY", clientKey)
	csrFile := writeSCEPPEMFile(t, dir, "sscep-client.csr", "CERTIFICATE REQUEST", csrDER)
	issuedFile := filepath.Join(dir, "sscep-issued.crt")
	selfSignedFile := filepath.Join(dir, "sscep-selfsigned.crt")
	getCALog := filepath.Join(dir, "sscep-getca.log")
	enrollLog := filepath.Join(dir, "sscep-enroll.log")
	scepURL := ts.URL + "/scep/pkiclient.exe"

	getCA := exec.Command(sscep, "getca", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-u", scepURL,
		"-c", caFile,
		"-F", "sha256",
		"-v",
	)
	getCAOut, err := getCA.CombinedOutput()
	if werr := os.WriteFile(getCALog, getCAOut, 0o600); werr != nil {
		t.Fatalf("write sscep getca log: %v", werr)
	}
	if err != nil {
		t.Fatalf("sscep getca failed: %v\n%s", err, getCAOut)
	}
	if stat, err := os.Stat(caFile); err != nil {
		t.Fatalf("sscep getca did not write CA file: %v\n%s", err, getCAOut)
	} else if stat.Size() == 0 {
		t.Fatalf("sscep getca wrote an empty CA file\n%s", getCAOut)
	}

	enroll := exec.Command(sscep, "enroll", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-u", scepURL,
		"-c", caFile,
		"-k", clientKeyFile,
		"-r", csrFile,
		"-l", issuedFile,
		"-L", selfSignedFile,
		"-E", "aes256",
		"-S", "sha256",
		"-t", "1",
		"-n", "1",
		"-v",
	)
	enrollOut, err := enroll.CombinedOutput()
	if werr := os.WriteFile(enrollLog, enrollOut, 0o600); werr != nil {
		t.Fatalf("write sscep enroll log: %v", werr)
	}
	if err != nil {
		t.Fatalf("sscep enroll failed: %v\n%s", err, enrollOut)
	}
	issuedDER := readSCEPCertificateFile(t, issuedFile)
	if err := crypto.VerifyLeafSignedByCA(issuedDER, ca.certDER); err != nil {
		t.Fatalf("sscep issued certificate does not verify against the served CA: %v", err)
	}

	pkiReq, pkiResp := recorder.pkioOperationFiles(t)
	archiveSCEPConformanceTranscripts(t, "scep-sscep-enroll", caFile, issuedFile, selfSignedFile, getCALog, enrollLog, pkiReq, pkiResp)
}

type scepTranscriptRecorder struct {
	mu      sync.Mutex
	dir     string
	handler http.Handler
	pkiReq  string
	pkiResp string
}

func newSCEPTranscriptRecorder(dir string, handler http.Handler) *scepTranscriptRecorder {
	return &scepTranscriptRecorder{dir: dir, handler: handler}
}

func (r *scepTranscriptRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var requestDER []byte
	if req.URL.Query().Get("operation") == "PKIOperation" {
		if req.Method == http.MethodPost {
			requestDER, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(requestDER))
		} else if msg := req.URL.Query().Get("message"); msg != "" {
			requestDER, _ = base64.StdEncoding.DecodeString(msg)
		}
	}
	rw := &recordingResponseWriter{ResponseWriter: w}
	r.handler.ServeHTTP(rw, req)
	if req.URL.Query().Get("operation") != "PKIOperation" || len(requestDER) == 0 || len(rw.body.Bytes()) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	reqPath := filepath.Join(r.dir, "sscep-pkioperation-request.der")
	respPath := filepath.Join(r.dir, "sscep-pkioperation-response.der")
	if err := os.WriteFile(reqPath, requestDER, 0o600); err == nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
		r.pkiReq = reqPath
	}
	if err := os.WriteFile(respPath, rw.body.Bytes(), 0o600); err == nil {
		r.pkiResp = respPath
	}
}

func (r *scepTranscriptRecorder) pkioOperationFiles(t *testing.T) (string, string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range []string{r.pkiReq, r.pkiResp} {
		if p == "" {
			t.Fatalf("sscep enrollment did not produce a captured PKIOperation transcript")
		}
		if stat, err := os.Stat(p); err != nil {
			t.Fatalf("captured PKIOperation transcript %s is missing: %v", p, err)
		} else if stat.Size() == 0 {
			t.Fatalf("captured PKIOperation transcript %s is empty", p)
		}
	}
	return r.pkiReq, r.pkiResp
}

type recordingResponseWriter struct {
	http.ResponseWriter
	body bytes.Buffer
}

func (w *recordingResponseWriter) Write(p []byte) (int, error) {
	_, _ = w.body.Write(p)
	return w.ResponseWriter.Write(p)
}

func writeSCEPPEMFile(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func readSCEPCertificateFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if block, _ := pem.Decode(raw); block != nil && block.Type == "CERTIFICATE" {
		return block.Bytes
	}
	return raw
}

func archiveSCEPConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil { // #nosec G301 G703 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276)
		t.Fatalf("create transcript archive dir: %v", err)
	}
	for _, src := range paths {
		in, err := os.Open(src) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatalf("open transcript %s: %v", src, err)
		}
		dst := filepath.Join(dstDir, prefix+"-"+filepath.Base(src))
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 G703 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			_ = in.Close()
			t.Fatalf("create archived transcript %s: %v", dst, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = in.Close()
			_ = out.Close()
			t.Fatalf("copy transcript %s: %v", src, err)
		}
		if err := in.Close(); err != nil {
			_ = out.Close()
			t.Fatalf("close transcript %s: %v", src, err)
		}
		if err := out.Close(); err != nil {
			t.Fatalf("close archived transcript %s: %v", dst, err)
		}
	}
}

func TestArchiveSCEPConformanceTranscriptsWritesAllFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR", dir)
	src := filepath.Join(t.TempDir(), "request.der")
	if err := os.WriteFile(src, []byte("transcript"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveSCEPConformanceTranscripts(t, "unit", src)
	got, err := os.ReadFile(filepath.Join(dir, "unit-request.der")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("transcript")) {
		t.Fatalf("archived transcript = %q", got)
	}
}
