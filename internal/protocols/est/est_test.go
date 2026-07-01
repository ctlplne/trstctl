package est_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/est"
)

// --- test doubles -----------------------------------------------------------

type caFixture struct {
	certDER []byte
	signer  crypto.DigestSigner
}

func newCA(t *testing.T) caFixture {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, "EST Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return caFixture{certDER: der, signer: signer}
}

// realEnroller signs the CSR with the fixture CA — a faithful issuance double.
type realEnroller struct {
	ca   caFixture
	hook func() // optional: called inside Enroll (for the bulkhead test)
}

func (e realEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	if e.hook != nil {
		e.hook()
	}
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

type allowAuth struct{}

func (allowAuth) Authenticate(*http.Request) bool { return true }

type recordingIdempotencyEnroller struct {
	ca              caFixture
	idempotencyKeys []string
}

func (e *recordingIdempotencyEnroller) Enroll(_ context.Context, csrDER []byte, _, _, idempotencyKey string) ([]byte, error) {
	e.idempotencyKeys = append(e.idempotencyKeys, idempotencyKey)
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

func deviceCSR(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-1", DNSNames: []string{"device-1.iot.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func newServer(t *testing.T, pool *bulkhead.Pool, hook func()) (*est.Server, caFixture) {
	t.Helper()
	ca := newCA(t)
	s := est.New(est.Config{
		Enroller: realEnroller{ca: ca, hook: hook}, Auth: allowAuth{},
		CAChainDER: [][]byte{ca.certDER}, ProfileName: "iot", Pool: pool,
	})
	return s, ca
}

func b64Body(der []byte) io.Reader { return strings.NewReader(base64.StdEncoding.EncodeToString(der)) }

// --- tests ------------------------------------------------------------------

func TestCACertsReturnsChain(t *testing.T) {
	s, ca := newServer(t, nil, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("cacerts status %d", rec.Code)
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("cacerts response missing Content-Length; stock EST clients reject chunked framing")
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Fatalf("cacerts Content-Length %s, want %s", got, want)
	}
	body := rec.Body.Bytes()
	if !bytes.HasSuffix(body, []byte("\n")) {
		t.Fatal("cacerts base64 is not MIME line terminated; stock OpenSSL BIO decoders reject unwrapped bodies")
	}
	for _, line := range bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n")) {
		if len(line) > 64 {
			t.Fatalf("cacerts base64 line has %d bytes, want at most 64", len(line))
		}
	}
	der, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("cacerts body not base64: %v", err)
	}
	certs, err := crypto.CertsFromPKCS7(der)
	if err != nil {
		t.Fatalf("parse cacerts PKCS#7: %v", err)
	}
	if len(certs) != 1 || string(certs[0]) != string(ca.certDER) {
		t.Error("cacerts did not return the CA chain")
	}
}

func TestEnrollAndReenroll(t *testing.T) {
	s, _ := newServer(t, nil, nil)
	for _, path := range []string{"/.well-known/est/simpleenroll", "/.well-known/est/simplereenroll"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, b64Body(deviceCSR(t)))
		req.Header.Set("Content-Type", "application/pkcs10")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d (%s)", path, rec.Code, rec.Body.String())
		}
		der, err := base64.StdEncoding.DecodeString(rec.Body.String())
		if err != nil {
			t.Fatalf("%s body not base64: %v", path, err)
		}
		certs, err := crypto.CertsFromPKCS7(der)
		if err != nil || len(certs) != 1 {
			t.Fatalf("%s did not return a PKCS#7 leaf: %v", path, err)
		}
	}
}

func TestEnrollFallbackIdempotencyKeyUsesFullCSRDigest(t *testing.T) {
	ca := newCA(t)
	recorder := &recordingIdempotencyEnroller{ca: ca}
	s := est.New(est.Config{
		Enroller: recorder, Auth: allowAuth{},
		CAChainDER: [][]byte{ca.certDER}, ProfileName: "iot",
	})

	csr1, csr2 := deviceCSR(t), deviceCSR(t)
	if bytes.Equal(csr1, csr2) {
		t.Fatal("test generated identical CSRs; need same subject with different keys")
	}
	for _, csr := range [][]byte{csr1, csr2} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", b64Body(csr))
		req.Header.Set("Content-Type", "application/pkcs10")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("EST enrollment status %d (%s), want 200", rec.Code, rec.Body.String())
		}
	}

	want := []string{
		"est-enroll:" + crypto.SHA256Hex(csr1),
		"est-enroll:" + crypto.SHA256Hex(csr2),
	}
	if len(recorder.idempotencyKeys) != len(want) {
		t.Fatalf("enroller idempotency keys = %v, want %v", recorder.idempotencyKeys, want)
	}
	for i := range want {
		if recorder.idempotencyKeys[i] != want[i] {
			t.Fatalf("enroller idempotency keys = %v, want %v", recorder.idempotencyKeys, want)
		}
	}
}

func TestEnrollRequiresAuth(t *testing.T) {
	ca := newCA(t)
	s := est.New(est.Config{Enroller: realEnroller{ca: ca}, Auth: denyAuth{}, CAChainDER: [][]byte{ca.certDER}})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", b64Body(deviceCSR(t))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated enroll status %d, want 401", rec.Code)
	}
}

type denyAuth struct{}

func (denyAuth) Authenticate(*http.Request) bool { return false }

func TestMalformedEnrollFailsClosed(t *testing.T) {
	s, _ := newServer(t, nil, nil)
	for _, body := range []string{"not-base64-!!!", base64.StdEncoding.EncodeToString([]byte("not a CSR"))} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("malformed body %q -> status %d, want 400", body, rec.Code)
		}
	}
}

func TestEnrollRejectsOverLimitSuffix(t *testing.T) {
	s, _ := newServer(t, nil, nil)
	encoded := base64.StdEncoding.EncodeToString(deviceCSR(t))
	if len(encoded) >= 1<<16 {
		t.Fatalf("test CSR body unexpectedly large: %d", len(encoded))
	}
	body := encoded + strings.Repeat("\n", (1<<16)-len(encoded)) + "A"

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(body)))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit EST enroll status %d, want 413 (body %q)", rec.Code, rec.Body.String())
	}
}

func TestCSRAttrsNoContent(t *testing.T) {
	s, _ := newServer(t, nil, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("csrattrs status %d, want 204", rec.Code)
	}
}

// TestEnrollBurstIsBulkheaded: with a saturated pool, an enrollment sheds fast
// (503) instead of starving the worker — AN-7.
func TestEnrollBurstIsBulkheaded(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "est", Workers: 1, Queue: 1})
	defer pool.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	var once bool
	s, _ := newServer(t, pool, func() {
		if !once {
			once = true
			close(started)
			<-release // hold the single worker
		}
	})

	body := base64.StdEncoding.EncodeToString(deviceCSR(t))
	serve := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(body))
		s.ServeHTTP(rec, req)
		return rec.Code
	}

	firstDone := make(chan int, 1)
	go func() {
		firstDone <- serve()
	}()
	select {
	case <-started: // the worker is now busy
	case <-time.After(5 * time.Second):
		t.Fatal("first EST enrollment never occupied the bulkhead worker")
	}

	secondDone := make(chan int, 1)
	go func() {
		secondDone <- serve()
	}()
	deadline := time.After(5 * time.Second)
	for pool.Stats().Queued < 1 {
		select {
		case code := <-secondDone:
			t.Fatalf("second EST enrollment completed before the queue filled: status %d", code)
		case <-deadline:
			t.Fatal("second EST enrollment never filled the bulkhead queue")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("enroll under saturation -> status %d, want 503", rec.Code)
	}
	close(release)
	for name, ch := range map[string]<-chan int{"first": firstDone, "second": secondDone} {
		select {
		case code := <-ch:
			if code != http.StatusOK {
				t.Fatalf("%s EST enrollment status %d, want 200", name, code)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s EST enrollment did not drain after releasing the bulkhead", name)
		}
	}
}
