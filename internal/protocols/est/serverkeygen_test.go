package est_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/est"
)

type recordingServerKeygen struct {
	result     est.ServerKeygenResult
	calls      int
	gotCSR     []byte
	gotProfile string
	gotProto   string
	gotIdem    string
	gotIdems   []string
}

func (r *recordingServerKeygen) ServerKeygen(_ context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (est.ServerKeygenResult, error) {
	r.calls++
	r.gotCSR = append(r.gotCSR[:0], csrDER...)
	r.gotProfile = profileName
	r.gotProto = protocol
	r.gotIdem = idempotencyKey
	r.gotIdems = append(r.gotIdems, idempotencyKey)
	return r.result, nil
}

func TestServerKeygenDisabledByDefault(t *testing.T) {
	ca := newCA(t)
	keygen := &recordingServerKeygen{}
	s := est.New(est.Config{
		Enroller:     realEnroller{ca: ca},
		ServerKeygen: keygen,
		Auth:         allowAuth{},
		CAChainDER:   [][]byte{ca.certDER},
		ProfileName:  "iot",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", b64Body(deviceCSR(t)))
	req.Header.Set("Content-Type", "application/pkcs10")
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled serverkeygen status %d, want 404", rec.Code)
	}
	if keygen.calls != 0 {
		t.Fatalf("disabled serverkeygen called signer-facing service %d times, want 0", keygen.calls)
	}
}

func TestServerKeygenEnabledReturnsCertAndEnvelopedKeyWithoutSecretAudit(t *testing.T) {
	ca, leafDER, rawKey, envelopedKeyDER := serverKeygenFixture(t)
	log := openESTEventLog(t)
	keygen := &recordingServerKeygen{
		result: est.ServerKeygenResult{
			CertificateDER:  leafDER,
			EnvelopedKeyDER: envelopedKeyDER,
		},
	}
	s := est.New(est.Config{
		Enroller:            realEnroller{ca: ca},
		ServerKeygen:        keygen,
		ServerKeygenEnabled: true,
		Auth:                allowAuth{},
		CAChainDER:          [][]byte{ca.certDER},
		ProfileName:         "iot",
		Log:                 log,
	})

	csrDER := deviceCSR(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", b64Body(csrDER))
	req = req.WithContext(est.WithTenant(req.Context(), "tenant-est"))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Idempotency-Key", "idem-serverkeygen-1")
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("serverkeygen status %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if keygen.calls != 1 {
		t.Fatalf("serverkeygen calls = %d, want 1", keygen.calls)
	}
	if !bytes.Equal(keygen.gotCSR, csrDER) || keygen.gotProfile != "iot" || keygen.gotProto != "est-serverkeygen" || keygen.gotIdem != "idem-serverkeygen-1" {
		t.Fatalf("serverkeygen signer request = csr:%t profile:%q proto:%q idem:%q", bytes.Equal(keygen.gotCSR, csrDER), keygen.gotProfile, keygen.gotProto, keygen.gotIdem)
	}

	parts := readServerKeygenMultipart(t, rec)
	if len(parts) != 2 {
		t.Fatalf("serverkeygen multipart parts = %d, want 2", len(parts))
	}
	assertPKCS7Part(t, parts[0].contentType, "certs-only")
	certs, err := crypto.CertsFromPKCS7(parts[0].der)
	if err != nil {
		t.Fatalf("serverkeygen cert part is not certs-only PKCS#7: %v", err)
	}
	if len(certs) != 1 || !bytes.Equal(certs[0], leafDER) {
		t.Fatalf("serverkeygen cert part did not carry issued leaf")
	}
	assertPKCS7Part(t, parts[1].contentType, "enveloped-data")
	if err := crypto.IsEnvelopedData(parts[1].der); err != nil {
		t.Fatalf("serverkeygen key part is not CMS EnvelopedData: %v", err)
	}
	assertNoSecretLeak(t, rec.Body.Bytes(), rawKey, "serverkeygen response body")

	var auditBytes []byte
	if err := log.Replay(context.Background(), 1, func(e events.Event) error {
		auditBytes = append(auditBytes, []byte(e.Type)...)
		auditBytes = append(auditBytes, e.Data...)
		return nil
	}); err != nil {
		t.Fatalf("replay EST audit log: %v", err)
	}
	if !bytes.Contains(auditBytes, []byte("protocol.est.est-serverkeygen")) {
		t.Fatalf("serverkeygen audit event missing: %s", auditBytes)
	}
	assertNoSecretLeak(t, auditBytes, rawKey, "serverkeygen audit log")
}

func TestServerKeygenFallbackIdempotencyKeyUsesFullCSRDigest(t *testing.T) {
	ca, leafDER, _, envelopedKeyDER := serverKeygenFixture(t)
	keygen := &recordingServerKeygen{
		result: est.ServerKeygenResult{
			CertificateDER:  leafDER,
			EnvelopedKeyDER: envelopedKeyDER,
		},
	}
	s := est.New(est.Config{
		Enroller:            realEnroller{ca: ca},
		ServerKeygen:        keygen,
		ServerKeygenEnabled: true,
		Auth:                allowAuth{},
		CAChainDER:          [][]byte{ca.certDER},
		ProfileName:         "iot",
	})

	csr1, csr2 := deviceCSR(t), deviceCSR(t)
	if bytes.Equal(csr1, csr2) {
		t.Fatal("test generated identical CSRs; need same subject with different keys")
	}
	for _, csr := range [][]byte{csr1, csr2} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", b64Body(csr))
		req.Header.Set("Content-Type", "application/pkcs10")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("serverkeygen status %d (%s), want 200", rec.Code, rec.Body.String())
		}
	}

	want := []string{
		"est-serverkeygen:" + crypto.SHA256Hex(csr1),
		"est-serverkeygen:" + crypto.SHA256Hex(csr2),
	}
	if len(keygen.gotIdems) != len(want) {
		t.Fatalf("serverkeygen idempotency keys = %v, want %v", keygen.gotIdems, want)
	}
	for i := range want {
		if keygen.gotIdems[i] != want[i] {
			t.Fatalf("serverkeygen idempotency keys = %v, want %v", keygen.gotIdems, want)
		}
	}
}

func serverKeygenFixture(t *testing.T) (caFixture, []byte, []byte, []byte) {
	t.Helper()
	ca := newCA(t)
	leafDER, err := crypto.SignLeafFromCSR(ca.certDER, ca.signer, deviceCSR(t), time.Hour)
	if err != nil {
		t.Fatalf("sign serverkeygen leaf: %v", err)
	}
	recipientSigner, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatalf("generate serverkeygen recipient: %v", err)
	}
	t.Cleanup(recipientSigner.Destroy)
	recipientDER, err := crypto.SelfSignedCACert(recipientSigner, "EST serverkeygen recipient", time.Hour)
	if err != nil {
		t.Fatalf("serverkeygen recipient cert: %v", err)
	}
	rawKey := []byte{
		't', 'r', 's', 't', 'c', 't', 'l', '-', 's', 'e', 'r', 'v', 'e', 'r', '-',
		'k', 'e', 'y', '-', 's', 'e', 'n', 't', 'i', 'n', 'e', 'l',
	}
	envelopedKeyDER, err := crypto.EnvelopedData(rawKey, recipientDER)
	if err != nil {
		t.Fatalf("envelope server-generated key: %v", err)
	}
	return ca, leafDER, rawKey, envelopedKeyDER
}

func openESTEventLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open embedded EST event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

type serverKeygenPart struct {
	contentType string
	der         []byte
}

func readServerKeygenMultipart(t *testing.T, rec *httptest.ResponseRecorder) []serverKeygenPart {
	t.Helper()
	mt, params, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse serverkeygen content type: %v", err)
	}
	if mt != "multipart/mixed" {
		t.Fatalf("serverkeygen content type = %q, want multipart/mixed", mt)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("serverkeygen multipart response missing boundary")
	}
	mr := multipart.NewReader(bytes.NewReader(rec.Body.Bytes()), boundary)
	var parts []serverKeygenPart
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read serverkeygen part: %v", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read serverkeygen part body: %v", err)
		}
		der, err := base64.StdEncoding.DecodeString(string(stripASCIIWhitespace(body)))
		if err != nil {
			t.Fatalf("serverkeygen part not base64: %v", err)
		}
		parts = append(parts, serverKeygenPart{contentType: part.Header.Get("Content-Type"), der: der})
	}
	return parts
}

func assertPKCS7Part(t *testing.T, contentType, smimeType string) {
	t.Helper()
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse part content type %q: %v", contentType, err)
	}
	if mt != "application/pkcs7-mime" || params["smime-type"] != smimeType {
		t.Fatalf("part content type = %q params=%v, want application/pkcs7-mime smime-type=%s", mt, params, smimeType)
	}
}

func assertNoSecretLeak(t *testing.T, haystack, secret []byte, label string) {
	t.Helper()
	if bytes.Contains(haystack, secret) {
		t.Fatalf("%s contains raw generated key material", label)
	}
	if bytes.Contains(haystack, []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatalf("%s contains base64 generated key material", label)
	}
}

func stripASCIIWhitespace(b []byte) []byte {
	out := b[:0]
	for _, c := range b {
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return out
}
