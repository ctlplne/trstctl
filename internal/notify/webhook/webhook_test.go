package webhook_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
)

const testSecret = "hmac-key-do-not-log"

func newChannel(t *testing.T, srv *fakeReceiver, secret string) *webhook.Channel {
	t.Helper()
	return webhook.New(srv.URL(), []byte(secret), webhook.WithHTTPClient(srv.Client()))
}

// TestWebhookConforms drives the channel through the shared notification conformance
// harness, against the signature-verifying double. The harness sends one well-formed
// alert and requires a name and an error-free delivery; the double accepts only a
// correctly signed request, so passing proves the channel both names itself and signs
// what it sends.
func TestWebhookConforms(t *testing.T) {
	srv := newFakeReceiver(testSecret)
	defer srv.Close()
	c := newChannel(t, srv, testSecret)

	if err := notify.Conform(context.Background(), c); err != nil {
		t.Fatalf("webhook channel failed notification conformance: %v", err)
	}
	if srv.Accepted() == 0 {
		t.Fatal("conformance ran but the double accepted no signed deliveries")
	}
	if got := srv.LastAlert(); got.TenantID == "" {
		t.Fatalf("double captured no alert from the conformance probe: %+v", got)
	}
}

// TestWebhookSSRFFailsClosed is the SEC-008 acceptance: a webhook configured to an
// internal/metadata address fails closed. The channel is built WITHOUT a client
// override, so it uses the default SSRF-safe client (netsec.SafeClient); a delivery
// to the cloud-metadata service (and to a loopback/RFC-1918 address) is refused
// before any request is made, so an operator/tenant-supplied URL cannot coerce the
// control plane into an internal request.
func TestWebhookSSRFFailsClosed(t *testing.T) {
	ctx := context.Background()
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=x"}
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/", // cloud metadata service
		"http://127.0.0.1:9999/hook",               // loopback
		"http://10.0.0.5/hook",                     // RFC-1918 private
	} {
		// No WithHTTPClient override -> the real default SSRF-safe client is used.
		c := webhook.New(target, []byte(testSecret))
		if err := c.Notify(ctx, alert); err == nil {
			t.Errorf("webhook delivery to %s was not blocked; the SSRF guard must fail closed (SEC-008)", target)
		}
	}
}

// TestSignatureVerified is the heart of S10.7: a channel holding the receiver's key is
// accepted (its HMAC over the body matches the header), and a channel holding the wrong
// key is rejected with 401 (its signature does not match), so the body really is
// authenticated end-to-end and a mismatch fails closed.
func TestSignatureVerified(t *testing.T) {
	srv := newFakeReceiver(testSecret)
	defer srv.Close()
	ctx := context.Background()
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=signed.example"}

	good := newChannel(t, srv, testSecret)
	if err := good.Notify(ctx, alert); err != nil {
		t.Fatalf("correctly signed alert was rejected: %v", err)
	}
	if got := srv.LastAlert(); got.Subject != alert.Subject {
		t.Fatalf("accepted alert mismatch: got %q, want %q", got.Subject, alert.Subject)
	}

	bad := newChannel(t, srv, "wrong-secret")
	err := bad.Notify(ctx, alert)
	if err == nil {
		t.Fatal("a wrong-secret signature was accepted; HMAC auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 signature rejection, got: %v", err)
	}
}

// TestSecretNeverLogged (AN-8): neither the failure-path error nor anything the channel
// puts on the wire may contain the HMAC key. The error from a rejected delivery and the
// captured request (headers + body) are both scanned for the secret.
func TestSecretNeverLogged(t *testing.T) {
	const secret = "ultra-secret-hmac-key"
	srv := newFakeReceiver("a-different-key") // force a 401 so we exercise the error path
	defer srv.Close()
	c := newChannel(t, srv, secret)

	err := c.Notify(context.Background(), notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1"})
	if err == nil {
		t.Fatal("expected a rejection from the mismatched key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the HMAC key: %v", err)
	}
	if hdr, body := srv.LastRequest(); strings.Contains(hdr, secret) || strings.Contains(body, secret) {
		t.Fatalf("the request put the HMAC key on the wire (only the derived signature should appear): headers=%q body=%q", hdr, body)
	}
}

// --- fakeReceiver: an in-process double of an HMAC-signed-webhook endpoint ------------
//
// It recomputes HMAC-SHA256 over the exact body it received, under its own copy of the
// shared key, and compares hex(mac) to the X-Trstctl-Signature: sha256=<hex> header.
// A missing or mismatched signature is rejected with 401 (so a sign-the-wrong-bytes or
// missing-header bug in the channel is caught here), exactly as a real receiver would
// fail closed. On a verified request it decodes and captures the Alert. It recomputes
// the MAC through internal/crypto.HMACSHA256 — the same AN-3 boundary the channel uses —
// so the double imports no crypto/* either (AN-3); the agreement of the two sides
// through that one function is what the signature test asserts.

type fakeReceiver struct {
	srv    *httptest.Server
	secret []byte

	mu       sync.Mutex
	accepted int
	last     notify.Alert
	lastHdr  string
	lastBody string
}

func newFakeReceiver(secret string) *fakeReceiver {
	s := &fakeReceiver{secret: []byte(secret)}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeReceiver) URL() string          { return s.srv.URL }
func (s *fakeReceiver) Client() *http.Client { return s.srv.Client() }
func (s *fakeReceiver) Close()               { s.srv.Close() }

// Accepted is the number of correctly signed deliveries the double accepted.
func (s *fakeReceiver) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// LastAlert returns the most recently accepted alert.
func (s *fakeReceiver) LastAlert() notify.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// LastRequest returns the signature header and raw body of the most recent request
// (accepted or not), so a test can assert the key never appeared on the wire.
func (s *fakeReceiver) LastRequest() (header, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHdr, s.lastBody
}

func (s *fakeReceiver) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	got := r.Header.Get("X-Trstctl-Signature")

	s.mu.Lock()
	s.lastHdr = got
	s.lastBody = string(body)
	s.mu.Unlock()

	// Recompute the MAC over the received bytes through the same crypto boundary the
	// channel uses (AN-3) and compare to the presented signature; fail closed on any
	// mismatch, exactly as a real signed-webhook receiver would.
	want := "sha256=" + hex.EncodeToString(crypto.HMACSHA256(s.secret, body))
	if got != want {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		http.Error(w, `{"error":"malformed alert"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.accepted++
	s.last = alert
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}
