package tlsprobe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/tlsprobe"
)

// Probe returns the exact certificate the server presents, and is non-invasive:
// it completes the handshake and closes without sending an HTTP request, so the
// server's handler never runs.
func TestProbeCapturesServerCertNonInvasively(t *testing.T) {
	var handlerCalled atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	res, err := tlsprobe.Probe(context.Background(), addr)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(res.PeerCertificates) == 0 {
		t.Fatal("no peer certificate captured")
	}
	// The captured leaf is byte-for-byte the server's certificate.
	want := crypto.SHA256Hex(srv.Certificate().Raw)
	if got := crypto.SHA256Hex(res.PeerCertificates[0]); got != want {
		t.Errorf("captured cert fingerprint = %s, want %s", got, want)
	}

	// Give the server a moment; it still must not have run the handler, because
	// the probe sent no request.
	time.Sleep(50 * time.Millisecond)
	if handlerCalled.Load() {
		t.Error("probe was not non-invasive: the server handler ran")
	}
}

// A probe to an address with nothing listening fails (bounded by the timeout).
func TestProbeUnreachable(t *testing.T) {
	_, err := tlsprobe.Probe(context.Background(), "127.0.0.1:1", tlsprobe.WithTimeout(500*time.Millisecond))
	if err == nil {
		t.Error("expected an error probing a closed port")
	}
}

// A malformed address is reported, not dialed.
func TestProbeBadAddress(t *testing.T) {
	if _, err := tlsprobe.Probe(context.Background(), "no-port"); err == nil {
		t.Error("expected an error for an address without a port")
	}
}
