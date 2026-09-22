// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNativeFallbackPreservesClassicalListenersAndUpgradeRefusals(t *testing.T) {
	executable := requireNativeProbeOpenSSL(t)
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12} // #nosec G402 -- interoperability fixture pins TLS 1.2 to prove the native fallback preserves an existing supported listener.
	srv.StartTLS()
	defer srv.Close()
	got, err := ProbeWithNativeFallback(context.Background(), executable, srv.Listener.Addr().String())
	if err != nil || got.TLSVersion != tls.VersionTLS12 || len(got.PeerCertificates) != 1 || !bytes.Equal(got.PeerCertificates[0], srv.Certificate().Raw) {
		t.Fatal("native configuration broke a supported classical listener")
	}
	if result, err := ProbeWithNativeFallback(context.Background(), "not-an-absolute-path", srv.Listener.Addr().String()); err == nil || len(result.PeerCertificates) != 0 {
		t.Fatal("a working Go probe masked invalid operator configuration")
	}
	var upgrades atomic.Int32
	result, err := ProbeWithNativeFallback(context.Background(), executable, srv.Listener.Addr().String(), WithPreHandshake(func(context.Context, net.Conn) error {
		upgrades.Add(1)
		return errors.New("test application refuses TLS upgrade")
	}))
	if err == nil || len(result.PeerCertificates) != 0 || upgrades.Load() != 1 {
		t.Fatal("failed application upgrade became a direct TLS success")
	}
}
