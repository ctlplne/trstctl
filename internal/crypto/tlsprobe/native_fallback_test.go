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
	"os"
	"path/filepath"
	"strings"
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

// B6-2: a host profile that pins OpenSSL behind a package manager's symlink
// used to fail with "must be a regular executable file", which hid the one
// fact the operator needs: the resolved path to pin instead.
func TestValidateOpenSSLExecutableNamesASymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "openssl-real")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- fixture executable written by this test (CWE-276)
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openssl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := ValidateOpenSSLExecutable(link)
	if err == nil || !strings.Contains(err.Error(), "symbolic link to") || !strings.Contains(err.Error(), "openssl-real") {
		t.Fatalf("symlinked executable = %v, want the resolved target named", err)
	}
	if err := ValidateOpenSSLExecutable(real); err != nil {
		t.Fatalf("regular executable = %v, want accepted", err)
	}
	if err := ValidateOpenSSLExecutable(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing executable was accepted")
	}
}
