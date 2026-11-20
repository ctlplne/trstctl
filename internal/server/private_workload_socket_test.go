// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestDefaultSPIFFESocketUsesPrivateRuntimeLocation(t *testing.T) {
	if defaultSPIFFESocket != "/run/trstctl-spiffe/workload.sock" {
		t.Fatalf("default Workload API socket = %q, want private runtime location", defaultSPIFFESocket)
	}
}

func TestEnabledSPIFFEStartupRefusesUnsafeSocketDirectory(t *testing.T) {
	dir := privateSocketRuntimeTestDir(t)
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- deliberately unsafe directory tests fail-closed startup
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore owner-only test directory for cleanup
	socket := filepath.Join(dir, "workload.sock")
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: socket,
	}})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, _, err := startBackgroundRuntime(t.Context(), config.Default(), h.srv, h.store, logger)
	if stop != nil {
		stop()
	}
	if err == nil {
		t.Fatal("control plane startup succeeded while its enabled Workload API socket could not be trusted")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("failed startup left a socket at the unsafe path: %v", err)
	}
}

func TestActiveSPIFFESocketBindsBeforeControlPlaneHTTP(t *testing.T) {
	dir := privateSocketRuntimeTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- owner-only socket fixture
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "workload.sock")
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: socket,
	}}
	h := newOperatingServedHarness(t, protocols)
	cfg := config.Default()
	cfg.Protocols = protocols
	cfg.Server.Addr = privateSocketRuntimeAddress(t)
	cfg.Server.TLS.Mode = config.TLSDisabled
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stop, failure, err := startBackgroundRuntime(ctx, cfg, h.srv, h.store, logger)
	if runtime.GOOS == "windows" {
		if stop != nil {
			stop()
		}
		if err == nil || !strings.Contains(err.Error(), "owner validation is unavailable") {
			t.Fatalf("Windows started an owner-unverified Workload API: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		stop()
		t.Fatalf("Workload API was not bound before HTTP startup: info=%v err=%v", info, err)
	}
	if conn, err := net.DialTimeout("tcp", cfg.Server.Addr, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		stop()
		t.Fatal("HTTP accepted a connection before its Workload API was bound")
	}
	done := make(chan error, 1)
	go func() { done <- serveRuntime(ctx, cfg, h.srv, logger, stop, failure) }()
	privateSocketWaitForHTTP(t, cfg.Server.Addr)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime shutdown: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runtime did not stop after cancellation")
	}
}

func TestDormantEvalSPIFFEBindFailureStopsControlPlaneHTTP(t *testing.T) {
	dir := privateSocketRuntimeTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- owner-only socket fixture before activation
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Protocols.Profile = config.ProtocolProfileEval
	cfg.Protocols.EvalTenantID = servedTestTenant
	cfg.Protocols.SPIFFE.SocketPath = filepath.Join(dir, "workload.sock")
	cfg.Protocols.RAKeyFile = filepath.Join(t.TempDir(), "protocol-ra.key")
	cfg.Protocols.TSACertFile = filepath.Join(t.TempDir(), "tsa.crt")
	protocols, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, protocols)
	if h.srv.protocols.activation == nil || h.srv.protocols.activation.Active() {
		t.Fatal("eval profile did not start dormant")
	}
	cfg.Protocols = protocols
	cfg.Server.Addr = privateSocketRuntimeAddress(t)
	cfg.Server.TLS.Mode = config.TLSDisabled
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stop, failure, err := startBackgroundRuntime(ctx, cfg, h.srv, h.store, logger)
	if runtime.GOOS == "windows" {
		if stop != nil {
			stop()
		}
		if err == nil || !strings.Contains(err.Error(), "owner validation is unavailable") {
			t.Fatalf("Windows started a dormant owner-unverified Workload API: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cfg.Protocols.SPIFFE.SocketPath); !errors.Is(err, os.ErrNotExist) {
		stop()
		t.Fatalf("dormant eval profile bound a Workload API socket: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- serveRuntime(ctx, cfg, h.srv, logger, stop, failure) }()
	privateSocketWaitForHTTP(t, cfg.Server.Addr)
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- unsafe directory triggers the required fail-closed shutdown
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore owner-only test directory for cleanup
	h.srv.protocols.activation.Activate()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "SPIFFE Workload API") {
			t.Fatalf("runtime error = %v, want fatal Workload API bind failure", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("control plane kept serving after its Workload API bind failed")
	}
	if conn, err := net.DialTimeout("tcp", cfg.Server.Addr, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("control plane HTTP listener remained open after Workload API failure")
	}
}

func privateSocketRuntimeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func privateSocketRuntimeTestDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		// Resolve /tmp to keep the socket path short and avoid macOS's /var
		// symlink. Production correctly rejects symlinked ancestors.
		var err error
		base, err = filepath.EvalSymlinks("/tmp")
		if err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.MkdirTemp(base, "ws-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func privateSocketWaitForHTTP(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("control plane HTTP listener never became reachable")
}
