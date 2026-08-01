// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

const dodParentSubstrateConnectionLifetime = 2 * time.Minute

// dodParentSubstrateLoopbackBridge makes a parent-owned DoD substrate available
// through a literal child-process loopback address. Production network policy is
// intentionally strict: plaintext development endpoints must be loopback, while
// Docker Desktop exposes the parent as host.docker.internal. This raw TCP bridge
// keeps that policy honest instead of teaching production code that Docker's
// private gateway is loopback. HTTPS bytes are not terminated, so Entrust mTLS
// still reaches the independent parent process unchanged.
func dodParentSubstrateLoopbackBridge(t *testing.T, endpoint string) string {
	t.Helper()
	scheme, upstreamAddress, err := dodParentSubstrateBridgeTarget(endpoint)
	if err != nil {
		t.Fatalf("validate parent substrate endpoint: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for parent substrate loopback bridge: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	bridge := &dodParentSubstrateBridge{
		listener: listener,
		upstream: upstreamAddress,
		active:   map[net.Conn]struct{}{},
		done:     make(chan struct{}),
	}
	go bridge.serve(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		bridge.closeActive()
		select {
		case <-bridge.done:
		case <-time.After(5 * time.Second):
			t.Error("parent substrate loopback bridge did not stop")
		}
	})
	return scheme + "://" + listener.Addr().String()
}

type dodParentSubstrateBridge struct {
	listener net.Listener
	upstream string

	mu      sync.Mutex
	active  map[net.Conn]struct{}
	closing bool
	wg      sync.WaitGroup
	done    chan struct{}
}

func (b *dodParentSubstrateBridge) serve(ctx context.Context) {
	defer close(b.done)
	defer b.wg.Wait()
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			return
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.forward(ctx, connection)
		}()
	}
}

func (b *dodParentSubstrateBridge) forward(ctx context.Context, downstream net.Conn) {
	if !b.track(downstream) {
		_ = downstream.Close()
		return
	}
	defer b.untrackAndClose(downstream)
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext(ctx, "tcp", b.upstream)
	if err != nil {
		return
	}
	if !b.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer b.untrackAndClose(upstream)

	deadline := time.Now().Add(dodParentSubstrateConnectionLifetime)
	_ = downstream.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	requestCopied := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, downstream)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(requestCopied)
	}()
	_, _ = io.Copy(downstream, upstream)
	if tcp, ok := downstream.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	select {
	case <-requestCopied:
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
}

func (b *dodParentSubstrateBridge) track(connection net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return false
	}
	b.active[connection] = struct{}{}
	return true
}

func (b *dodParentSubstrateBridge) untrackAndClose(connection net.Conn) {
	b.mu.Lock()
	delete(b.active, connection)
	b.mu.Unlock()
	_ = connection.Close()
}

func (b *dodParentSubstrateBridge) closeActive() {
	b.mu.Lock()
	b.closing = true
	connections := make([]net.Conn, 0, len(b.active))
	for connection := range b.active {
		connections = append(connections, connection)
	}
	b.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func dodParentSubstrateBridgeTarget(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return "", "", errors.New("endpoint is not a URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", errors.New("endpoint scheme must be http or https")
	}
	if parsed.User != nil || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery {
		return "", "", errors.New("endpoint must be an origin without userinfo, path, query, or fragment")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "host.docker.internal" {
		return "", "", fmt.Errorf("endpoint host %q is outside the parent broker allowlist", host)
	}
	port := parsed.Port()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", errors.New("endpoint requires an explicit port in 1..65535")
	}
	return parsed.Scheme, net.JoinHostPort(host, port), nil
}

func TestDODParentSubstrateLoopbackBridgeForwardsHTTP(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { // #nosec G112 -- local test listener owned and torn down by the test (CWE-400)
		if request.URL.Path != "/proof" {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(upstream) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	bridge := dodParentSubstrateLoopbackBridge(t, "http://"+upstream.Addr().String())
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(bridge + "/proof")
	if err != nil {
		t.Fatalf("request through parent substrate bridge: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("bridge status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestDODParentSubstrateLoopbackBridgePreservesOpaqueHTTPSBytes(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	requestBytes := []byte{0x16, 0x03, 0x03, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x7f, 0x80}
	responseBytes := []byte{0x16, 0x03, 0x03, 0x00, 0x07, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03}
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer func() { _ = connection.Close() }()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(requestBytes))
		if _, readErr := io.ReadFull(connection, got); readErr != nil {
			serverResult <- readErr
			return
		}
		if string(got) != string(requestBytes) {
			serverResult <- errors.New("bridge changed opaque request bytes")
			return
		}
		_, writeErr := connection.Write(responseBytes)
		serverResult <- writeErr
	}()

	bridge := dodParentSubstrateLoopbackBridge(t, "https://"+upstream.Addr().String())
	parsed, err := url.Parse(bridge)
	if err != nil || parsed.Scheme != "https" {
		t.Fatalf("HTTPS bridge endpoint = %q err=%v", bridge, err)
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial HTTPS byte bridge: %v", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write(requestBytes); err != nil {
		t.Fatalf("write opaque request: %v", err)
	}
	got := make([]byte, len(responseBytes))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatalf("read opaque response: %v", err)
	}
	if string(got) != string(responseBytes) {
		t.Fatal("bridge changed opaque response bytes")
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("opaque upstream: %v", err)
	}
}

func TestDODParentSubstrateBridgeTargetIsClosed(t *testing.T) {
	for _, test := range []struct {
		raw         string
		wantScheme  string
		wantAddress string
		wantError   bool
	}{
		{raw: "http://127.0.0.1:8080", wantScheme: "http", wantAddress: "127.0.0.1:8080"},
		{raw: "https://host.docker.internal:9443", wantScheme: "https", wantAddress: "host.docker.internal:9443"},
		{raw: "http://localhost:8080", wantError: true},
		{raw: "http://attacker.test:8080", wantError: true},
		{raw: "http://127.0.0.1", wantError: true},
		{raw: "http://127.0.0.1:8080/path", wantError: true},
		{raw: "ftp://127.0.0.1:21", wantError: true},
	} {
		scheme, address, err := dodParentSubstrateBridgeTarget(test.raw)
		if test.wantError {
			if err == nil {
				t.Errorf("accepted untrusted endpoint %q as %s %s", test.raw, scheme, address)
			}
			continue
		}
		if err != nil || scheme != test.wantScheme || address != test.wantAddress {
			t.Errorf("target(%q) = %q %q err=%v, want %q %q", test.raw, scheme, address, err, test.wantScheme, test.wantAddress)
		}
	}
}
