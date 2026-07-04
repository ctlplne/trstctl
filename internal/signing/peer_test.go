// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"net"
	"testing"
	"time"
)

// fakeListener feeds pre-made conns to Accept so the peer-uid gate can be exercised
// without a real Unix socket.
type fakeListener struct {
	conns chan net.Conn
}

func (f *fakeListener) Accept() (net.Conn, error) { return <-f.conns, nil }
func (f *fakeListener) Close() error              { return nil }
func (f *fakeListener) Addr() net.Addr            { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

// closeSpyConn wraps a net.Conn to record whether it was closed (i.e. rejected).
type closeSpyConn struct {
	net.Conn
	closed chan struct{}
}

func (c *closeSpyConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return c.Conn.Close()
}

// TestPeerAuthListenerRejectsMismatchedUID is the SIGNER-006 acceptance: a peer
// whose resolved uid does not match the allowed uid is closed by the listener and
// never returned to Accept's caller (so it never reaches a signer handler). The
// rejection branch was previously untested. A second, matching connection lets
// Accept make progress, so we can assert both that the mismatched conn was closed
// and that only the matching one is returned.
func TestPeerAuthListenerRejectsMismatchedUID(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 2)}

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	spy := &closeSpyConn{Conn: server, closed: make(chan struct{})}

	matching, mclient := net.Pipe()
	defer func() { _ = mclient.Close() }()
	defer func() { _ = matching.Close() }()

	// First conn (the spy) resolves to a non-matching uid; the second matches.
	uids := map[net.Conn]int{spy: 1234, matching: 1000}
	l := &peerAuthListener{
		Listener:   fl,
		allowedUID: 1000,
		peerUID:    func(c net.Conn) (int, bool) { return uids[c], true },
	}

	fl.conns <- spy      // mismatched uid -> must be closed, skipped
	fl.conns <- matching // matching uid -> returned

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != matching {
		t.Fatal("Accept returned the wrong connection; the mismatched-uid conn must be skipped")
	}
	select {
	case <-spy.closed:
		// Good: the mismatched-uid connection was closed (rejected).
	case <-time.After(2 * time.Second):
		t.Fatal("mismatched-uid connection was not closed by the listener (SIGNER-006)")
	}
}

// TestPeerAuthListenerAcceptsMatchingUID confirms the allow path: a matching uid is
// returned to the caller unclosed.
func TestPeerAuthListenerAcceptsMatchingUID(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 1)}
	l := &peerAuthListener{
		Listener:   fl,
		allowedUID: 1000,
		peerUID:    func(net.Conn) (int, bool) { return 1000, true },
	}
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	fl.conns <- server

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != server {
		t.Fatal("Accept did not return the matching-uid connection")
	}
}

// TestPeerAuthListenerRejectsWhenUIDUndeterminable proves SIGNER-002's fail-closed
// default: if the platform cannot bind the UDS peer to a uid, the signer must not
// silently fall back to filesystem permissions only.
func TestPeerAuthListenerRejectsWhenUIDUndeterminable(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 2)}
	l := &peerAuthListener{
		Listener:   fl,
		allowedUID: 1000,
		peerUID:    func(net.Conn) (int, bool) { return 0, false }, // undeterminable (non-Linux)
	}
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	spy := &closeSpyConn{Conn: server, closed: make(chan struct{})}

	matching, mclient := net.Pipe()
	defer func() { _ = mclient.Close() }()
	defer func() { _ = matching.Close() }()
	l.peerUID = func(c net.Conn) (int, bool) {
		if c == matching {
			return 1000, true
		}
		return 0, false
	}
	fl.conns <- spy
	fl.conns <- matching

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != matching {
		t.Fatal("Accept returned the undetermined-uid connection; it must wait for an authenticated peer")
	}
	select {
	case <-spy.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("undetermined-uid connection was not closed by the listener")
	}
}

// TestPeerAuthListenerAcceptsUndeterminableUIDOnlyWithDevOverride keeps the local
// non-Linux development escape hatch explicit and test-visible.
func TestPeerAuthListenerAcceptsUndeterminableUIDOnlyWithDevOverride(t *testing.T) {
	assertPeerAuthListenerAcceptsWithExplicitDevOverride(t)
}

// TestPeerAuthListenerAcceptsWithExplicitDevOverride uses the exact WIRE-009
// acceptance-test name from the audit backlog.
func TestPeerAuthListenerAcceptsWithExplicitDevOverride(t *testing.T) {
	assertPeerAuthListenerAcceptsWithExplicitDevOverride(t)
}

func assertPeerAuthListenerAcceptsWithExplicitDevOverride(t *testing.T) {
	t.Helper()

	fl := &fakeListener{conns: make(chan net.Conn, 1)}
	l := &peerAuthListener{
		Listener:                     fl,
		allowedUID:                   1000,
		allowUndeterminedDevNonLinux: true,
		peerUID:                      func(net.Conn) (int, bool) { return 0, false },
	}
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	fl.conns <- server

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != server {
		t.Fatal("dev override should accept an undetermined-uid connection")
	}
}
