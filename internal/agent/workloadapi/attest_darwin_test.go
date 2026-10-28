// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package workloadapi

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// On darwin the connecting process's executable is resolved from its audit
// token: a connection from this test process attests to this test binary, and
// one from a different process (the system's nc) attests to that program.
func TestDarwinPeerAttestationResolvesTheConnectingExecutable(t *testing.T) {
	dir, err := os.MkdirTemp("", "trstctl-a204-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accept := func() PeerIdentity {
		t.Helper()
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		id, err := AttestPeer(conn)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	id := accept()
	_ = client.Close()
	if id.PID != os.Getpid() || id.UID != os.Getuid() || id.Path != self {
		t.Fatalf("own connection attested as %+v, want pid %d uid %d path %s", id, os.Getpid(), os.Getuid(), self)
	}
	if !containsSelector(id.Selectors(), "unix:path:"+self) {
		t.Fatalf("selectors %v carry no path selector", id.Selectors())
	}

	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skipf("nc is needed for a second process: %v", err)
	}
	ncPath, err := filepath.EvalSymlinks(nc)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(nc, "-U", socket) // #nosec G204 -- test runs the system nc against its own socket (CWE-78)
	cmd.Stdin = strings.NewReader("")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan PeerIdentity, 1)
	go func() { done <- accept() }()
	var other PeerIdentity
	select {
	case other = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("nc did not connect")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if other.PID != cmd.Process.Pid || other.Path != ncPath {
		t.Fatalf("nc's connection attested as %+v, want pid %d path %s", other, cmd.Process.Pid, ncPath)
	}
}

// A pid version that does not match the live process yields no path: the path
// selector is only ever the connecting process's own.
func TestDarwinPathRefusesAStalePIDVersion(t *testing.T) {
	dir, err := os.MkdirTemp("", "trstctl-a204v-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("unix", filepath.Join(dir, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var token auditToken
	var tokenErr error
	if err := raw.Control(func(fd uintptr) { token, tokenErr = peerAuditToken(fd) }); err != nil || tokenErr != nil {
		t.Fatalf("read the audit token: %v %v", err, tokenErr)
	}
	if path := darwinExecutablePath(token); path == "" {
		t.Fatal("the live token resolved no path")
	}
	stale := token
	stale[7] ^= 1
	if path := darwinExecutablePath(stale); path != "" {
		t.Fatalf("a stale pid version resolved %q", path)
	}
	stale = token
	stale[5] = 0
	if path := darwinExecutablePath(stale); path != "" {
		t.Fatalf("pid 0 resolved %q", path)
	}
}

func containsSelector(selectors []string, want string) bool {
	for _, s := range selectors {
		if s == want {
			return true
		}
	}
	return false
}
