// SPDX-License-Identifier: BUSL-1.1

//go:build linux && workloadapi_namespace_integration

package workloadapi

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const mountNamespaceLabSocket = "TRSTCTL_TEST_MOUNT_NAMESPACE_SOCKET"

// CR-693: run this listener and TestLinuxMountNamespacePeerFixture in separate
// mount namespaces that share a PID namespace and an owned socket directory.
func TestLinuxPathSelectorRequiresTheAgentsMountNamespace(t *testing.T) {
	socket := os.Getenv(mountNamespaceLabSocket)
	if socket == "" {
		t.Fatal("mount namespace lab requires an owned socket path")
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := ln.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Log("mount namespace lab listener ready")
	conn, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = conn.Write([]byte{1})
		_ = conn.Close()
	}()
	if !peerPIDFDSupported(t, conn) {
		t.Fatal("mount namespace lab requires SO_PEERPIDFD")
	}

	id, err := AttestPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	peerProc := filepath.Join("/proc", strconv.Itoa(id.PID))
	localMount, err := os.Stat("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	peerMount, err := os.Stat(filepath.Join(peerProc, "ns", "mnt"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(localMount, peerMount) {
		t.Fatal("mount namespace fixture is in the listener's namespace")
	}
	if path, err := os.Readlink(filepath.Join(peerProc, "exe")); err != nil || path == "" {
		t.Fatalf("live fixture executable is unavailable: %v", err)
	}
	if id.UID != os.Getuid() || id.GID != os.Getgid() {
		t.Fatalf("peer uid/gid = %d/%d, want %d/%d", id.UID, id.GID, os.Getuid(), os.Getgid())
	}
	if id.Path != "" || hasPathSelector(id) {
		t.Fatal("a peer in a different mount namespace supplied an executable path selector")
	}
}

// TestLinuxMountNamespacePeerFixture connects and remains live until the
// listener has read the kernel credentials and completed its assertions.
func TestLinuxMountNamespacePeerFixture(t *testing.T) {
	socket := os.Getenv(mountNamespaceLabSocket)
	if socket == "" {
		t.Fatal("mount namespace lab requires an owned socket path")
	}
	// #nosec G704 -- this fixture connects to the test's own local socket (CWE-918).
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("listener did not acknowledge the fixture: %v", err)
	}
}
