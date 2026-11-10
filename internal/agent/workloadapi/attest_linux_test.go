// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package workloadapi

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const a203HelperSocket = "TRSTCTL_A203_HELPER_SOCKET"

// TestA203ConnectHelper is not a test of its own: re-executed with
// TRSTCTL_A203_HELPER_SOCKET set, this test binary connects to that socket and
// exits, which is the caller the pid-reuse test needs.
func TestA203ConnectHelper(t *testing.T) {
	socket := os.Getenv(a203HelperSocket)
	if socket == "" {
		t.Skip("helper process only")
	}
	// #nosec G704 -- the parent test hands its own temporary socket's path to this helper process (CWE-918).
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func linuxListen(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "trstctl-a203-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "w.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, socket
}

func hasPathSelector(id PeerIdentity) bool {
	for _, selector := range id.Selectors() {
		if len(selector) > len("unix:path:") && selector[:len("unix:path:")] == "unix:path:" {
			return true
		}
	}
	return false
}

// peerPIDFDSupported reports whether this kernel answers SO_PEERPIDFD (6.5+).
func peerPIDFDSupported(t *testing.T, conn net.Conn) bool {
	t.Helper()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	supported := false
	if err := raw.Control(func(fd uintptr) {
		if pidfd, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); err == nil {
			supported = true
			_ = unix.Close(pidfd)
		}
	}); err != nil {
		t.Fatal(err)
	}
	return supported
}

// A connection from this live test process attests to this test binary; on a
// kernel without SO_PEERPIDFD it attests no path at all rather than a guess.
func TestLinuxPeerAttestationResolvesTheConnectingExecutable(t *testing.T) {
	ln, socket := linuxListen(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	id, err := AttestPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !peerPIDFDSupported(t, conn) {
		if id.Path != "" || hasPathSelector(id) {
			t.Fatalf("without SO_PEERPIDFD the caller was attested as %q; want no path selector", id.Path)
		}
		t.Skip("this kernel has no SO_PEERPIDFD (Linux 6.5+): no path selector, as intended")
	}
	if id.PID != os.Getpid() || id.UID != os.Getuid() || id.Path != self || !hasPathSelector(id) {
		t.Fatalf("own connection attested as %+v (selectors %v), want pid %d path %s", id, id.Selectors(), os.Getpid(), self)
	}
}

// A203-L3: a process that connects and exits frees its pid. When another
// binary is given that pid before the agent reads the caller's executable,
// /proc/<pid>/exe names the other binary, and attesting it would let the
// first caller claim the second binary's path selector. Reproduced for real:
// the pid is handed to /bin/sleep through ns_last_pid, which needs
// CAP_SYS_ADMIN in this pid namespace (a privileged container), so the test
// skips elsewhere.
func TestLinuxPathSelectorIsNotTakenFromAReusedPID(t *testing.T) {
	const lastPID = "/proc/sys/kernel/ns_last_pid"
	if err := os.WriteFile(lastPID, []byte("0"), 0o600); err != nil {
		t.Skipf("cannot choose the next pid here (%v); run in a privileged container", err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep is needed as the reused pid's binary: %v", err)
	}
	if sleep, err = filepath.EvalSymlinks(sleep); err != nil {
		t.Fatal(err)
	}
	ln, socket := linuxListen(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(self, "-test.run=^TestA203ConnectHelper$") // #nosec G204 -- the test re-executes its own binary (CWE-78)
	helper.Env = append(os.Environ(), a203HelperSocket+"="+socket)
	if err := helper.Run(); err != nil {
		t.Fatalf("connect helper: %v", err)
	}
	caller := helper.Process.Pid
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var reuser *exec.Cmd
	for attempt := 0; attempt < 50 && reuser == nil; attempt++ {
		if err := os.WriteFile(lastPID, []byte(strconv.Itoa(caller-1)), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(sleep, "30") // #nosec G204 -- the system sleep binary (CWE-78)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if cmd.Process.Pid == caller {
			reuser = cmd
			break
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		time.Sleep(10 * time.Millisecond)
	}
	if reuser == nil {
		t.Skipf("could not hand pid %d to another binary in 50 attempts", caller)
	}
	t.Cleanup(func() { _ = reuser.Process.Kill(); _ = reuser.Wait() })
	if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(caller), "exe")); err != nil || target != sleep {
		t.Fatalf("pid %d now runs %q (%v); want the reused pid's binary %s", caller, target, err, sleep)
	}

	id, err := AttestPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	if id.PID != caller {
		t.Fatalf("attested pid %d, want the caller's %d", id.PID, caller)
	}
	if id.Path != "" || hasPathSelector(id) {
		t.Fatalf("an exited caller was attested as %q (selectors %v): the reused pid's binary, not the caller's", id.Path, id.Selectors())
	}
}
