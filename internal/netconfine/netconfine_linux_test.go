// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package netconfine

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary is also the helper and the confined probe.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperArg {
		os.Exit(RunHelper(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if targets := os.Getenv("TRSTCTL_NETCONFINE_PROBE"); targets != "" {
		os.Exit(probe(strings.Split(targets, ",")))
	}
	os.Exit(m.Run())
}

// probe dials each target and says what happened, then names its effective
// capabilities.
func probe(targets []string) int {
	for _, target := range targets {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second) // #nosec G704 -- the probe dials the test's own listeners to show which the confinement lets through
		if err != nil {
			fmt.Printf("%s: %s\n", target, dialFailure(err))
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("hello\n"))
		reply, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		fmt.Printf("%s: reached %q\n", target, strings.TrimSpace(reply))
	}
	status, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fmt.Println(strings.Join(strings.Fields(line), " "))
		}
	}
	return 0
}

func dialFailure(err error) string {
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	default:
		return "failed: " + err.Error()
	}
}

// A257-L2 Done-when (Linux): a confined command reaches its forwards and
// nothing else. Outside the confinement an echo server serves a Unix socket and
// another listens on every address; the confined probe reaches the echo
// through its forward's loopback address, gets refused on the other server's
// loopback port (another network's loopback) and finds the host's own address
// unreachable (its network has no route anywhere), and runs with no
// capability.
func TestConfinedCommandReachesOnlyItsForwardsA257L2(t *testing.T) {
	dir, err := os.MkdirTemp("", "nc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "account-1.sock")
	upstream, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	echo := func(ln net.Listener, label string) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte(label + " " + line))
			}()
		}
	}
	go echo(upstream, "tunnel")
	outside, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- the outside listener answers on every address so the test proves the confined command reaches none of them
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outside.Close() })
	go echo(outside, "outside")
	port := outside.Addr().(*net.TCPAddr).Port
	hostIP := ""
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			hostIP = ipnet.IP.String()
			break
		}
	}
	if hostIP == "" {
		t.Skip("no non-loopback IPv4 address to try from inside the confinement")
	}
	// Outside the confinement the host address answers.
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostIP, port), 2*time.Second); err != nil {
		t.Fatalf("the outside server is not reachable outside the confinement: %v", err)
	} else {
		_ = conn.Close()
	}
	targets := []string{"127.0.0.1:30001", fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("%s:%d", hostIP, port)}
	argv := Wrap(os.Args[0], []Forward{{Listen: "127.0.0.1:30001", Socket: socket}}, []string{os.Args[0]})
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the test re-runs its own binary through Wrap
	cmd.Env = append(os.Environ(), "TRSTCTL_NETCONFINE_PROBE="+strings.Join(targets, ","))
	if err := Isolate(cmd); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "operation not permitted") || errors.Is(err, syscall.EPERM) {
			t.Skipf("this host refuses an unprivileged user namespace: %v\n%s", err, out)
		}
		t.Fatalf("the confined probe failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		`127.0.0.1:30001: reached "tunnel hello"`,
		fmt.Sprintf("127.0.0.1:%d: refused", port),
		fmt.Sprintf("%s:%d: unreachable", hostIP, port),
		"CapEff: 0000000000000000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the confined probe said:\n%s\nwant a line %q", got, want)
		}
	}
	t.Logf("A257L2_CONFINED_OK\n%s", got)
}
