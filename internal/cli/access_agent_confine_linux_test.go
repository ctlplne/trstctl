// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package cli_test

import (
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/netconfine"
)

// The launcher re-runs its own binary as the confinement helper; under test
// that binary is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == netconfine.HelperArg {
		os.Exit(netconfine.RunHelper(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// A257-L2 Done-when (Linux): trstctl access agent --confine-network runs the
// command in a network of its own. Its first account's address is
// 127.0.0.1:30001, which it can open (the helper carries it to the launcher's
// tunnel); the host's own address is unreachable from it; it holds no
// capability; and its session is revoked when it exits.
func TestAccessAgentConfinesTheCommandsNetworkA257L2(t *testing.T) {
	probe := exec.Command("/bin/true")
	if err := netconfine.Isolate(probe); err != nil {
		t.Fatal(err)
	}
	if err := probe.Run(); err != nil {
		if errors.Is(err, syscall.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("this host refuses an unprivileged user namespace: %v", err)
		}
		t.Fatalf("an isolated /bin/true failed: %v", err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	outside, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- the outside listener answers on every address so the test proves the confined command reaches none of them
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outside.Close() }()
	go func() {
		for {
			conn, err := outside.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
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
	hostPort := outside.Addr().(*net.TCPAddr).Port
	s := &accessAgentServer{}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	dir := t.TempDir()
	payload := filepath.Join(dir, "attestation")
	if err := os.WriteFile(payload, []byte("genuine"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`echo "addr=$TRSTCTL_ACCESS_1_ADDR"
if exec 3<>/dev/tcp/127.0.0.1/30001; then echo tunnel=open; exec 3>&-; else echo tunnel=closed; fi
if (exec 4<>/dev/tcp/%s/%d) 2>/dev/null; then echo host=reached; else echo host=unreachable; fi
grep CapEff /proc/self/status`, hostIP, hostPort)
	code, stdout, stderr := run(t, []string{"access", "agent", "--account", "postgres/pg-gw:readonly", "--reason", "confined report",
		"--method", "stub_pam", "--payload-file", payload, "--confine-network", "--", bash, "-c", script},
		cli.Env{Server: srv.URL, Token: agentTestToken, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{"addr=127.0.0.1:30001", "tunnel=open", "host=unreachable", "CapEff:\t0000000000000000"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the confined command said:\n%s\nwant %q (stderr=%s)", stdout, want, stderr)
		}
	}
	if last := s.calls[len(s.calls)-1]; last != "POST /api/v1/access/sessions/"+agentTestID+"/revoke" {
		t.Fatalf("the session was not revoked at exit: %v", s.calls)
	}
	t.Logf("A257L2_LAUNCHER_CONFINED_OK\n%s", stdout)
}
