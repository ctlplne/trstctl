// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// A257-L2: in a confined network each tunnel is a Unix socket in the
// launcher's private directory, and the command is told the loopback address
// its helper carries there: 127.0.0.1:30001 for the first account, in the
// environment, the stock client's variables and the instructions alike.
func TestConfinedTunnelsAreSocketsBehindLoopbackAddressesA257L2(t *testing.T) {
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	l := &agentLauncher{ctx: ctx, stderr: io.Discard}
	s := &agentSession{account: agentAccount{TargetType: "postgres", TargetID: "orders-db", Role: "readonly"}}
	if err := l.serve(ctx, &wg, s, dir, 1, true); err != nil {
		t.Fatal(err)
	}
	if s.addr.String() != "127.0.0.1:30001" || s.socket != dir+"/account-1.sock" {
		t.Fatalf("confined tunnel = %s via %s", s.addr, s.socket)
	}
	if info, err := os.Stat(s.socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the tunnel socket: %v %v", info, err)
	}
	if conn, err := net.Dial("unix", s.socket); err != nil {
		t.Fatalf("the tunnel socket does not accept: %v", err)
	} else {
		_ = conn.Close()
	}
	vars := agentVariables([]*agentSession{s}, dir+"/instructions.md")
	if string(vars["TRSTCTL_ACCESS_1_ADDR"]) != "127.0.0.1:30001" || string(vars["PGHOST"]) != "127.0.0.1" || string(vars["PGPORT"]) != "30001" {
		t.Fatalf("variables = ADDR %s PGHOST %s PGPORT %s", vars["TRSTCTL_ACCESS_1_ADDR"], vars["PGHOST"], vars["PGPORT"])
	}
	if text := agentInstructions([]*agentSession{s}); !strings.Contains(text, "\n   address: 127.0.0.1:30001 (environment TRSTCTL_ACCESS_1_ADDR)\n") {
		t.Fatalf("instructions:\n%s", text)
	}
}
