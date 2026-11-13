// SPDX-License-Identifier: BUSL-1.1

package netconfine

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A257-L2: the helper's arguments carry each forward and the command intact,
// and refuse a forward that is not a loopback address and an absolute socket.
func TestWrapRoundTripsAndRefusesBadForwardsA257L2(t *testing.T) {
	forwards := []Forward{{Listen: "127.0.0.1:30001", Socket: "/run/user/1000/trstctl/account-1.sock"}}
	argv := Wrap("/usr/bin/trstctl-cli", forwards, []string{"psql", "--", "-c", "select 1"})
	if argv[0] != "/usr/bin/trstctl-cli" || argv[1] != HelperArg {
		t.Fatalf("argv = %q", argv)
	}
	gotForwards, gotArgv, err := parseHelperArgs(argv[2:])
	if err != nil || !reflect.DeepEqual(gotForwards, forwards) || !reflect.DeepEqual(gotArgv, []string{"psql", "--", "-c", "select 1"}) {
		t.Fatalf("parsed %v %q %v", gotForwards, gotArgv, err)
	}
	for _, bad := range [][]string{
		{"--forward", "10.0.0.1:5432=/run/s.sock", "--", "x"},
		{"--forward", "127.0.0.1:5432=relative.sock", "--", "x"},
		{"--forward", "localhost:5432=/run/s.sock", "--", "x"},
		{"--forward", "127.0.0.1:5432=/run/s.sock"},
		{"--", ""},
		{"--other", "--", "x"},
	} {
		if _, _, err := parseHelperArgs(bad); err == nil {
			t.Fatalf("helper arguments %q were accepted", bad)
		}
	}
}

// A257-L2: a forward carries a TCP connection to its Unix socket and back.
func TestForwardCarriesAConnectionToItsSocketA257L2(t *testing.T) {
	dir, err := os.MkdirTemp("", "nc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	upstream, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte("echo " + line))
			}()
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go forward(ctx, ln, socket)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "echo hello\n" {
		t.Fatalf("reply %q %v", reply, err)
	}
}
