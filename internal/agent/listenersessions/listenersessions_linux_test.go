// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package listenersessions

import (
	"net"
	"testing"
	"time"
)

// A245-L2 (Linux): a real accepted connection on a real listener is counted
// once, held by this test process: compared with a moment after the process
// started it is held by an older process, and compared with a moment before
// it, by a newer one. The client's own socket (an ephemeral local port) and
// the listening socket are not counted.
func TestObserveCountsARealConnectionA245L2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = server.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	after, err := Observe(port, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if after.Established != 1 || after.HeldByOlder != 1 || after.Unattributed != 0 || !after.Valid() {
		t.Fatalf("compared with a later moment: %+v", after)
	}
	before, err := Observe(port, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if before.Established != 1 || before.HeldByOlder != 0 || before.Unattributed != 0 || !before.Valid() {
		t.Fatalf("compared with a moment before the process started: %+v", before)
	}
	_ = server.Close()
	_ = client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone, err := Observe(port, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if gone.Established == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed connection still counted: %+v", gone)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("A245L2_LISTENER_SESSIONS_OK port=%d older=%+v newer=%+v", port, after, before)
}
