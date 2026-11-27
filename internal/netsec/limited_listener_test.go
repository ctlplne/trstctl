// SPDX-License-Identifier: BUSL-1.1

package netsec_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestLimitedListenerCapsOneSourceAndReleasesClosedConnections(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := netsec.LimitListenerBySource(base, 3, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), ReadHeaderTimeout: time.Second, IdleTimeout: time.Second}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	defer func() { _ = server.Close(); <-done }()
	request := func() (net.Conn, error) {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: relay.local\r\n\r\n"); err != nil {
			_ = conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		return conn, nil
	}
	first, err := request()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := request()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if extra, err := request(); err == nil {
		_ = extra.Close()
		t.Fatal("third connection from one source was admitted above the per-source cap")
	}
	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if replacement, err := request(); err == nil {
			_ = replacement.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("closed connection did not release its per-source slot")
}
