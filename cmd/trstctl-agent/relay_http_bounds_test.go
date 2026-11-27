// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestRelayHTTPServerClosesStalledBodiesAndIdleConnections(t *testing.T) {
	finished := make(chan error, 1)
	server := newRelayHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, err := io.ReadAll(r.Body)
			finished <- err
			return
		}
		_, _ = w.Write([]byte("ok"))
	}), 100*time.Millisecond, time.Second)
	server.IdleTimeout = 100 * time.Millisecond
	if server.MaxHeaderBytes != 16<<10 || server.WriteTimeout != time.Second {
		t.Fatalf("relay server limits: header=%d write=%s", server.MaxHeaderBytes, server.WriteTimeout)
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := netsec.LimitListenerBySource(base, 3, 2)
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	defer func() { _ = server.Close(); <-done }()
	stalled, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stalled, "POST /ocsp/issuer HTTP/1.1\r\nHost: relay.local\r\nContent-Length: 100000\r\n\r\nabc"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("incomplete OCSP body finished without a timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled OCSP body held the handler past its read deadline")
	}
	_ = stalled.Close()
	idle, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()
	_ = idle.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(idle, "GET /crl/issuer HTTP/1.1\r\nHost: relay.local\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(idle)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	time.Sleep(250 * time.Millisecond)
	if _, err := io.WriteString(idle, "GET /crl/issuer HTTP/1.1\r\nHost: relay.local\r\n\r\n"); err == nil {
		if _, err := http.ReadResponse(reader, nil); err == nil {
			t.Fatal("idle relay connection served a second request past its idle deadline")
		}
	}
}
