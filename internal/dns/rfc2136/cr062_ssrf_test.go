// SPDX-License-Identifier: BUSL-1.1

package rfc2136

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCR062DefaultRFC2136DoesNotSendUpdateToLoopback(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	provider := New(listener.LocalAddr().String(), "example.test", Credentials{})
	err = provider.PresentTXT(ctx, "_acme-challenge.example.test", "fixture")
	if err == nil {
		t.Fatal("default RFC2136 provider accepted a loopback update")
	}
	if err := listener.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [4096]byte
	if n, _, readErr := listener.ReadFrom(buf[:]); readErr == nil {
		t.Fatalf("default RFC2136 provider sent %d bytes to loopback", n)
	}
}
