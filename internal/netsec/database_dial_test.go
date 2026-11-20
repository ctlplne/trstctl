// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDatabaseDialChecksActualPeerAndLocalPolicy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	endpoint := listener.Addr().String()
	if _, err := NewDatabaseDialer(DatabaseDialOptions{}).DialContext(ctx, "tcp", endpoint); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("a tenant-stored connection without a private grant: %v", err)
	}
	private := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	approved := NewDatabaseDialer(DatabaseDialOptions{PrivateCIDRs: private})
	conn, err := approved.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		t.Fatalf("explicitly approved local test listener: %v", err)
	}
	_ = conn.Close()
	agent, err := ParseRelayEgress([]string{"127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	bounded := NewDatabaseDialer(DatabaseDialOptions{PrivateCIDRs: private, Agent: agent})
	if _, err := bounded.DialResolved(ctx, "tcp", endpoint); !errors.Is(err, ErrRelayEgressBlocked) {
		t.Fatalf("a destination outside the local agent policy: %v", err)
	}
	operator := NewDatabaseDialer(DatabaseDialOptions{OperatorFile: true})
	if err := operator.control("tcp", endpoint, nil); err != nil {
		t.Fatal(err)
	}
	if err := operator.ForDiscoveredPeer().control("tcp", endpoint, nil); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatal("a discovered database peer inherited direct file authority")
	}
}
