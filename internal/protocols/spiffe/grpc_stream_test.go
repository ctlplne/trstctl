// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

type x509StreamProbe struct {
	grpc.ServerStream
	ctx       context.Context
	responses chan []byte
}

func (s *x509StreamProbe) Context() context.Context { return s.ctx }

func (s *x509StreamProbe) Send(resp *workloadpb.X509SVIDResponse) error {
	if len(resp.Svids) == 0 || len(resp.Svids[0].X509SvidKey) == 0 {
		return context.DeadlineExceeded
	}
	leaf := append([]byte(nil), resp.Svids[0].X509Svid...)
	select {
	case s.responses <- leaf:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func newX509StreamProbe(t *testing.T, ttl time.Duration) (*WorkloadAPIServer, *x509StreamProbe, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(SecurityHeaderKey, SecurityHeaderValue))
	wl, err := New(Config{
		Issuer: testIssuer(t), TenantID: "tenant-a", TrustDomain: "example.org",
		Entries: []RegistrationEntry{{SPIFFEID: "spiffe://example.org/workload", Selectors: []string{"unix"}, X509TTL: ttl}},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return NewWorkloadAPIServer(wl, []string{"unix"}), &x509StreamProbe{ctx: ctx, responses: make(chan []byte, 4)}, cancel
}

func TestWorkloadAPIStreamStaysOpenWithoutEarlyRemint(t *testing.T) {
	api, stream, cancel := newX509StreamProbe(t, time.Hour)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- api.FetchX509SVID(&workloadpb.X509SVIDRequest{}, stream) }()
	select {
	case <-stream.responses:
	case <-time.After(3 * time.Second):
		t.Fatal("initial SVID was not delivered")
	}
	select {
	case err := <-done:
		t.Fatalf("long-lived stream ended immediately: %v", err)
	case <-stream.responses:
		t.Fatal("long-lived SVID was reminted before expiry approached")
	case <-time.After(350 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled stream returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled stream did not release")
	}
}

func TestWorkloadAPIStreamRenewsShortSVIDBeforeExpiry(t *testing.T) {
	api, stream, cancel := newX509StreamProbe(t, 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- api.FetchX509SVID(&workloadpb.X509SVIDRequest{}, stream) }()
	var first, second []byte
	select {
	case first = <-stream.responses:
	case <-time.After(3 * time.Second):
		t.Fatal("initial short SVID was not delivered")
	}
	select {
	case second = <-stream.responses:
	case err := <-done:
		t.Fatalf("stream ended before renewal: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("short SVID was not renewed before expiry")
	}
	if bytes.Equal(first, second) {
		t.Fatal("renewal repeated the old certificate")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled stream returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("renewed stream did not release")
	}
}
