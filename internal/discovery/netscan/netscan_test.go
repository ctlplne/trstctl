package netscan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/netscan"
)

func targets(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.%d:443", i/256, i%256)
	}
	return out
}

// The scanner discovers the certificate a real TLS server presents and records
// it (with the address it was served from) for inventory merge.
func TestScanDiscoversRealCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	sink := netscan.NewMemorySink()
	s := netscan.New(sink, netscan.WithAllowLoopbackTargets(true))
	defer s.Close()

	rep := s.Scan(context.Background(), []string{addr})
	if rep.Discovered != 1 || rep.Failed != 0 {
		t.Fatalf("report = %+v, want 1 discovered", rep)
	}
	found := sink.All()
	if len(found) != 1 {
		t.Fatalf("recorded %d certs, want 1", len(found))
	}
	if found[0].Address != addr {
		t.Errorf("address = %q, want %q", found[0].Address, addr)
	}
	if want := crypto.SHA256Hex(srv.Certificate().Raw); found[0].Cert.SHA256Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s", found[0].Cert.SHA256Fingerprint, want)
	}
}

// Throughput is bounded: no more than Workers probes run concurrently, however
// many targets there are — so the scan cannot exhaust the host.
func TestScanBoundsConcurrency(t *testing.T) {
	const workers = 4
	var current, peak atomic.Int32
	prober := func(_ context.Context, addr string) (certinfo.Info, error) {
		c := current.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		current.Add(-1)
		return certinfo.Info{SHA256Fingerprint: addr}, nil
	}

	sink := netscan.NewMemorySink()
	s := netscan.New(sink, netscan.WithProber(prober), netscan.WithWorkers(workers), netscan.WithQueue(1000), netscan.WithAllowRFC1918Targets(true))
	defer s.Close()

	rep := s.Scan(context.Background(), targets(60))
	if rep.Discovered != 60 {
		t.Errorf("discovered %d, want 60", rep.Discovered)
	}
	if peak.Load() > workers {
		t.Errorf("peak concurrency %d exceeded the %d-worker bound", peak.Load(), workers)
	}
	if peak.Load() < 2 {
		t.Errorf("expected real concurrency, peak was %d", peak.Load())
	}
}

// Backpressure throttles the producer instead of dropping work: with a single
// worker and no queue, every target is still scanned exactly once.
func TestScanBackpressureLosesNoTargets(t *testing.T) {
	prober := func(_ context.Context, addr string) (certinfo.Info, error) {
		time.Sleep(time.Millisecond)
		return certinfo.Info{SHA256Fingerprint: addr}, nil
	}
	sink := netscan.NewMemorySink()
	s := netscan.New(sink, netscan.WithProber(prober),
		netscan.WithWorkers(1), netscan.WithQueue(0), netscan.WithBackoff(time.Millisecond), netscan.WithAllowRFC1918Targets(true))
	defer s.Close()

	const n = 40
	rep := s.Scan(context.Background(), targets(n))
	if rep.Discovered != n || rep.Rejected != 0 {
		t.Fatalf("report = %+v, want %d discovered, 0 rejected", rep, n)
	}
	if got := len(sink.All()); got != n {
		t.Errorf("recorded %d certs, want %d (backpressure must not drop targets)", got, n)
	}
}

// Probe failures are counted, not fatal: the scan continues and reports them.
func TestScanReportsFailures(t *testing.T) {
	prober := func(_ context.Context, addr string) (certinfo.Info, error) {
		if addr == "10.0.0.1:443" {
			return certinfo.Info{}, errors.New("connection refused")
		}
		return certinfo.Info{SHA256Fingerprint: addr}, nil
	}
	s := netscan.New(netscan.NewMemorySink(), netscan.WithProber(prober), netscan.WithAllowRFC1918Targets(true))
	defer s.Close()

	rep := s.Scan(context.Background(), []string{"10.0.0.0:443", "10.0.0.1:443", "10.0.0.2:443"})
	if rep.Discovered != 2 || rep.Failed != 1 {
		t.Errorf("report = %+v, want 2 discovered / 1 failed", rep)
	}
}

func TestScanBlocksReservedTargetsAndAudits(t *testing.T) {
	var probed []string
	var blocked []netscan.BlockedTarget
	prober := func(_ context.Context, addr string) (certinfo.Info, error) {
		probed = append(probed, addr)
		return certinfo.Info{SHA256Fingerprint: addr}, nil
	}
	s := netscan.New(netscan.NewMemorySink(),
		netscan.WithProber(prober),
		netscan.WithBlockedTargetHook(func(_ context.Context, target netscan.BlockedTarget) {
			blocked = append(blocked, target)
		}),
	)
	defer s.Close()

	rep := s.Scan(context.Background(), []string{
		"127.0.0.1:443",
		"169.254.169.254:443",
		"10.0.0.0:443",
		"93.184.216.34:443",
	})
	if rep.Blocked != 3 || rep.Discovered != 1 || rep.Failed != 0 {
		t.Fatalf("report = %+v, want 3 blocked / 1 discovered / 0 failed", rep)
	}
	if len(blocked) != 3 {
		t.Fatalf("blocked audit hooks = %d, want 3", len(blocked))
	}
	for _, addr := range []string{"127.0.0.1:443", "169.254.169.254:443", "10.0.0.0:443"} {
		if !containsBlocked(blocked, addr) {
			t.Errorf("missing blocked audit for %s: %+v", addr, blocked)
		}
		if contains(probed, addr) {
			t.Errorf("reserved target %s reached the prober", addr)
		}
	}
	if !contains(probed, "93.184.216.34:443") {
		t.Fatalf("public target was not probed: %v", probed)
	}
}

// The pool is bounded by configuration, observable via Stats.
func TestScannerPoolIsBounded(t *testing.T) {
	s := netscan.New(netscan.NewMemorySink(), netscan.WithWorkers(8), netscan.WithQueue(32))
	defer s.Close()
	st := s.Stats()
	if st.Workers != 8 || st.Capacity != 32 {
		t.Errorf("pool stats = %+v, want 8 workers / 32 capacity", st)
	}
}

// ExpandRange enumerates CIDR x ports and guards against oversized ranges.
func TestExpandRange(t *testing.T) {
	got, err := netscan.ExpandRange("10.0.0.0/30", []int{443, 8443})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 { // 4 addresses x 2 ports
		t.Fatalf("got %d targets, want 8: %v", len(got), got)
	}
	if !contains(got, "10.0.0.1:443") || !contains(got, "10.0.0.2:8443") {
		t.Errorf("missing expected targets: %v", got)
	}

	if _, err := netscan.ExpandRange("10.0.0.0/8", []int{443}); err == nil {
		t.Error("an oversized range must be rejected")
	}
	if _, err := netscan.ExpandRange("10.0.0.0/30", nil); err == nil {
		t.Error("an empty port list must be rejected")
	}
	if _, err := netscan.ExpandRange("not-a-cidr", []int{443}); err == nil {
		t.Error("a malformed CIDR must be rejected")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsBlocked(xs []netscan.BlockedTarget, x string) bool {
	for _, v := range xs {
		if v.Address == x {
			return true
		}
	}
	return false
}
