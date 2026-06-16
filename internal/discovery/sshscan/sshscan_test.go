package sshscan_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/sshtestserver"
	"trstctl.com/trstctl/internal/discovery/sshscan"
	"trstctl.com/trstctl/internal/sshinv"
)

func targets(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.%d:22", i/256, i%256)
	}
	return out
}

// The scanner discovers a real SSH server's host key (via the default probe) and
// records it.
func TestScanDiscoversHostKey(t *testing.T) {
	srv, err := sshtestserver.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	sink := sshinv.NewMemorySink()
	s := sshscan.New(sink)
	defer s.Close()

	rep := s.Scan(context.Background(), []string{srv.Addr()})
	if rep.Discovered != 1 {
		t.Fatalf("report = %+v, want 1 discovered", rep)
	}
	found := sink.All()
	if len(found) != 1 || found[0].Fingerprint != srv.FingerprintSHA256() {
		t.Fatalf("recorded %+v, want host key %s", found, srv.FingerprintSHA256())
	}
	if found[0].Source != sshinv.SourceHostProbe || found[0].KeyType != "ssh-ed25519" {
		t.Errorf("found = %+v", found[0])
	}
}

// Throughput is bounded: no more than Workers probes run concurrently.
func TestScanBoundsConcurrency(t *testing.T) {
	const workers = 4
	var current, peak atomic.Int32
	prober := func(_ context.Context, addr string) (sshinv.Found, error) {
		c := current.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		current.Add(-1)
		return sshinv.Found{Source: sshinv.SourceHostProbe, Location: addr, Fingerprint: addr}, nil
	}

	s := sshscan.New(sshinv.NewMemorySink(), sshscan.WithProber(prober), sshscan.WithWorkers(workers), sshscan.WithQueue(1000))
	defer s.Close()

	rep := s.Scan(context.Background(), targets(60))
	if rep.Discovered != 60 {
		t.Errorf("discovered %d, want 60", rep.Discovered)
	}
	if peak.Load() > workers {
		t.Errorf("peak concurrency %d exceeded the %d-worker bound", peak.Load(), workers)
	}
}

// Backpressure throttles rather than dropping: 1 worker, 0 queue scans every
// target.
func TestScanBackpressureLosesNoTargets(t *testing.T) {
	prober := func(_ context.Context, addr string) (sshinv.Found, error) {
		time.Sleep(time.Millisecond)
		return sshinv.Found{Source: sshinv.SourceHostProbe, Location: addr, Fingerprint: addr}, nil
	}
	sink := sshinv.NewMemorySink()
	s := sshscan.New(sink, sshscan.WithProber(prober),
		sshscan.WithWorkers(1), sshscan.WithQueue(0), sshscan.WithBackoff(time.Millisecond))
	defer s.Close()

	rep := s.Scan(context.Background(), targets(30))
	if rep.Discovered != 30 || rep.Rejected != 0 || len(sink.All()) != 30 {
		t.Fatalf("report = %+v, recorded %d (want all 30)", rep, len(sink.All()))
	}
}
