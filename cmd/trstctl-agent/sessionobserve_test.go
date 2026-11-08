// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/observe"
	"trstctl.com/trstctl/internal/agent/sessionobserve"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

type fakeProbes struct {
	closed atomic.Int32
}

func (f *fakeProbes) RingDrops() uint64 { return 0 }
func (f *fakeProbes) Close() error      { f.closed.Add(1); return nil }

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestSessionObserverNeedsTheRoleAndDetachesWhenItGoesX5: an agent without
// the session-observer role refuses the work and attaches nothing; one with
// it attaches the probes and keeps them until a role check finds the role
// gone — a renewal that dropped it — and then detaches them once and reports
// nothing more; stopping the agent detaches them too.
func TestSessionObserverNeedsTheRoleAndDetachesWhenItGoesX5(t *testing.T) {
	var log syncBuffer
	opened := 0
	open := func(*sessionobserve.Assembler) (sessionObserver, error) { opened++; return &fakeProbes{}, nil }
	report := func(context.Context, []agent.InventoryFinding) error { return nil }
	stop := runSessionObserver(context.Background(), func() []string { return []string{mtls.AgentRoleHost, mtls.AgentRoleObserver} },
		open, report, time.Hour, time.Millisecond, &log)
	stop()
	if opened != 0 || !strings.Contains(log.String(), "needs the session-observer role") {
		t.Fatalf("an agent without the role: opened %d, log %q", opened, log.String())
	}

	var roles atomic.Value
	roles.Store([]string{mtls.AgentRoleHost, mtls.AgentRoleSessionObserver})
	probes := &fakeProbes{}
	stop = runSessionObserver(context.Background(), func() []string { return roles.Load().([]string) },
		func(*sessionobserve.Assembler) (sessionObserver, error) { return probes, nil }, report, time.Hour, time.Millisecond, &log)
	time.Sleep(20 * time.Millisecond)
	if probes.closed.Load() != 0 {
		t.Fatal("the probes were detached while the agent held the role")
	}
	roles.Store([]string{mtls.AgentRoleHost})
	deadline := time.Now().Add(2 * time.Second)
	for probes.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	if probes.closed.Load() != 1 || !strings.Contains(log.String(), "no longer carries the session-observer role; the probes are detached") {
		t.Fatalf("after the role was removed: closed %d times, log %q", probes.closed.Load(), log.String())
	}

	probes = &fakeProbes{}
	stop = runSessionObserver(context.Background(), func() []string { return []string{mtls.AgentRoleSessionObserver} },
		func(*sessionobserve.Assembler) (sessionObserver, error) { return probes, nil }, report, time.Hour, time.Hour, &log)
	stop()
	if probes.closed.Load() != 1 {
		t.Fatalf("stopping the agent closed the probes %d times", probes.closed.Load())
	}

	log = syncBuffer{}
	stop = runSessionObserver(context.Background(), func() []string { return []string{mtls.AgentRoleSessionObserver} },
		func(*sessionobserve.Assembler) (sessionObserver, error) {
			return nil, errors.New("load the probe program (needs CAP_BPF and CAP_PERFMON)")
		}, report, time.Hour, time.Hour, &log)
	stop()
	if !strings.Contains(log.String(), "needs CAP_BPF") {
		t.Fatalf("a probe program the kernel refused: log %q", log.String())
	}
}

// TestSessionFindingsCarryFactsNotData: a session item becomes one tls_session
// finding with the negotiated facts, the peer certificate's facts and
// fingerprint, application_data_read=false and a risk that rewards hybrid
// post-quantum key exchange and flags anything before TLS 1.2.
func TestSessionFindingsCarryFactsNotData(t *testing.T) {
	notAfter := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	items := []sessionobserve.Item{
		{Ref: "tls-session|/usr/bin/curl|client|api.x5.test|TLSv1.3|TLS_AES_256_GCM_SHA384|X25519MLKEM768|ab", Process: "curl",
			Executable: "/usr/bin/curl", Side: "client", Sessions: 3,
			Obs: observe.Observation{Protocol: "tls", TLSVersion: "TLSv1.3", CipherSuite: "TLS_AES_256_GCM_SHA384", Group: "X25519MLKEM768",
				ServerName: "api.x5.test", OfferedGroups: []string{"X25519MLKEM768", "x25519"}},
			Peer: &observe.CertificateFacts{SHA256: "ab", KeyAlgorithm: "ECDSA", PublicKeyBits: 256, NotAfter: notAfter}},
		{Ref: "tls-session|legacy|client|old.x5.test|TLSv1.0|x|y|-", Process: "legacy", Side: "client", Sessions: 1,
			Obs: observe.Observation{Protocol: "tls", TLSVersion: "TLSv1.0"}},
	}
	got := sessionFindings(items, sessionobserve.Stats{RingDrops: 2, Gaps: 1}, 3)
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	f := got[0]
	if f.Kind != "tls_session" || f.Fingerprint != "ab" || f.RiskScore != 10 || f.Provenance != "tls-session-observer:/usr/bin/curl" ||
		f.Metadata["group"] != "X25519MLKEM768" || f.Metadata["application_data_read"] != "false" || f.Metadata["peer_certificate_key_bits"] != "256" ||
		f.Metadata["peer_certificate_not_after"] != "2027-01-02T03:04:05Z" || f.Metadata["sessions"] != "3" || f.Metadata["pq_hybrid"] != "true" ||
		f.Metadata["observer_drops"] != "6" || f.Metadata["offered_groups"] != "X25519MLKEM768,x25519" {
		t.Fatalf("hybrid TLS 1.3 finding %+v", f)
	}
	if g := got[1]; g.RiskScore != 70 || g.Metadata["peer_certificate_visible"] != "false" || g.Provenance != "tls-session-observer:legacy" {
		t.Fatalf("TLS 1.0 finding %+v", g)
	}
}
