// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/decoy"
	"trstctl.com/trstctl/internal/agent/transport"
)

// scriptedDecoyWatch reports the accesses a test sends it.
type scriptedDecoyWatch chan decoy.Access

func (scriptedDecoyWatch) Mechanism() string { return "test" }

func (w scriptedDecoyWatch) Run(ctx context.Context, report func(decoy.Access)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case a := <-w:
			report(a)
		}
	}
}

// recordingDecoySender keeps every report and answers from a script.
type recordingDecoySender struct {
	mu      sync.Mutex
	reports []*transport.DecoyReportRequest
	answer  func(n int, req *transport.DecoyReportRequest) error
	sent    chan struct{}
}

func (s *recordingDecoySender) ReportDecoys(_ context.Context, req *transport.DecoyReportRequest) (*transport.DecoyReportResponse, error) {
	s.mu.Lock()
	n := len(s.reports)
	s.reports = append(s.reports, req)
	s.mu.Unlock()
	defer func() { s.sent <- struct{}{} }()
	if s.answer != nil {
		if err := s.answer(n, req); err != nil {
			return nil, err
		}
	}
	return &transport.DecoyReportResponse{Registered: len(req.Decoys), Recorded: len(req.Opens)}, nil
}

func (s *recordingDecoySender) wait(t *testing.T, n int) []*transport.DecoyReportRequest {
	t.Helper()
	for {
		s.mu.Lock()
		got := len(s.reports)
		s.mu.Unlock()
		if got >= n {
			s.mu.Lock()
			defer s.mu.Unlock()
			return append([]*transport.DecoyReportRequest(nil), s.reports...)
		}
		select {
		case <-s.sent:
		case <-time.After(5 * time.Second):
			t.Fatalf("%d decoy reports sent, want %d", got, n)
		}
	}
}

// Q6-O1: the agent registers its decoys before it reports any open; an open a
// retry cannot fix is dropped while later opens are still sent; an opener's
// self-chosen name is made printable, so it cannot get its open refused; and a
// control plane that refuses the agent's decoys stops the loop.
func TestDecoyLoopRegistersThenReportsOpensQ6O1(t *testing.T) {
	dir := t.TempDir()
	planted, err := plantDecoys(filepath.Join(dir, "id_ed25519_backup")+", ", "", filepath.Join(dir, "agent.key"))
	if err != nil || len(planted) != 1 {
		t.Fatalf("plant: %v %v", planted, err)
	}
	if _, err := decoyPaths("relative/key"); err == nil {
		t.Fatal("a relative decoy path was accepted")
	}
	accesses := make(chan decoy.Access, 4)
	watch := scriptedDecoyWatch(accesses)
	sender := &recordingDecoySender{sent: make(chan struct{}, 16), answer: func(n int, req *transport.DecoyReportRequest) error {
		switch n {
		case 0:
			return status.Error(codes.FailedPrecondition, "send an authenticated heartbeat before a decoy report")
		case 2:
			return status.Error(codes.InvalidArgument, "open 0 is malformed")
		}
		return nil
	}}
	var log bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runDecoys(ctx, planted, sender, watch, time.Millisecond, &log) }()
	reports := sender.wait(t, 2)
	for _, r := range reports[:2] {
		if len(r.Decoys) != 1 || r.Decoys[0].Path != planted[0].Path || !strings.HasPrefix(r.Decoys[0].PublicKey, "ssh-ed25519 ") || len(r.Opens) != 0 {
			t.Fatalf("registration = %+v; want the decoy's path and public half, sent again after the refusal", r)
		}
	}
	accesses <- decoy.Access{Path: planted[0].Path, At: time.Now(), PID: 7, Process: "cat", Mechanism: "inotify"}
	sender.wait(t, 3)
	accesses <- decoy.Access{Path: planted[0].Path, At: time.Now(), PID: 8, Process: "evil\x1b[2J\xff" + strings.Repeat("x", 400), Mechanism: "fanotify"}
	reports = sender.wait(t, 4)
	last := reports[3]
	if len(last.Opens) != 1 || last.Opens[0].PID != 8 || last.Opens[0].Mechanism != "fanotify" {
		t.Fatalf("open report after a dropped one = %+v", last)
	}
	if p := last.Opens[0].Process; !strings.HasPrefix(p, "evil?[2J?xx") || len(p) > transport.DecoyProcessMaxBytes {
		t.Fatalf("process name sent as %q; want it printable and at most %d bytes", p, transport.DecoyProcessMaxBytes)
	}
	cancel()
	<-done

	refusing := &recordingDecoySender{sent: make(chan struct{}, 4), answer: func(int, *transport.DecoyReportRequest) error {
		return status.Error(codes.PermissionDenied, "decoy files are planted by host agents")
	}}
	refusedCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		runDecoys(refusedCtx, planted, refusing, watch, time.Millisecond, &log)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the decoy loop kept retrying a refusal no retry changes")
	}
	if !strings.Contains(log.String(), "decoys are not watched for the control plane") {
		t.Fatalf("the refusal was not said: %s", log.String())
	}
}
