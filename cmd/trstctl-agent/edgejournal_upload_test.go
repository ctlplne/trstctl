// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

type recordingJournalSender struct {
	mu    sync.Mutex
	calls [][]string
	fail  error
}

func (s *recordingJournalSender) ReportEdgeJournal(_ context.Context, req *transport.EdgeJournalRequest) (*transport.EdgeJournalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	s.calls = append(s.calls, append([]string(nil), req.CertificatesPEM...))
	return &transport.EdgeJournalResponse{Reconciled: len(req.CertificatesPEM)}, nil
}

func (s *recordingJournalSender) sent() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.calls...)
}

func writeTestJournal(t *testing.T, path string, entries ...string) {
	t.Helper()
	raw, err := json.Marshal(edgeJournal{Host: "edge-host", CertificatesPEM: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testJournalEntry(i int) string {
	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\nentry-%d\n-----END CERTIFICATE-----\n", i)
}

// A219: the upload sends only what the control plane has not acknowledged,
// in parts of at most 500, and a journal rewritten under the same path is sent
// again from the start.
func TestEdgeJournalUploadSendsOnlyUnacknowledgedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge-journal.json")
	sender := &recordingJournalSender{}
	if resp, err := uploadEdgeJournal(context.Background(), sender, path); err != nil || len(sender.sent()) != 0 || resp.Reconciled != 0 {
		t.Fatalf("no journal yet = %+v, %v, %d calls", resp, err, len(sender.sent()))
	}
	entries := make([]string, 0, 502)
	for i := 0; i < 501; i++ {
		entries = append(entries, testJournalEntry(i))
	}
	writeTestJournal(t, path, entries...)
	if resp, err := uploadEdgeJournal(context.Background(), sender, path); err != nil || resp.Reconciled != 501 {
		t.Fatalf("first upload = %+v, %v", resp, err)
	}
	if calls := sender.sent(); len(calls) != 2 || len(calls[0]) != 500 || len(calls[1]) != 1 {
		t.Fatalf("parts = %d; want 500 then 1", len(calls))
	}
	if _, err := uploadEdgeJournal(context.Background(), sender, path); err != nil || len(sender.sent()) != 2 {
		t.Fatalf("an acknowledged journal was sent again: %d calls, %v", len(sender.sent()), err)
	}
	entries = append(entries, testJournalEntry(501))
	writeTestJournal(t, path, entries...)
	if _, err := uploadEdgeJournal(context.Background(), sender, path); err != nil {
		t.Fatal(err)
	}
	if calls := sender.sent(); len(calls) != 3 || len(calls[2]) != 1 || calls[2][0] != testJournalEntry(501) {
		t.Fatalf("after one new entry the upload sent %v", calls[len(calls)-1])
	}
	writeTestJournal(t, path, testJournalEntry(900), testJournalEntry(901))
	if _, err := uploadEdgeJournal(context.Background(), sender, path); err != nil {
		t.Fatal(err)
	}
	if calls := sender.sent(); len(calls) != 4 || len(calls[3]) != 2 {
		t.Fatalf("a rewritten journal was not sent from the start: %v", calls[len(calls)-1])
	}
	writeTestJournal(t, path, testJournalEntry(900), testJournalEntry(901), strings.Repeat("x", transport.EdgeJournalMaxCertificateBytes+1))
	if resp, err := uploadEdgeJournal(context.Background(), sender, path); err != nil || resp.Rejected != 1 || len(sender.sent()) != 4 {
		t.Fatalf("an oversize entry = %+v, %v, %d calls; want it counted and not sent", resp, err, len(sender.sent()))
	}
}

// A failed upload is retried after the next heartbeat even without a
// reconnect; with nothing new and nothing pending, a heartbeat sends nothing.
func TestEdgeJournalUploaderRetriesAFailedUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge-journal.json")
	writeTestJournal(t, path, testJournalEntry(1))
	sender := &recordingJournalSender{fail: status.Error(codes.Unavailable, "control plane busy")}
	u := &edgeJournalUploader{path: path}
	u.afterHeartbeat(context.Background(), sender, true)
	if !u.pending || len(sender.sent()) != 0 {
		t.Fatalf("pending = %v after a failed upload", u.pending)
	}
	sender.mu.Lock()
	sender.fail = nil
	sender.mu.Unlock()
	u.afterHeartbeat(context.Background(), sender, false)
	if u.pending || len(sender.sent()) != 1 {
		t.Fatalf("the failed upload was not retried: pending=%v calls=%d", u.pending, len(sender.sent()))
	}
	u.afterHeartbeat(context.Background(), sender, false)
	if len(sender.sent()) != 1 {
		t.Fatal("an unchanged journal was sent again")
	}
	var nilUploader *edgeJournalUploader
	nilUploader.afterHeartbeat(context.Background(), sender, true)
	(&edgeJournalUploader{}).afterHeartbeat(context.Background(), sender, true)
	if len(sender.sent()) != 1 {
		t.Fatal("an agent without --edge-journal-upload sent a journal")
	}
}

// offlineEdgeChannel answers its first heartbeats with Unavailable (the host
// is offline), then accepts heartbeats and edge journals.
type offlineEdgeChannel struct {
	blockedJobChannel
	mu        sync.Mutex
	offline   int
	beats     int
	journals  chan []string
	firstBeat chan struct{}
}

func (s *offlineEdgeChannel) Heartbeat(context.Context, *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beats++
	if s.beats <= s.offline {
		return nil, status.Error(codes.Unavailable, "the control plane is unreachable")
	}
	if s.beats == s.offline+1 {
		close(s.firstBeat)
	}
	return &transport.HeartbeatResponse{TenantID: "tenant-a", NextHeartbeatSeconds: 1}, nil
}

func (s *offlineEdgeChannel) ReportEdgeJournal(_ context.Context, req *transport.EdgeJournalRequest) (*transport.EdgeJournalResponse, error) {
	s.journals <- append([]string(nil), req.CertificatesPEM...)
	return &transport.EdgeJournalResponse{Reconciled: len(req.CertificatesPEM)}, nil
}

func (*offlineEdgeChannel) ClaimJobs(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
	return &transport.ClaimJobsResponse{NextPollSeconds: 60}, nil
}

// The assembled agent loop over a real pinned mTLS channel: the host issues
// while the control plane is unreachable; when a heartbeat succeeds again, the
// agent sends the journal without an operator; a leaf issued while connected
// goes on the next heartbeat, alone.
func TestAgentSendsTheEdgeJournalWhenItReconnects(t *testing.T) {
	ca, err := mtls.NewCA("edge-journal-ca")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := mtls.GenerateAgentKey("edge-host")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "tenant-a", []string{mtls.AgentRoleHost}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, certPath, caPath := filepath.Join(dir, "agent.key"), filepath.Join(dir, "agent.crt"), filepath.Join(dir, "ca.pem")
	if err := identity.Save(keyPath, certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca.BundlePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(dir, "edge-journal.json")
	writeTestJournal(t, journalPath, testJournalEntry(1), testJournalEntry(2))
	creds, err := ca.ServerCredentials([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := &offlineEdgeChannel{offline: 2, journals: make(chan []string, 4), firstBeat: make(chan struct{})}
	server := transport.NewServer(creds, svc)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, agentOptions{caBundle: caPath, keyPath: keyPath, certPath: certPath,
			commonName: "edge-host", serverName: "agent.trstctl.local", serverAddr: listener.Addr().String(),
			enrollURL: "https://127.0.0.1:1", rotateEvery: time.Hour, edgeJournalUpload: journalPath})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	select {
	case got := <-svc.journals:
		t.Fatalf("the agent sent %v while the control plane was unreachable", got)
	case <-svc.firstBeat:
	case <-time.After(15 * time.Second):
		t.Fatal("the agent never reconnected")
	}
	select {
	case got := <-svc.journals:
		if len(got) != 2 || got[0] != testJournalEntry(1) || got[1] != testJournalEntry(2) {
			t.Fatalf("journal on reconnect = %v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not send its journal when it reconnected")
	}
	writeTestJournal(t, journalPath, testJournalEntry(1), testJournalEntry(2), testJournalEntry(3))
	select {
	case got := <-svc.journals:
		if len(got) != 1 || got[0] != testJournalEntry(3) {
			t.Fatalf("journal after a new issuance = %v; want only the new entry", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a leaf issued while connected was not sent")
	}
}
