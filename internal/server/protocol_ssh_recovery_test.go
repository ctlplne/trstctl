// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestSSHProtocolRestoresTenantRevocationsFromEventLog is the regression guard
// for a live g78 failure: the product API appended ssh.cert.revoked, but a fresh
// control-plane process started with an empty in-memory KRL. Hosts downloading
// /ssh/krl after that restart could therefore accept a certificate trstctl had
// already revoked.
func TestSSHProtocolRestoresTenantRevocationsFromEventLog(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{
		Mode:     config.NATSEmbedded,
		StoreDir: filepath.Join(t.TempDir(), "nats"),
	})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":42,"reason":"compromised"}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"key_id":"retired-host","reason":"replaced"}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-b", Data: []byte(`{"serial":99}`)},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatalf("append %s event: %v", event.TenantID, err)
		}
	}

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatalf("new SSH protocol: %v", err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatalf("restore SSH revocations: %v", err)
	}
	if got := p.KRLVersion(); got != 2 {
		t.Fatalf("restored KRL version = %d, want two tenant-local revocation events", got)
	}
	if got := p.RevokedCount(); got != 2 {
		t.Fatalf("restored revoked count = %d, want serial plus key ID", got)
	}
	snapshot := p.krl.Distribute()
	if !slices.Contains(snapshot.Serials, uint64(42)) || slices.Contains(snapshot.Serials, uint64(99)) {
		t.Fatalf("restored serials = %v, want tenant-a serial only", snapshot.Serials)
	}
	if !slices.Contains(snapshot.KeyIDs, "retired-host") {
		t.Fatalf("restored key IDs = %v, want retired-host", snapshot.KeyIDs)
	}
}

// A public KRL poll advances a finite tail without returning a partial trust
// artifact. Restart must reconstruct the final artifact from immutable source
// history, including a poll that stopped midway through catch-up.
func TestSSHProtocolBoundsRequestCatchUpAndRestoresAfterRestart(t *testing.T) {
	ctx := context.Background()
	storeDir := filepath.Join(t.TempDir(), "nats")
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatal(err)
	}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatal(err)
	}
	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":42}`)},
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"key_id":"retired-host"}`)},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	p.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	if err := p.syncRevocationsWithLimit(ctx, false, 2); !errors.Is(err, errSSHKRLBehind) {
		t.Fatalf("first finite page: %v, want behind", err)
	}
	if p.applied != 2 || !p.syncedFrom.IsZero() {
		t.Fatalf("partial cursor=%d throttle=%s, want 2 and immediate retry", p.applied, p.syncedFrom)
	}
	// Simulate a process loss before the next page: the in-memory cursor is
	// gone, so the replacement must rebuild all three source events.
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.restoreRevocations(ctx, reopened); err != nil {
		t.Fatal(err)
	}
	if restored.KRLVersion() != 2 || restored.RevokedCount() != 2 || restored.applied != 3 {
		t.Fatalf("cold restore cursor=%d version=%d count=%d", restored.applied, restored.KRLVersion(), restored.RevokedCount())
	}
	for _, event := range []events.Event{
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":43}`)},
	} {
		if _, err := reopened.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	restored.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	if err := restored.syncRevocationsWithLimit(ctx, false, 2); !errors.Is(err, errSSHKRLBehind) {
		t.Fatalf("first later page: %v, want behind", err)
	}
	if err := restored.syncRevocationsWithLimit(ctx, false, 2); err != nil {
		t.Fatalf("second later page: %v", err)
	}
	if restored.applied != 6 || restored.KRLVersion() != 3 || restored.RevokedCount() != 3 {
		t.Fatalf("complete cursor=%d version=%d count=%d", restored.applied, restored.KRLVersion(), restored.RevokedCount())
	}
}

// TestSSHProtocolFailsClosedOnMalformedRevocationHistory prevents a damaged
// source-of-truth event from silently producing an incomplete KRL at startup.
func TestSSHProtocolFailsClosedOnMalformedRevocationHistory(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{
		Mode:     config.NATSEmbedded,
		StoreDir: filepath.Join(t.TempDir(), "nats"),
	})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, events.Event{
		Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":`),
	}); err != nil {
		t.Fatalf("append malformed fixture: %v", err)
	}

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatalf("new SSH protocol: %v", err)
	}
	if err := p.restoreRevocations(ctx, log); err == nil {
		t.Fatal("malformed tenant revocation history was ignored; startup would serve an incomplete KRL")
	}
}
