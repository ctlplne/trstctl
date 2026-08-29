// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

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

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", &allowAllSSHAuth{})
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

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", &allowAllSSHAuth{})
	if err != nil {
		t.Fatalf("new SSH protocol: %v", err)
	}
	if err := p.restoreRevocations(ctx, log); err == nil {
		t.Fatal("malformed tenant revocation history was ignored; startup would serve an incomplete KRL")
	}
}
