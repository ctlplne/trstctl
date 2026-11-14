// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedTrafficGateSeesADecidingFindingPastTheFirst5000X3L4 is X3-L4's
// Done-when (served): the observed-traffic gate read at most 5000 of a
// tenant's observer TLS findings a pass, in ID order, so a tenant with more
// never saw a deciding finding past them. A replaced endpoint awaits wire
// evidence while 5,100 findings at other hosts sort before both its
// predecessor's finding and the new connections presenting its replacement:
// the next pass records the evidence on the endpoint, names that finding, and
// closes the predecessor's finding.
func TestServedTrafficGateSeesADecidingFindingPastTheFirst5000X3L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	const (
		address  = "10.0.44.4:443"
		name     = "x3l4.example.test"
		sourceID = "00000000-0000-4000-8000-0000000034a1"
		runID    = "00000000-0000-4000-8000-0000000034a2"
		filler   = 5100
	)
	predecessor := strings.Repeat("a1", 32)
	replacement := strings.Repeat("b2", 32)
	verify := func(fingerprint string, at time.Time) {
		t.Helper()
		if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
			EndpointID: "x3l4-endpoint", Address: address, Vantage: "local", Reached: true,
			ExpectedFingerprint: fingerprint, ObservedFingerprint: fingerprint, ObservedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	verify(predecessor, time.Now().UTC().Add(-time.Hour))
	verify(replacement, time.Now().UTC().Add(-time.Minute))
	awaiting, err := h.store.EndpointsAwaitingTraffic(ctx, h.tenant)
	if err != nil || len(awaiting) != 1 || awaiting[0].ReplacedAt == nil {
		t.Fatalf("the replaced endpoint does not await traffic: %+v %v", awaiting, err)
	}
	replacedAt := *awaiting[0].ReplacedAt

	now := time.Now().UTC()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: h.tenant, Kind: "network-observer", Name: "x3l4-observer",
			Config: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "running", CreatedAt: now,
		}); err != nil {
			return err
		}
		// Observer findings at other hosts whose IDs sort before any the
		// observer records below: the old pass read only the first 5000.
		_, err := tx.Exec(ctx, `INSERT INTO discovery_findings
			(id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at)
			SELECT ('00000000-0000-4000-8001-' || lpad(i::text, 12, '0'))::uuid, $1, $2, $3, 'tls_handshake',
			       'tls 10.9.' || (i / 250) || '.' || (i % 250) || ':443', 'network-observer:eth1', md5(i::text) || md5(i::text), 40,
			       jsonb_build_object('protocol', 'tls', 'server', '10.9.' || (i / 250) || '.' || (i % 250) || ':443',
			                          'certificate_visible', 'true', 'last_seen', to_char($4::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
			       $4
			  FROM generate_series(1, $5) AS i`, h.tenant, runID, sourceID, now, filler)
		return err
	}); err != nil {
		t.Fatalf("seed the observer's findings: %v", err)
	}
	observe := func(ref, fingerprint string, lastSeen time.Time) string {
		t.Helper()
		meta, err := json.Marshal(map[string]string{"protocol": "tls", "server": address, "server_name": name, "tls_version": "TLSv1.2",
			"group": "x25519", "certificate_visible": "true", "last_seen": lastSeen.UTC().Format(time.RFC3339), "payload_stored": "false"})
		if err != nil {
			t.Fatal(err)
		}
		f, err := h.srv.orch.RecordDiscoveryFinding(ctx, h.tenant, store.DiscoveryFinding{
			RunID: runID, SourceID: sourceID, Kind: "tls_handshake", Ref: ref, Provenance: "network-observer:eth1",
			Fingerprint: fingerprint, RiskScore: 60, Metadata: meta,
		})
		if err != nil {
			t.Fatal(err)
		}
		if f.ID <= "00000000-0000-4000-8001-999999999999" {
			t.Fatalf("finding %s sorts among the other hosts' findings", f.ID)
		}
		return f.ID
	}
	expiring := observe("tls "+address+" TLSv1.2 x25519 "+predecessor[:16], predecessor, replacedAt.Add(-30*time.Minute))
	newConnections := observe("tls "+address+" TLSv1.2 x25519 "+replacement[:16], replacement, replacedAt.Add(30*time.Second))
	var tlsFindings int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND kind = 'tls_handshake'`, h.tenant).Scan(&tlsFindings)
	}); err != nil || tlsFindings != filler+2 {
		t.Fatalf("the tenant holds %d observer findings (%v), want %d", tlsFindings, err, filler+2)
	}

	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	verifications, err := h.store.ListEndpointVerifications(ctx, h.tenant)
	if err != nil || len(verifications) != 1 || verifications[0].EndpointID != "x3l4-endpoint" {
		t.Fatalf("endpoint verifications: %+v %v", verifications, err)
	}
	if v := verifications[0]; v.TrafficObservedAt == nil || v.TrafficFindingID != newConnections {
		t.Fatalf("the pass recorded %+v; want the wire evidence of finding %s, past %d others", v, newConnections, filler)
	}
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiring); err != nil || f.TriageStatus != string(discovery.TriageRemediated) {
		t.Fatalf("the predecessor's finding reads %+v (%v), want remediated", f, err)
	}
	t.Logf("X3L4_OK evidence=%s past %d findings", newConnections, filler)
}
