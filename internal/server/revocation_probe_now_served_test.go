// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// Replay defect B14-R1: revocation-endpoint health refreshed only on the
// hourly sweep, so an operator who fixed a relay's trust bundle kept reading
// the stale failure for up to an hour. An operator with certs:write now asks
// for a probe: the request is recorded with who made it, and the dispatcher
// queues relay probes for exactly the hourly sweep's targets under the
// request's own bucket. Requests inside the same minute share one probe.
func TestServedOperatorProbesRevocationEndpointsNow(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "probe-now-test", Status: "active"}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Probe Now CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "probe-now.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		CRLDistributionPoints: []string{"https://crl.probe-now.example/ca.crl"},
		OCSPServers:           []string{"https://ocsp.probe-now.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	recordInventoryCertificateAUD38(t, h, caDER, caInfo)
	recordInventoryCertificateAUD38(t, h, leafDER, leafInfo)

	reader := seedScopedTokenSubject(t, h.store, h.tenant, "reader@customer.test", "certs:read")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "ops@customer.test", "certs:read", "certs:write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/health/probe", reader, "probe-reader", map[string]any{}); status != http.StatusForbidden {
		t.Fatalf("probe with certs:read = %d %s, want 403", status, body)
	}
	type probeNow struct {
		Queued bool   `json:"queued"`
		Bucket string `json:"bucket"`
	}
	request := func(key string) probeNow {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/health/probe", operator, key, map[string]any{})
		var out probeNow
		if status != http.StatusAccepted || json.Unmarshal(body, &out) != nil {
			t.Fatalf("probe now = %d %s", status, body)
		}
		return out
	}
	first := request("probe-now-1")
	if !first.Queued || !strings.HasPrefix(first.Bucket, orchestrator.RevocationProbeRequestBucketPrefix) {
		t.Fatalf("first probe request = %+v, want queued under a manual bucket", first)
	}
	if !h.hasEvent(t, orchestrator.EventRevocationProbeRequested) {
		t.Fatal("the probe request left no revocation.probe.requested event")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the probe request: %v", err)
	}
	probes := relayProbeIntents(t, ctx, h)
	if len(probes) != 1 || probes[0].Bucket != first.Bucket || len(probes[0].Targets) != 2 {
		t.Fatalf("probe intents after the request = %+v, want one batch of CRL+OCSP under the request's bucket", probes)
	}
	second := request("probe-now-2")
	if second.Bucket == first.Bucket && second.Queued {
		t.Fatalf("a second request in the same minute queued again: %+v", second)
	}
	if second.Bucket != first.Bucket && !second.Queued {
		t.Fatalf("a request in a new minute did not queue: %+v", second)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the second request: %v", err)
	}
	want := 1
	if second.Bucket != first.Bucket {
		want = 2
	}
	if got := len(relayProbeIntents(t, ctx, h)); got != want {
		t.Fatalf("probe intents after the second request = %d, want %d", got, want)
	}
}

func relayProbeIntents(t *testing.T, ctx context.Context, h *roleHarness) []revocationhealth.Intent {
	t.Helper()
	var intents []revocationhealth.Intent
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id`,
			h.tenant, relay.KindRevocationProbe)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			var intent revocationhealth.Intent
			if err := json.Unmarshal(payload, &intent); err != nil {
				return err
			}
			intents = append(intents, intent)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read relay probe jobs: %v", err)
	}
	return intents
}
