// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A147 on the assembled control plane: an anchor timestamped by the served TSA
// over the tenant's full audit chain is accepted by the production event log
// (which refuses any payload without a registered privacy policy), projected
// into the anchoring status, and carried by a signed export that verifies
// offline with the anchor re-checked and an hourly cadence held.
func TestServedContinuousAnchorVerifiesOfflineFromAnExport(t *testing.T) {
	dir := t.TempDir()
	auditKey, err := jose.GenerateRSASigningKey("served-anchor-audit")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{
		TSA:         config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		TSACertFile: filepath.Join(dir, "tsa.crt"),
	}, func(d *Deps) {
		d.AuditSigningKey = auditKey
		// The licensed factory's export anchor, inline: core tests cannot link ee/.
		d.AuditComplianceFactory = func(deps editionseam.AuditComplianceDeps) editionseam.AuditComplianceRuntime {
			return editionseam.AuditComplianceRuntime{Anchor: func(ctx context.Context, head string) (auditanchor.Anchor, error) {
				return auditanchor.AnchorHead(ctx, deps.Timestamper, head)
			}}
		}
	})
	ctx := context.Background()
	if h.srv.audit == nil || h.srv.protocols == nil || h.srv.protocols.tsa == nil {
		t.Fatal("the served harness has no audit service or TSA")
	}
	if _, err := h.log.Append(ctx, events.Event{Type: "test.audit.recorded", TenantID: servedTestTenant, Data: []byte(`{}`)}); err == nil {
		t.Fatal("the served log accepted a payload with no privacy policy; this test needs the production log")
	}

	writer := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"owners:write", "owners:read"})
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", writer, "served-anchor-owner",
		map[string]any{"kind": "team", "name": "Platform", "email": "platform@example.test"}); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("seed owner = %d: %s", code, body)
	}
	position, chainErr := h.srv.audit.ChainHead(ctx, servedTestTenant)
	if chainErr != nil || position.Sequence == 0 {
		t.Fatalf("chain head = %+v, %v", position, chainErr)
	}
	anchor, err := auditanchor.AnchorHead(ctx, auditTimestamper{srv: h.srv}, position.Head)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(auditanchor.AnchoredEvent{ThroughSequence: position.Sequence, CadenceSeconds: 3600, Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(ctx, events.Event{
		ID: "served-anchor-1", Type: auditanchor.EventTypeAnchored, TenantID: servedTestTenant,
		SchemaVersion: auditanchor.AnchoredEventSchemaVersion, Data: data,
	}); err != nil {
		t.Fatalf("the production event log refused the anchor: %v", err)
	}
	if err := projections.New(h.store).Project(ctx, h.log); err != nil {
		t.Fatal(err)
	}

	token := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"audit:read"})
	get := func(path string) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, body)
		}
		return body
	}
	var status api.AuditAnchoringStatus
	if err := json.Unmarshal(get("/api/v1/audit/anchors"), &status); err != nil {
		t.Fatal(err)
	}
	if status.AnchorCount != 1 || len(status.Anchors) != 1 || status.Anchors[0].ThroughSequence != position.Sequence ||
		status.Anchors[0].ChainHead != position.Head {
		t.Fatalf("anchoring status = %+v", status)
	}

	keys, err := jose.ParseJWKSet(get("/api/v1/audit/verification-keys"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(h.caPEM)
	if block == nil {
		t.Fatal("served CA PEM")
	}
	exported := get("/api/v1/audit/export?format=jws")
	result, err := auditanchor.VerifyArtifact(exported, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: keys, TSARootDER: block.Bytes,
		Series: auditanchor.SeriesPolicy{Cadence: time.Hour},
	})
	if err != nil {
		t.Fatalf("offline verification of the served export: %v", err)
	}
	if !result.AnchorVerified || result.AnchorSeries == nil || result.AnchorSeries.Anchors != 1 || result.AnchorSeries.Verified != 1 {
		t.Fatalf("receipt = %+v series %+v", result, result.AnchorSeries)
	}
}
