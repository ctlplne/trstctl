// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/revcacheposture"
)

func TestSignedRevocationCachePostureIsTenantAgentBoundServedAndReplayableAUD39(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
	entries := aud39CacheEntries()
	report, err := transport.SignedRevocationCachePosture(h.identity.Identity(), h.tenant, h.agent, entries, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		Status: "active", Version: "aud39", RevocationCaches: report,
	}); err != nil {
		t.Fatalf("valid signed cache posture heartbeat: %v", err)
	}
	agentID := agentRowID(h.tenant, h.agent)
	assertProjected := func(stage string) {
		t.Helper()
		row, err := h.store.GetAgent(ctx, h.tenant, agentID)
		if err != nil {
			t.Fatalf("%s: get projected agent: %v", stage, err)
		}
		if len(row.RevocationCaches) != 2 || row.RevocationCaches[0].CacheID != "issuer-a" ||
			row.RevocationCachesReportedAt == nil || row.RevocationCachesStatement == "" ||
			len(row.RevocationCachesSignature) == 0 || row.RevocationCachesSignerFingerprint == "" {
			t.Fatalf("%s: projected revocation cache posture = %+v", stage, row)
		}
	}
	assertProjected("live")

	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	assertAPI := func(stage string) {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/caches", token, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: cache API=%d %s", stage, code, body)
		}
		for _, forbidden := range [][]byte{[]byte(`"signature":`), []byte(`"statement":`), report.Signature, []byte("upstream_url"), []byte("issuer_der")} {
			if bytes.Contains(body, forbidden) {
				t.Fatalf("%s: cache API leaked private/evidence bytes %q: %s", stage, forbidden, body)
			}
		}
		var got struct {
			Observed bool `json:"observed"`
			Summary  struct {
				Caches int `json:"caches"`
				Fresh  int `json:"fresh"`
				Stale  int `json:"stale"`
				Empty  int `json:"empty"`
				Error  int `json:"error"`
			} `json:"summary"`
			Items []struct {
				AgentID           string `json:"agent_id"`
				AgentName         string `json:"agent_name"`
				Segment           string `json:"segment"`
				CacheID           string `json:"cache_id"`
				Protocol          string `json:"protocol"`
				IssuerFingerprint string `json:"issuer_fingerprint"`
				LocalPath         string `json:"local_path"`
				Status            string `json:"status"`
				DetailCode        string `json:"detail_code"`
				ReportedAt        string `json:"reported_at"`
				Fresh             bool   `json:"fresh"`
				SignatureVerified bool   `json:"signature_verified"`
				MetadataOnly      bool   `json:"metadata_only"`
				CachedResponses   int64  `json:"cached_responses"`
				ServedRequests    int64  `json:"served_requests"`
				RefusedRequests   int64  `json:"refused_requests"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("%s: decode cache API: %v (%s)", stage, err, body)
		}
		if !got.Observed || got.Summary.Caches != 2 || got.Summary.Fresh != 1 || got.Summary.Stale != 1 ||
			len(got.Items) != 2 || got.Items[0].AgentID != agentID || got.Items[0].AgentName != h.agent ||
			got.Items[0].Segment != "plant-7" || got.Items[0].CacheID != "issuer-a" ||
			got.Items[0].IssuerFingerprint == "" || !got.Items[0].SignatureVerified || !got.Items[0].MetadataOnly ||
			got.Items[0].ReportedAt == "" {
			t.Fatalf("%s: served cache posture = %+v", stage, got)
		}
	}
	assertAPI("live")

	// Changing a per-cache counter after signing must fail and preserve the last
	// accepted view. Otherwise a valid relay certificate could present an
	// unsigned green status and the signature would be decoration.
	tampered := *report
	tampered.Entries = append([]revcacheposture.Entry(nil), report.Entries...)
	tampered.Entries[0].RefusedRequests++
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RevocationCaches: &tampered}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("tampered cache posture error=%v, want PermissionDenied", err)
	}
	assertProjected("after tamper")

	crossTenant, err := transport.SignedRevocationCachePosture(h.identity.Identity(),
		"22222222-2222-2222-2222-222222222222", h.agent, entries, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RevocationCaches: crossTenant}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant cache posture error=%v, want PermissionDenied", err)
	}

	stale, err := transport.SignedRevocationCachePosture(h.identity.Identity(), h.tenant, h.agent, entries, report.IssuedAtUnix-1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RevocationCaches: stale}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale cache posture error=%v, want FailedPrecondition", err)
	}

	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold rebuild cache posture: %v", err)
	}
	assertProjected("after rebuild")
	assertAPI("after rebuild")

	otherToken := seedScopedToken(t, h.store, "22222222-2222-2222-2222-222222222222", "certs:read")
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/caches", otherToken, nil)
	if code != http.StatusOK || bytes.Contains(body, []byte("plant-7")) || !bytes.Contains(body, []byte(`"observed":false`)) {
		t.Fatalf("cross-tenant cache API=%d %s", code, body)
	}
}

func TestHostAgentCannotReportServingRevocationCachesAUD39(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	report, err := transport.SignedRevocationCachePosture(h.identity.Identity(), h.tenant, h.agent,
		aud39CacheEntries(), time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{Status: "active", RevocationCaches: report})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("host cache posture error=%v, want PermissionDenied", err)
	}
}

func aud39CacheEntries() []revcacheposture.Entry {
	base := int64(1_786_570_000)
	return []revcacheposture.Entry{
		{CacheID: "issuer-a", Segment: "plant-7", Protocol: revcacheposture.ProtocolCRL,
			IssuerFingerprint: "sha256:" + strings.Repeat("a", 64), LocalPath: "/crl/issuer-a",
			Status: revcacheposture.StatusFresh, CachedResponses: 1, Fresh: true, SignatureVerified: true,
			ThisUpdateUnix: base, NextUpdateUnix: base + 3600, LastValidatedAtUnix: base + 10,
			ServedRequests: 8, RefusedRequests: 1},
		{CacheID: "issuer-a", Segment: "plant-7", Protocol: revcacheposture.ProtocolOCSP,
			IssuerFingerprint: "sha256:" + strings.Repeat("a", 64), LocalPath: "/ocsp/issuer-a",
			Status: revcacheposture.StatusStale, DetailCode: "next_update_passed", CachedResponses: 1,
			SignatureVerified: true, ThisUpdateUnix: base - 3600, NextUpdateUnix: base - 1,
			LastValidatedAtUnix: base - 3590, ServedRequests: 3, RefusedRequests: 2},
	}
}
