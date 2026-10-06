// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestCRLDistributionsEncodeNoShardsAsEmptyArray(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 28, 18, 0, 0, 0, time.UTC)
	distributions := crlDistributionsFromArtifacts("tenant-a", []store.CRL{{
		TenantID:   "tenant-a",
		CAID:       "ca-a",
		Kind:       store.CRLKindFull,
		Number:     7,
		ShardCount: 1,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}}, nil)

	if len(distributions) != 1 {
		t.Fatalf("distribution count = %d, want 1", len(distributions))
	}
	if distributions[0].Shards == nil {
		t.Fatal("shards = nil, want an empty array matching the OpenAPI contract")
	}
	payload, err := json.Marshal(crlDistributionListResponse{Items: distributions})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(payload), `"shards":null`) {
		t.Fatalf("response contains nullable shards: %s", payload)
	}
}

func TestCRLDistributionsUseExactManagedAuthorityRoutes(t *testing.T) {
	t.Parallel()
	tenantID, caID := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	now := time.Date(2026, time.October, 6, 0, 0, 0, 0, time.UTC)
	distributions := crlDistributionsFromArtifacts(tenantID, []store.CRL{
		{TenantID: tenantID, CAID: caID, Kind: store.CRLKindFull, Number: 4, ShardCount: 2, ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour)},
		{TenantID: tenantID, CAID: caID, Kind: store.CRLKindShard, ShardIndex: 1},
		{TenantID: tenantID, CAID: caID, Kind: store.CRLKindDelta, DeltaBaseNumber: func() *int64 { n := int64(4); return &n }()},
	}, map[string]bool{caID: true})
	if len(distributions) != 1 {
		t.Fatalf("managed CA distributions = %d, want one", len(distributions))
	}
	base := "/crl/" + tenantID + "/authorities/" + caID
	if distributions[0].FullURL != base || len(distributions[0].Shards) != 1 ||
		distributions[0].Shards[0].URL != base+"/shards/1" || distributions[0].DeltaURL != base+"/delta/4" {
		t.Fatalf("managed CA CRL URLs point to another issuer: %+v", distributions[0])
	}
}
