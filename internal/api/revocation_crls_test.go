// SPDX-License-Identifier: MPL-2.0

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
	}})

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
