// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

func TestDynamicLeaseMetadataReturnsProviderEvidenceWithoutCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	lease := dynsecret.Lease{
		ID: "lease-exact", TenantID: "tenant-hidden", Provider: "postgres", Role: "reader",
		BackendRef: "provider-private-handle", State: dynsecret.LeaseRevoked,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now, HardExpiresAt: now.Add(time.Hour),
		RevocationStatus: "completed", RevokedAt: &now, RevocationCompletedAt: &now,
	}
	raw, err := json.Marshal(toDynamicLeaseResponse(lease, nil))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"credential", "tenant_id", "backend_ref", "last_error"} {
		if _, ok := fields[forbidden]; ok {
			t.Errorf("metadata leaks %s", forbidden)
		}
	}
	if fields["revocation_status"] != "completed" || fields["revocation_completed_at"] != now.Format(time.RFC3339) || fields["hard_expires_at"] != lease.HardExpiresAt.Format(time.RFC3339) {
		t.Fatalf("provider evidence changed or disappeared: %s", raw)
	}
}

func TestDynamicLeaseMetadataDoesNotInventLegacyRevocationEvidence(t *testing.T) {
	raw, err := json.Marshal(toDynamicLeaseResponse(dynsecret.Lease{ID: "legacy-receipt", State: dynsecret.LeaseRevoked}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"hard_expires_at", "revocation_status", "revoked_at", "revocation_completed_at"} {
		if _, ok := fields[field]; ok {
			t.Errorf("old receipt invented %s: %s", field, raw)
		}
	}
}
