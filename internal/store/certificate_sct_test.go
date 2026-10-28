// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A213: a submission keeps its newest SCT, an inclusion result lands only on
// a newer sequence, the pending list holds only verified SCTs not yet proven,
// and tenant B reads none of tenant A's.
func TestCertificateSCTsProjectPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	fingerprint := strings.Repeat("d3", 32)
	submission := "5b0f3f0e-8a52-5c55-9d43-6f1a2b3c4d5e"
	at := time.Date(2026, 10, 28, 6, 0, 0, 0, time.UTC)
	record := func(sequence uint64, status, inclusion string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyCertificateSCTRecordedTx(ctx, tx, store.CertificateSCT{
				TenantID: tenantA, SubmissionID: submission, LeafFingerprint: fingerprint, LogURL: "https://ct.example/log",
				LogID: strings.Repeat("0a", 32), EntryType: "certificate", SCTTimestamp: at, SCTStatus: status,
				LeafHash: strings.Repeat("ee", 32), LogPublicKey: []byte("spki"), InclusionStatus: inclusion,
				RecordedAt: at, EventSequence: sequence,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	include := func(sequence uint64, status string) {
		t.Helper()
		index, size := int64(4), int64(9)
		checked := at.Add(time.Hour)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyCertificateSCTInclusionTx(ctx, tx, store.CertificateSCT{
				TenantID: tenantA, SubmissionID: submission, InclusionStatus: status, LeafIndex: &index, TreeSize: &size,
				RootHash: strings.Repeat("ab", 32), InclusionCheckedAt: &checked, EventSequence: sequence,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(tenant string) []store.CertificateSCT {
		t.Helper()
		rows, err := s.CertificateSCTs(ctx, tenant, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}

	record(3101, store.SCTVerified, store.InclusionPending)
	if got := read(tenantA); len(got) != 1 || got[0].SCTStatus != store.SCTVerified || got[0].InclusionStatus != store.InclusionPending {
		t.Fatalf("recorded SCT = %+v", got)
	}
	pending, err := s.PendingCertificateSCTInclusions(ctx, tenantA, 64)
	if err != nil || len(pending) != 1 || pending[0].SubmissionID != submission {
		t.Fatalf("pending inclusions = %+v (%v)", pending, err)
	}
	tenants, err := s.TenantsWithPendingCTInclusions(ctx)
	if err != nil || !slices.Contains(tenants, tenantA) || slices.Contains(tenants, tenantB) {
		t.Fatalf("tenants with pending inclusions = %v (%v)", tenants, err)
	}

	include(3102, store.InclusionVerified)
	got := read(tenantA)
	if len(got) != 1 || got[0].InclusionStatus != store.InclusionVerified || got[0].TreeSize == nil || *got[0].TreeSize != 9 {
		t.Fatalf("proven inclusion = %+v", got)
	}
	if pending, err := s.PendingCertificateSCTInclusions(ctx, tenantA, 64); err != nil || len(pending) != 0 {
		t.Fatalf("a proven SCT is still pending: %+v (%v)", pending, err)
	}
	include(3102, store.InclusionNotIncluded)
	record(3101, store.SCTInvalid, store.InclusionNotChecked)
	if got := read(tenantA); got[0].InclusionStatus != store.InclusionVerified || got[0].SCTStatus != store.SCTVerified {
		t.Fatalf("a replayed older event changed the SCT: %+v", got)
	}
	if got := read(tenantB); len(got) != 0 {
		t.Fatalf("tenant B read tenant A's SCTs: %+v", got)
	}
}
