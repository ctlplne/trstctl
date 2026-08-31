// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestBrokerHistoryValidityBoundariesFiltersAndLegacyGaps(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "History fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		name, status, want string
		before, after      *time.Time
	}{
		{"at-not-before", "active", "valid", &now, &future},
		{"inside-window", "active", "valid", &past, &future},
		{"at-not-after", "active", "expired", &past, &now},
		{"future-window", "active", "not_yet_valid", &future, timePtr(future.Add(time.Hour))},
		{"revoked-expired", "revoked", "revoked", &past, &now},
		{"superseded-expired", "superseded", "superseded", &past, &now},
		{"missing-start", "active", "unknown", nil, &future},
		{"missing-end", "active", "unknown", &past, nil},
		{"inverted-window", "active", "unknown", &future, &past},
		{"empty-window", "active", "unknown", &now, &now},
	}
	wantByID := map[string]string{}
	for i, tc := range cases {
		id := uuid(tenantA, 87000+i)
		wantByID[id] = tc.want
		// Deliberate pre-metadata/erased read-model fixtures. This is not a
		// product write path: it verifies we never infer missing original facts.
		if _, err := s.SystemPool().Exec(ctx, `INSERT INTO certificates
			(id, tenant_id, fingerprint, subject, source, issuance_idempotency_key, status, not_before, not_after, created_at)
			VALUES ($1, $2, $3, $3, 'rediscovered', $4, $5, $6, $7, $8)`,
			id, tenantA, tc.name, "broker-issue:"+tc.name, tc.status, tc.before, tc.after, now); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetBrokerCertificate(ctx, tenantA, id, now)
		if err != nil || got.State != tc.want || got.Issuance != nil {
			t.Fatalf("%s: state=%s metadata=%v err=%v", tc.name, got.State, got.Issuance, err)
		}
		if _, err := s.GetBrokerCertificate(ctx, tenantB, id, now); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("neighbor could read %s: %v", id, err)
		}
	}
	for _, state := range store.BrokerCertificateStates() {
		got, err := s.ListBrokerCertificatesPage(ctx, tenantA, store.BrokerHistoryFilter{AfterID: store.ZeroUUID, Limit: 100, State: state}, now)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, want := range wantByID {
			if want == state {
				count++
			}
		}
		if len(got) != count {
			t.Fatalf("filter %s: got %d want %d", state, len(got), count)
		}
		for _, row := range got {
			if row.State != state || wantByID[row.CertificateID] != state {
				t.Fatalf("display/filter disagree for %s", row.CertificateID)
			}
		}
	}
	for _, query := range []string{"%", "_", "' OR true --"} {
		got, err := s.ListBrokerCertificatesPage(ctx, tenantA, store.BrokerHistoryFilter{AfterID: store.ZeroUUID, Limit: 100, Query: query}, now)
		if err != nil || len(got) != 0 {
			t.Fatalf("search is not literal: %q count=%d err=%v", query, len(got), err)
		}
	}
	got, err := s.ListBrokerCertificatesPage(ctx, tenantA, store.BrokerHistoryFilter{AfterID: store.ZeroUUID, Limit: 100, Method: "rediscovered"}, now)
	if err != nil || len(got) != 0 {
		t.Fatal("guessed an attestation method from a later discovery source")
	}
	for _, limit := range []int{0, 102} {
		if _, err := s.ListBrokerCertificatesPage(ctx, tenantA, store.BrokerHistoryFilter{Limit: limit}, now); err == nil {
			t.Fatal("accepted unbounded history")
		}
	}
}

func TestBrokerHistoryKeysetKeepsTimeTiesAndExcludesOtherInventory(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "History fixture"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 17; i++ {
		key := fmt.Sprintf("broker-issue:history-%d", i)
		if i == 16 {
			key = "ordinary-issuance"
		}
		if _, err := s.SystemPool().Exec(ctx, `INSERT INTO certificates
			(id, tenant_id, fingerprint, subject, source, issuance_idempotency_key, created_at)
			VALUES ($1, $2, $3, 'history', 'broker:untrusted-source-label', $4, $5)`,
			uuid(tenantA, 88000+i), tenantA, fmt.Sprintf("history-%d", i), key, now.Add(time.Duration(i/4)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	f := store.BrokerHistoryFilter{AfterID: store.ZeroUUID, Limit: 3}
	seen := map[string]bool{}
	var previous *store.BrokerCertificate
	for page := 0; page < 10; page++ {
		rows, err := s.ListBrokerCertificatesPage(ctx, tenantA, f, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if seen[row.CertificateID] {
				t.Fatal("duplicate row across cursor pages")
			}
			if row.CertificateID == uuid(tenantA, 88016) {
				t.Fatal("source label alone made an ordinary certificate a broker record")
			}
			if previous != nil && (row.RecordedAt.After(previous.RecordedAt) || (row.RecordedAt.Equal(previous.RecordedAt) && row.CertificateID >= previous.CertificateID)) {
				t.Fatal("history is not newest-first with stable tie ordering")
			}
			seen[row.CertificateID] = true
			previous = &row
		}
		last := rows[len(rows)-1]
		f.AfterID, f.AfterTime = last.CertificateID, &last.RecordedAt
	}
	if len(seen) != 16 {
		t.Fatalf("history lost rows: got %d want 16", len(seen))
	}
	if _, err := s.GetBrokerCertificate(ctx, tenantA, uuid(tenantA, 88016), now); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("detail included a non-broker certificate")
	}
}

func timePtr(value time.Time) *time.Time { return &value }
