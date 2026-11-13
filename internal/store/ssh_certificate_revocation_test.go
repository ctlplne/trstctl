// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A245-L1 Done-when (store, part 2): an ssh.cert.revoked projection keeps one
// row per revocation event — a replay changes nothing — and the operations
// ledger reads it as an SSH certificate revocation named by its serial, or by
// "a key ID" without the ID, with its reason and who revoked it; each row reads
// back by its event id, and another tenant's revocations stay out.
func TestSSHCertificateRevocationsReadModelFeedsTheLedgerA245L1(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID, otherTenant = "a2451000-0000-4000-8b01-000000000000", "a2451000-0000-4000-8b02-000000000000"
	seedTenant(t, s, tenantID)
	seedTenant(t, s, otherTenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	apply := func(tenant, eventID string, serial uint64, byKeyID bool, reason, by string, revokedAt time.Time, seq uint64) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplySSHCertificateRevokedTx(ctx, tx, tenant, eventID, serial, byKeyID, reason, by, revokedAt, seq)
		}); err != nil {
			t.Fatalf("apply %s: %v", eventID, err)
		}
	}
	apply(tenantID, "evtA245L1serial", 245001, false, "the build host was retired", "ops@example.test", at, 10)
	apply(tenantID, "evtA245L1serial", 245001, false, "replayed", "replay", at.Add(time.Minute), 10)
	apply(tenantID, "evtA245L1both", 245002, true, "", "", at.Add(time.Second), 11)
	apply(tenantID, "evtA245L1keyid", 0, true, "laptop lost", "ops@example.test", at.Add(2*time.Second), 12)
	apply(otherTenant, "evtA245L1other", 245003, false, "", "", at, 13)

	rows, err := s.ListOperationLedgerRows(ctx, tenantID, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		if r.Source != "ssh_certificate_revocation" {
			continue
		}
		if r.SubjectKind != "ssh_certificate" || r.Status != "revoked" {
			t.Fatalf("row %s reads %+v", r.ID, r)
		}
		got[r.ID] = r.SubjectName + "|" + r.Detail + "|" + r.Origin
	}
	want := map[string]string{
		"evtA245L1serial": "serial 245001|the build host was retired|revoked by ops@example.test",
		"evtA245L1both":   "serial 245002 and a key ID||revoked by the system",
		"evtA245L1keyid":  "a key ID|laptop lost|revoked by ops@example.test",
	}
	if len(got) != len(want) {
		t.Fatalf("ledger rows = %v; want %v", got, want)
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("row %s = %q; want %q", id, got[id], w)
		}
	}
	one, err := s.GetOperationLedgerRow(ctx, tenantID, "ssh_certificate_revocation", "evtA245L1keyid")
	if err != nil || one.SubjectName != "a key ID" || !one.CreatedAt.Equal(at.Add(2*time.Second)) {
		t.Fatalf("read back by event id = %+v, %v", one, err)
	}
	if _, err := s.GetOperationLedgerRow(ctx, tenantID, "ssh_certificate_revocation", "evtA245L1other"); err == nil {
		t.Fatal("another tenant's revocation read back")
	}
	var stored int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM ssh_certificate_revocations WHERE tenant_id = $1`, tenantID).Scan(&stored); err != nil || stored != 3 {
		t.Fatalf("stored rows = %d, %v; a replayed event must not add one", stored, err)
	}
}
