// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestCR016AgentNameAdmissionPreservesOffboardTombstone(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const agentID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "agent binding fixture"}); err != nil {
		t.Fatal(err)
	}
	available, err := s.AgentNameAvailableForEnrollment(ctx, tenantA, agentID)
	if err != nil || !available {
		t.Fatalf("new name available=%v err=%v, want true", available, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agents (id, tenant_id, name, status)
			VALUES ($1,$2,'retired-agent','offboarded')`, agentID, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	available, err = s.AgentNameAvailableForEnrollment(ctx, tenantA, agentID)
	if err != nil || available {
		t.Fatalf("offboarded name available=%v err=%v, want false until a distinct replacement name is chosen", available, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyAgentCertificateBindingTx(ctx, tx, store.AgentCertificateBinding{
			TenantID: tenantA, AgentID: agentID, Serial: "a1", Fingerprint: "original",
			NotAfter: time.Now().Add(time.Hour), EventSeq: 1,
		})
	}); err != nil {
		t.Fatal(err)
	}
	bound, matches, err := s.AgentCertificateMatches(ctx, tenantA, agentID, "clone", "clone")
	if err != nil || !bound || matches {
		t.Fatalf("same-name clone binding: bound=%v matches=%v err=%v", bound, matches, err)
	}
	bound, matches, err = s.AgentCertificateMatches(ctx, tenantB, agentID, "a1", "original")
	if err != nil || bound || matches {
		t.Fatalf("neighbor tenant binding: bound=%v matches=%v err=%v", bound, matches, err)
	}
}
