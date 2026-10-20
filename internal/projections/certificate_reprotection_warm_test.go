// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateReprotectionIssuerNameRecoversFromRetainedCutover(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "reprotection recovery"}); err != nil {
		t.Fatal(err)
	}
	predecessor, err := s.InsertCAAuthority(ctx, store.CAAuthority{TenantID: tenantA, CommonName: "Old QA CA", Kind: "intermediate", CertificatePEM: "public-old", Serial: "warm-old"})
	if err != nil {
		t.Fatal(err)
	}
	successor, err := s.InsertCAAuthority(ctx, store.CAAuthority{TenantID: tenantA, CommonName: "New QA CA", Kind: "intermediate", CertificatePEM: "public-new", Serial: "warm-new"})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := "5f4a1a12-ae66-4074-aac4-9dd7295bd8fe"
	identityID := "4f064580-6422-40e2-a1d5-ecf82e4e5a3e"
	if err := s.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenantA, Kind: store.OwnerService, Name: "warm-reprotection"}); err != nil {
		t.Fatal(err)
	}
	attrs := json.RawMessage(fmt.Sprintf(`{"deployment_target_id":"qa-host","issuing_authority_source":"private","issuing_authority_id":%q,"issuing_authority_name":"Old QA CA"}`, successor.ID))
	if err := s.UpsertIdentity(ctx, store.Identity{ID: identityID, TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "warm.qa.invalid", OwnerID: ownerID, Status: "deployed", Attributes: attrs}); err != nil {
		t.Fatal(err)
	}
	cut := store.CertificateReprotectionCutover{
		IdentityID: identityID, TargetID: "qa-host", OldCertificateID: "cb14031a-7b86-483c-b0a9-270329ac7c33",
		NewCertificateID: "d8bc64b7-1c23-451e-9330-205be9adff30", OldFingerprint: "old-qa-fingerprint",
		NewFingerprint: "new-qa-fingerprint", OldAuthorityID: predecessor.ID, NewAuthorityID: successor.ID,
		JobID: "qa-job", ReceiptID: "agent-job:42:1:verified", ReceiptSignerFingerprint: "qa-agent",
		ReceiptSignature: "cWEtc2lnbmF0dXJl",
		ReceiptStatement: fmt.Sprintf("trstctl-agent-job-receipt/v2\ntenant=%s\nagent=qa-host\njob=42\nattempt=1\noutcome=verified\nevidence=qa-probe\ndetail=qa-detail\ncredential_fingerprint=new-qa-fingerprint\nkey_origin=host_agent\nkey_storage=filesystem\nkey_exportable=false\nkey_generated_by=qa-host\nissued_at=1\n", tenantA),
	}
	data, err := json.Marshal(cut)
	if err != nil {
		t.Fatal(err)
	}
	e, err := log.Append(ctx, events.Event{Type: projections.EventCertificateReprotectionCutover, TenantID: tenantA, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	// Model a warm upgrade: the old binary already applied this event and saved
	// the tail checkpoint, but left the human-facing issuer name stale.
	if err := s.AdvanceProjectionCheckpoint(ctx, e.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	identity, err := s.GetIdentity(ctx, tenantA, identityID)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(identity.Attributes, &got); err != nil {
		t.Fatal(err)
	}
	if got["issuing_authority_id"] != successor.ID || got["issuing_authority_name"] != successor.CommonName {
		t.Fatalf("warm cutover identity issuer = %v, want successor ID and name", got)
	}
	if cursor, err := s.CAReprotectionNameRecoveryCursor(ctx); err != nil || cursor != e.Sequence {
		t.Fatalf("recovery cursor = %d, err=%v, want %d", cursor, err, e.Sequence)
	}
	// An old snapshot can preserve the stale name even when its checkpoint
	// covers the cutover. Restore must repair that snapshot before serving it.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identities SET attributes=attributes ||
			jsonb_build_object('issuing_authority_name','Old QA CA')
			WHERE tenant_id=$1 AND id=$2::uuid`, tenantA, identityID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("restore stale snapshot: restored=%t err=%v", restored, err)
	}
	identity, err = s.GetIdentity(ctx, tenantA, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(identity.Attributes, &got); err != nil {
		t.Fatal(err)
	}
	if got["issuing_authority_name"] != successor.CommonName {
		t.Fatalf("snapshot retained stale issuer name: %v", got)
	}
	// If later work moves this identity to another issuer, a repeated warm
	// backfill cannot roll it back to the historical cutover's successor.
	later, err := s.InsertCAAuthority(ctx, store.CAAuthority{TenantID: tenantA, CommonName: "Later QA CA", Kind: "intermediate", CertificatePEM: "public-later", Serial: "warm-later"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identities SET attributes=attributes ||
			jsonb_build_object('issuing_authority_id',$3::text,'issuing_authority_name',$4::text)
			WHERE tenant_id=$1 AND id=$2::uuid`, tenantA, identityID, later.ID, later.CommonName)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint
		SET ca_reprotection_name_checked_through=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	identity, err = s.GetIdentity(ctx, tenantA, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(identity.Attributes, &got); err != nil {
		t.Fatal(err)
	}
	if got["issuing_authority_id"] != later.ID || got["issuing_authority_name"] != later.CommonName {
		t.Fatalf("historical cutover rewound later authority: %v", got)
	}
}
