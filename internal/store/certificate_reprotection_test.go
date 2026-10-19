// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateReprotectionCutoverIsTenantBoundAndIdempotent(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "reprotection"}); err != nil {
			t.Fatal(err)
		}
	}
	old, err := st.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Fingerprint: "old-reprotection-fingerprint", Status: "active", Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := st.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Fingerprint: "new-reprotection-fingerprint", Status: "active", Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "e416b25d-25bf-4a03-9f0c-bb78ef9b1180"
	ownerID := "149eab5a-026d-41c2-8a08-17b4f603c957"
	if err := st.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenantA, Kind: store.OwnerService, Name: "reprotection-owner"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertIdentity(ctx, store.Identity{ID: identityID, TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "host.qa.invalid", OwnerID: ownerID, Status: "deployed", Attributes: json.RawMessage(`{"deployment_target_id":"target-1","issuing_authority_source":"private","issuing_authority_id":"old-ca"}`)}); err != nil {
		t.Fatal(err)
	}
	cutover := store.CertificateReprotectionCutover{IdentityID: identityID, TargetID: "target-1", OldCertificateID: old.ID,
		OldFingerprint: old.Fingerprint, NewCertificateID: next.ID, NewFingerprint: next.Fingerprint,
		OldAuthorityID: "old-ca", NewAuthorityID: "new-ca", JobID: "job-1", ReceiptID: "agent-job:42:1:verified",
		ReceiptStatement: fmt.Sprintf("trstctl-agent-job-receipt/v2\ntenant=%s\nagent=qa-host\njob=42\nattempt=1\noutcome=verified\nevidence=qa-probe\ndetail=qa-detail\ncredential_fingerprint=%s\nkey_origin=host_agent\nkey_storage=filesystem\nkey_exportable=false\nkey_generated_by=qa-host\nissued_at=1\n", tenantA, next.Fingerprint),
		ReceiptSignature: "cWEtc2lnbmF0dXJl", ReceiptSignerFingerprint: "qa-agent-fingerprint"}
	apply := func(tenant string) error {
		return st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return st.ApplyCertificateReprotectionCutoverTx(ctx, tx, tenant, cutover, time.Now().UTC())
		})
	}
	if err := apply(tenantB); err == nil {
		t.Fatal("foreign tenant cutover admitted")
	}
	if err := apply(tenantA); err != nil {
		t.Fatal(err)
	}
	if err := apply(tenantA); err != nil {
		t.Fatalf("same cutover retry: %v", err)
	}
	oldAfter, err := st.GetCertificate(ctx, tenantA, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	nextAfter, err := st.GetCertificate(ctx, tenantA, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := st.GetIdentity(ctx, tenantA, identityID)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]string
	if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
		t.Fatal(err)
	}
	if oldAfter.Status != "superseded" || nextAfter.ReplacesID == nil || *nextAfter.ReplacesID != old.ID ||
		attrs["issuing_authority_id"] != "new-ca" || attrs["issuing_authority_source"] != "private" {
		t.Fatalf("cutover readback: old=%s next=%v issuer=%v", oldAfter.Status, nextAfter.ReplacesID, attrs)
	}
}
