// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestServedIdentityDeploymentEvidencePreservesRestoredAndRevokedLeaf(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(*Deps) {})
	ctx := t.Context()
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "evidence owner"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.store.CreateIdentity(ctx, store.Identity{TenantID: h.tenant, OwnerID: owner.ID, Kind: store.KindX509Certificate, Name: "evidence.example"})
	if err != nil {
		t.Fatal(err)
	}
	readToken := seedScopedToken(t, h.store, h.tenant, "certs:read")
	identityOnly := seedScopedToken(t, h.store, h.tenant, "identities:read")
	path := "/api/v1/identities/" + identity.ID + "/deployment-evidence"
	type response struct {
		IdentityID  string                                `json:"identity_id"`
		ReadAt      time.Time                             `json:"read_at"`
		Receipt     *struct{ Fingerprint, Status string } `json:"receipt"`
		Certificate *struct {
			ID, Fingerprint, Status string
			NotAfter                *time.Time `json:"not_after"`
			IdentityIDs             []string   `json:"identity_ids"`
		} `json:"certificate"`
	}
	read := func() response {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, path, readToken, nil)
		if status != http.StatusOK {
			t.Fatalf("HTTP %d: %s", status, raw)
		}
		var result response
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if result.IdentityID != identity.ID || result.ReadAt.IsZero() {
			t.Fatalf("missing read identity/time: %s", raw)
		}
		return result
	}
	if got := read(); got.Receipt != nil || got.Certificate != nil {
		t.Fatal("invented absent deployment")
	}
	if status, _ := secretsReq(t, h, http.MethodGet, path, identityOnly, nil); status != http.StatusForbidden {
		t.Fatalf("certificate permission bypass: HTTP %d", status)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+store.ZeroUUID+"/deployment-evidence", readToken, nil); status != http.StatusNotFound {
		t.Fatalf("absent identity: HTTP %d", status)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(10 * time.Minute)
	cert, err := h.store.UpsertCertificate(ctx, store.Certificate{TenantID: h.tenant, OwnerID: &owner.ID, Subject: identity.Name, Fingerprint: "exact-restored", Serial: "35", Source: "issued", NotBefore: &now, NotAfter: &expires})
	if err != nil {
		t.Fatal(err)
	}
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.SetCertificateSupersededTx(ctx, tx, h.tenant, cert.Fingerprint, now); err != nil {
			return err
		}
		return h.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{ID: "03500000-0000-4000-8000-000000000101", TenantID: h.tenant, IdentityID: &identity.ID, Destination: "connector.rollback", Connector: "traefik", Target: "test", Fingerprint: cert.Fingerprint, Status: "rolled_back", IdempotencyKey: "restore", CreatedAt: now, UpdatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCertificate := func(wantStatus string) {
		t.Helper()
		got := read()
		if got.Receipt == nil || got.Receipt.Status != "rolled_back" || got.Receipt.Fingerprint != cert.Fingerprint || got.Certificate == nil || got.Certificate.ID != cert.ID || got.Certificate.Status != wantStatus || got.Certificate.NotAfter == nil || !got.Certificate.NotAfter.Equal(expires) || len(got.Certificate.IdentityIDs) != 1 || got.Certificate.IdentityIDs[0] != identity.ID {
			t.Fatalf("lost exact restored %s evidence: %+v", wantStatus, got)
		}
	}
	assertCertificate("superseded")
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.SetCertificateRevokedTx(ctx, tx, h.tenant, cert.Fingerprint, "superseded", now)
	}); err != nil {
		t.Fatal(err)
	}
	assertCertificate("revoked")
	// Retained completion can outlive inventory metadata. Do not fall back to
	// an older certificate and give it the newer receipt's proof.
	later := now.Add(time.Second)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{ID: "03500000-0000-4000-8000-000000000102", TenantID: h.tenant, IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "traefik", Target: "test", Fingerprint: "metadata-unavailable", Status: "verified", IdempotencyKey: "missing-metadata", CreatedAt: later, UpdatedAt: later})
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Receipt == nil || got.Receipt.Fingerprint != "metadata-unavailable" || got.Certificate != nil {
		t.Fatal("missing metadata was replaced by an older leaf")
	}
}
