// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
)

type servedCARevocation struct {
	Authority struct {
		ID               string `json:"id"`
		Status           string `json:"status"`
		Serial           string `json:"serial"`
		SignerHandle     string `json:"signer_handle"`
		RevokedAt        string `json:"revoked_at"`
		RevocationReason string `json:"revocation_reason"`
	} `json:"authority"`
	Reason             string   `json:"reason"`
	RevokedAt          string   `json:"revoked_at"`
	SignerRevoked      bool     `json:"signer_revoked"`
	ParentID           *string  `json:"parent_id"`
	RevokedOnParentCRL bool     `json:"revoked_on_parent_crl"`
	CeremonyID         string   `json:"ceremony_id"`
	FollowUp           []string `json:"follow_up"`
}

func startCARevokeCeremony(t *testing.T, h *servedHarness, token, authorityID, reason, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation": "revoke_ca", "authority_id": authorityID, "reason": reason, "threshold": 1,
	})
	if code != http.StatusCreated {
		t.Fatalf("start revoke_ca ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Status != "pending" {
		t.Fatalf("decode revoke_ca ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

// A128 through the served binary: two custodians approve a revoke_ca ceremony
// bound to one authority and reason; executing it revokes the key in the
// isolated signer (the signer's own readback says so and a signature is
// refused), the authority stops issuing, the event log records it once, a
// replay of the log reproduces it, and the authority's certificate is revoked
// on its managed parent's published CRL.
func TestServedCAAuthorityRevokeStopsIssuanceAndRevokesItAtItsParent(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-revoke-operator", []string{"issuers:write", "issuers:read", "certs:issue", "identities:write"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-revoke-approver", []string{"issuers:write", "issuers:read", "certs:issue"})

	rootSpec := map[string]any{
		"common_name": "revoke root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"revoke.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "revoke-root-ceremony")
	approveCACeremony(t, h, approver, rootCeremony.ID, 1, "revoke-root-approval")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "revoke-root-create")
	interSpec := map[string]any{
		"common_name": "revoke issuing intermediate", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"revoke.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, interSpec, 1, "revoke-inter-ceremony")
	approveCACeremony(t, h, approver, interCeremony.ID, 1, "revoke-inter-approval")
	inter := createIntermediateCA(t, h, operator, interCeremony.ID, root.ID, interSpec, "revoke-inter-create")
	before := issueHierarchyLeaf(t, h, operator, inter.ID, "before.revoke.example.test", "revoke-leaf-before")

	code, preview := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", map[string]any{
		"operation": "revoke_ca", "authority_id": inter.ID, "reason": "key_compromise", "threshold": 1,
	})
	if code != http.StatusOK || !strings.Contains(string(preview), `"operation":"revoke_ca"`) ||
		!strings.Contains(string(preview), inter.ID) || strings.Contains(string(preview), inter.SignerHandle) {
		t.Fatalf("revoke_ca preview = %d body=%s", code, preview)
	}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "revoke-bad-reason", map[string]any{
		"operation": "revoke_ca", "authority_id": inter.ID, "reason": "because", "threshold": 1,
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("revoke_ca with a free-text reason = %d body=%s; want 422", code, raw)
	}
	ceremony := startCARevokeCeremony(t, h, operator, inter.ID, "key_compromise", "revoke-inter-revoke-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "revoke-inter-revoke-approval")

	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/revoke", operator, "revoke-wrong-reason", map[string]any{
		"ceremony_id": ceremony.ID, "reason": "superseded",
	}); code != http.StatusConflict {
		t.Fatalf("revoke with a reason the ceremony did not approve = %d body=%s; want 409", code, raw)
	}
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/revoke", operator, "revoke-inter", map[string]any{
		"ceremony_id": ceremony.ID, "reason": "key_compromise",
	})
	if code != http.StatusOK {
		t.Fatalf("revoke intermediate = %d body=%s; want 200", code, raw)
	}
	var revoked servedCARevocation
	if err := json.Unmarshal(raw, &revoked); err != nil {
		t.Fatalf("decode revocation: %v body=%s", err, raw)
	}
	if revoked.Authority.Status != "revoked" || revoked.Authority.RevocationReason != "key_compromise" || revoked.Authority.RevokedAt == "" ||
		!revoked.SignerRevoked || !revoked.RevokedOnParentCRL || revoked.ParentID == nil || *revoked.ParentID != root.ID ||
		revoked.CeremonyID != ceremony.ID || len(revoked.FollowUp) == 0 {
		t.Fatalf("revocation result = %+v", revoked)
	}
	if code, again := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/revoke", operator, "revoke-inter", map[string]any{
		"ceremony_id": ceremony.ID, "reason": "key_compromise",
	}); code != http.StatusOK || string(again) != string(raw) {
		t.Fatalf("idempotent replay = %d body=%s; want the original response", code, again)
	}

	// The signer's own answer, not the control plane's record.
	client := h.signer.Client()
	if isRevoked, err := client.KeyRevoked(ctx, revoked.Authority.SignerHandle); err != nil || !isRevoked {
		t.Fatalf("signer reports the revoked authority's key revoked = %v, %v", isRevoked, err)
	}
	remote, err := client.SignerForHandleWithPurpose(ctx, revoked.Authority.SignerHandle, signing.PurposeCASign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.SignDigest(make([]byte, 32), crypto.SignOptions{Hash: crypto.SHA256}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("signature with the revoked key = %v, want FailedPrecondition", err)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/issue", operator, "revoke-leaf-after", map[string]any{
		"csr_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: hierarchyLeafCSR(t, "after.revoke.example.test")})),
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	}); code != http.StatusConflict {
		t.Fatalf("issue from a revoked authority = %d body=%s; want 409", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "revoke-again-ceremony", map[string]any{
		"operation": "revoke_ca", "authority_id": inter.ID, "reason": "superseded", "threshold": 1,
	}); code != http.StatusConflict {
		t.Fatalf("a second revocation ceremony for a revoked authority = %d body=%s; want 409", code, body)
	}
	if n := servedEventCount(t, h, projections.EventCAAuthorityRevoked); n != 1 {
		t.Fatalf("ca.authority.revoked events = %d, want 1", n)
	}
	// A leaf under the revoked authority cannot be revoked on that authority's
	// CRL, which its key no longer signs: the request fails for that leaf
	// instead of queueing a publication that can never succeed.
	beforeInfo, err := certinfo.Inspect(caCertDER(t, []byte(before.CertificatePEM)))
	if err != nil {
		t.Fatal(err)
	}
	beforeCert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, beforeInfo.SHA256Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	outboxBefore := exactRevocationOutboxCount(t, h)
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", operator, "revoke-leaf-under-revoked-ca", map[string]any{
		"certificate_ids": []string{beforeCert.ID}, "reason": "keyCompromise",
	}); code != http.StatusOK || !strings.Contains(string(body), `"total_failed":1`) {
		t.Fatalf("revoking a leaf of a revoked authority = %d body=%s; want one failed item", code, body)
	}
	if after := exactRevocationOutboxCount(t, h); after != outboxBefore {
		t.Fatalf("revocation publications %d → %d; a revoked authority's CRL was queued", outboxBefore, after)
	}

	// The parent's published CRL now lists the intermediate's certificate.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("publish the parent's CRL from the durable outbox: %v", err)
	}
	response, err := http.Get(h.ts.URL + "/crl/" + h.tenant + "/authorities/" + root.ID)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("parent CRL = HTTP %d read %v", response.StatusCode, readErr)
	}
	crl, err := crypto.ParseCRL(crlDER, caCertDER(t, []byte(root.CertificatePEM)))
	if err != nil || !protoContains(crl.RevokedSerials, revoked.Authority.Serial) {
		t.Fatalf("parent CRL %+v omits the revoked intermediate serial %s: %v", crl.RevokedSerials, revoked.Authority.Serial, err)
	}

	// The periodic CRL refresh skips the revoked authority, whose key signs
	// nothing, and keeps refreshing its parent.
	refreshed, err := h.store.ManagedCAAuthoritiesWithIssuedCerts(ctx, h.tenant)
	if err != nil || !protoContains(refreshed, root.ID) || protoContains(refreshed, inter.ID) {
		t.Fatalf("CRL refresh set = %v, %v; want the parent and not the revoked authority", refreshed, err)
	}

	// The read model is a projection of the log: replaying it restores the
	// revocation after the row is reset.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ca_authorities SET status = 'active', revoked_at = NULL, revocation_reason = NULL WHERE tenant_id = $1 AND id = $2`, h.tenant, inter.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Project(ctx, h.log); err != nil {
		t.Fatalf("replay the log: %v", err)
	}
	replayed, err := h.store.GetCAAuthority(ctx, h.tenant, inter.ID)
	if err != nil || replayed.Status != "revoked" || replayed.RevocationReason != "key_compromise" || replayed.RevokedAt == nil {
		t.Fatalf("replayed authority = %+v, %v; want revoked again", replayed, err)
	}
}
