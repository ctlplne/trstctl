// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// Q1-L1: a review's revoke decision on a certificate or an identity acts.
// The certificate is revoked by the trstctl CA that issued it and the
// identity moves to revoked through its lifecycle, both as the reviewer and
// through the same gate an operator's request meets; each item closes once
// its credential reads revoked. A reviewer the certificate's gate refuses
// (no certs:issue) revokes nothing: the item is left to an operator, saying
// why.
func TestServedAccessReviewRevokesCertificatesAndIdentitiesQ1L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	issuer := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l1-lead", "access:read", "access:write")
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "review-alice", "access:read", "access:write", "certs:issue", "identities:write")
	carol := seedScopedTokenSubject(t, h.store, h.tenant, "review-carol", "access:read", "access:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", issuer, map[string]any{"kind": "workload", "name": "q1l1-owner"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil {
		t.Fatalf("create owner: %d %s", status, body)
	}
	issue := func(name string) (identityID, certificateID, serial string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", issuer, map[string]any{
			"kind": "x509_certificate", "name": name, "owner_id": owner.ID,
		})
		var ident struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
			t.Fatalf("create identity %s: %d %s", name, status, body)
		}
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", issuer,
			map[string]any{"to": "issued", "reason": "Q1-L1 fixture"}); status != http.StatusOK {
			t.Fatalf("issue %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		certs, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, name)
		if err != nil || len(certs) != 1 {
			t.Fatalf("issued certificates for %s = %d, %v", name, len(certs), err)
		}
		return ident.ID, certs[0].ID, certs[0].Serial
	}
	_, reviewedCert, reviewedSerial := issue("cert-reviewed.q1l1.example.test")
	reviewedIdentity, _, _ := issue("identity-reviewed.q1l1.example.test")
	_, refusedCert, _ := issue("refused.q1l1.example.test")

	campaign := func(key, reviewer string, items []map[string]any) q1Campaign {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, key, map[string]any{
			"name": "Q1-L1 " + key, "reviewer_subject": reviewer, "items": items,
		})
		var c q1Campaign
		if status != http.StatusCreated || json.Unmarshal(raw, &c) != nil || len(c.Items) != len(items) {
			t.Fatalf("start campaign %s: HTTP %d %s", key, status, raw)
		}
		return c
	}
	const certItem, identityItem, refusedItem = "7b1f9a52-1d43-4c8e-9b31-5b7e0c1a0001", "7b1f9a52-1d43-4c8e-9b31-5b7e0c1a0002", "7b1f9a52-1d43-4c8e-9b31-5b7e0c1a0003"
	acting := campaign("q1l1-alice", "review-alice", []map[string]any{
		{"item_id": certItem, "nhi_id": "cert:" + reviewedCert, "nhi_kind": "x509_certificate", "resource": "payments edge", "entitlement": "serves TLS"},
		{"item_id": identityItem, "nhi_id": "id:" + reviewedIdentity, "nhi_kind": "x509_certificate", "resource": "payments edge", "entitlement": "serves TLS"},
	})
	refusing := campaign("q1l1-carol", "review-carol", []map[string]any{
		{"item_id": refusedItem, "nhi_id": "cert:" + refusedCert, "nhi_kind": "x509_certificate", "resource": "payments edge", "entitlement": "serves TLS"},
	})
	decide := func(token, campaignID, itemID, key string) q1Item {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+itemID+"/decision", token, key,
			map[string]any{"decision": "revoked", "reason": "the edge moved to the new gateway"})
		return q1ItemFrom(t, status, raw, itemID)
	}

	certDecision := decide(alice, acting.ID, certItem, "q1l1-cert")
	if certDecision.RevocationStatus != "requested" || !strings.Contains(certDecision.RevocationDetail, "revoked (cessationOfOperation) by the trstctl CA") {
		t.Fatalf("certificate revoke decision = %+v", certDecision)
	}
	identityDecision := decide(alice, acting.ID, identityItem, "q1l1-identity")
	if identityDecision.RevocationStatus != "requested" || !strings.Contains(identityDecision.RevocationDetail, "identity revoked through its lifecycle") {
		t.Fatalf("identity revoke decision = %+v", identityDecision)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var cert struct {
		Status           string     `json:"status"`
		RevokedAt        *time.Time `json:"revoked_at"`
		RevocationReason string     `json:"revocation_reason"`
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+reviewedCert, issuer, nil)
	if status != http.StatusOK || json.Unmarshal(body, &cert) != nil || cert.RevokedAt == nil {
		t.Fatalf("the reviewed certificate after the decision: %d %s; want it revoked", status, body)
	}
	var ident struct {
		Status string `json:"status"`
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+reviewedIdentity, issuer, nil)
	if status != http.StatusOK || json.Unmarshal(body, &ident) != nil || ident.Status != "revoked" {
		t.Fatalf("the reviewed identity after the decision: %d %s; want revoked", status, body)
	}

	// The reviewer without certs:issue revokes nothing.
	refused := decide(carol, refusing.ID, refusedItem, "q1l1-refused")
	if refused.RevocationStatus != "manual" || !strings.Contains(refused.RevocationDetail, "certs:issue") {
		t.Fatalf("a reviewer the gate refuses = %+v; want manual naming certs:issue", refused)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+refusedCert, issuer, nil)
	var stillValid struct {
		RevokedAt *time.Time `json:"revoked_at"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &stillValid) != nil || stillValid.RevokedAt != nil {
		t.Fatalf("the refused reviewer's certificate: %d %s; want it not revoked", status, body)
	}

	// The reconcile closes the acted items on the evidence and leaves the
	// refused one open.
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
	if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC().Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	closedCert := q1GetItem(t, h, alice, acting.ID, certItem)
	if closedCert.ClosedAs != "revoked" || closedCert.ClosedAt == nil || !strings.Contains(closedCert.ClosingEvidence, "certificate "+reviewedSerial+" revoked") {
		t.Fatalf("certificate item after the reconcile = %+v", closedCert)
	}
	closedIdentity := q1GetItem(t, h, alice, acting.ID, identityItem)
	if closedIdentity.ClosedAs != "revoked" || closedIdentity.ClosedAt == nil || !strings.Contains(closedIdentity.ClosingEvidence, "identity identity-reviewed.q1l1.example.test revoked") {
		t.Fatalf("identity item after the reconcile = %+v", closedIdentity)
	}
	if open := q1GetItem(t, h, carol, refusing.ID, refusedItem); open.ClosedAt != nil || open.RevocationStatus != "manual" {
		t.Fatalf("the refused item after the reconcile = %+v; want it open and manual", open)
	}
}
