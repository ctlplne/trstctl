// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// F262: a token that one person mints for another subject can do that subject's
// work, but it never counts as that subject's approval. Otherwise one admin can
// mint tokens named after the custodians and pass every two-person control alone.
// A token its own subject minted and a deployment-custody token still approve.
func TestServedDelegatedTokensCannotApprove(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.EnablePolicyGate = true
		d.DefaultProfile = "tls-server"
	})
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"},
		MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "f262-payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	approverScopes := []string{"issuers:read", "issuers:write", "certs:issue", "identities:read"}
	admin := seedServedAPIToken(t, ctx, h.store, h.tenant, "people-admin", append([]string{"access:read", "access:write"}, approverScopes...))
	custody := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-d", approverScopes)
	selfBootstrap := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-c", append([]string{"access:write"}, approverScopes...))
	requester := seedServedAPIToken(t, ctx, h.store, h.tenant, "requester", []string{"identities:write", "identities:read", "certs:request"})
	issuer := seedServedAPIToken(t, ctx, h.store, h.tenant, "issuer", []string{"identities:write", "identities:read", "certs:issue", "certs:request"})

	delegated := createServedToken(t, h.ts, admin, "custodian-b", approverScopes)
	selfMinted := createServedToken(t, h.ts, selfBootstrap, "custodian-c", approverScopes)

	refused := func(what string, code int, body []byte) {
		t.Helper()
		if code != http.StatusForbidden || !bytes.Contains(body, []byte("minted")) {
			t.Errorf("%s with a token minted by someone else = %d body=%s; want 403 explaining the token was minted for its subject by another person", what, code, body)
		}
	}

	// CA key ceremony: the opener needs two distinct custodians.
	spec := map[string]any{"common_name": "f262 root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256"}
	ceremony := createCACeremony(t, h, admin, "create_root", "", spec, 2, "f262-ceremony")
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", delegated, "f262-ceremony-delegated", nil)
	refused("CA ceremony approval", code, body)
	approveCACeremony(t, h, selfMinted, ceremony.ID, 1, "f262-ceremony-self")
	approveCACeremony(t, h, custody, ceremony.ID, 2, "f262-ceremony-custody")
	if code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/ca/ceremonies/"+ceremony.ID, delegated, "", nil); code != http.StatusOK {
		t.Errorf("delegated token reading the ceremony = %d body=%s; want 200 (it still does its subject's work)", code, body)
	}

	// Identity issuance under dual control.
	identityID := createIdentityWithToken(t, h.ts, requester, owner.ID)
	if code, body := transitionIdentityWithToken(t, h.ts, issuer, identityID, "issued", "f262-issue-first"); code != http.StatusForbidden {
		t.Fatalf("issue before approvals = %d body=%s; want 403", code, body)
	}
	approval := approvalForIdentityWithToken(t, h.ts, custody, identityID, "issue")
	code, body = approveIdentityWithToken(t, h.ts, delegated, identityID, "f262-identity-delegated", approval)
	refused("identity approval", code, body)
	if code, body := approveIdentityWithToken(t, h.ts, selfMinted, identityID, "f262-identity-self", approval); code != http.StatusOK {
		t.Fatalf("self-minted approval = %d body=%s; want 200", code, body)
	}
	if code, body := approveIdentityWithToken(t, h.ts, custody, identityID, "f262-identity-custody", approval); code != http.StatusOK {
		t.Fatalf("custody approval = %d body=%s; want 200", code, body)
	}
	if code, body := transitionIdentityWithToken(t, h.ts, issuer, identityID, "issued", "f262-issue-first"); code != http.StatusOK {
		t.Fatalf("issue after two genuine approvals = %d body=%s; want 200", code, body)
	}
}
