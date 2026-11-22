// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// CR-101: the owner and the owner's active bundle run are not independent
// reviewers. The fixture records review decisions on inert requests.
func TestServedApprovalRequiresAReviewerIndependentOfTheBundleRun(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.EnablePolicyGate = true
	})
	ctx := t.Context()
	x := a251Harness{t: t, h: h}
	const owner = "review-owner"
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "bundle-admin", "access:read", "access:write", "certs:read", "certs:issue")
	ownerToken := seedScopedTokenSubject(t, h.store, h.tenant, owner, "access:bundle.run", "certs:issue")
	reviewerToken := seedScopedTokenSubject(t, h.store, h.tenant, "independent-reviewer", "certs:issue")
	bundle := x.bundle(admin, "review-bundle", "review-fixture", "certs:read", "certs:issue")
	x.grant(admin, "review-grant", bundle, "machine", owner)
	run := x.run(ownerToken, "review-run", map[string]any{"bundle_ids": []string{bundle}, "ttl_seconds": 600})
	if code := x.status(http.MethodGet, "/api/v1/certificates", run.Token); code != http.StatusOK {
		t.Fatalf("active bundle run could not read its permitted surface: %d", code)
	}

	for _, tc := range []struct {
		name, resource, requester, token, reason string
	}{
		{"owner reviews run", "code-signing/run-fixture", orchestrator.BundleRunSubjectPrefix + owner, ownerToken, "own request"},
		{"run reviews owner", "code-signing/owner-fixture", owner, run.Token, "minted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := h.srv.orch.EnsureOperationApprovalRequest(ctx, h.tenant, orchestrator.OperationApprovalIntent{
				ResourceKind: "code_signing", ResourceID: tc.resource, Action: "sign",
				Requester: tc.requester, FromState: "requested", ToState: "signed",
				TargetVersion: 1, RequiredApprovals: 1, TTL: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/approval-requests/" + request.ID + "/approvals"
			command := map[string]any{"intent_digest": request.IntentDigest}
			status, body := secretsReq(t, h, http.MethodPost, path, tc.token, command)
			if status != http.StatusForbidden || !bytes.Contains(body, []byte(tc.reason)) {
				t.Errorf("same-principal review = %d %s, want a 403 explaining %q", status, body, tc.reason)
			}
			got, err := h.store.GetOperationApproval(ctx, h.tenant, request.ID)
			if err != nil || got.ApprovalCount != 0 || got.Status != store.ApprovalStatusPending {
				t.Fatalf("same-principal review changed the request: %+v, err=%v", got, err)
			}
			status, body = secretsReq(t, h, http.MethodPost, path, reviewerToken, command)
			if status != http.StatusOK {
				t.Fatalf("independent reviewer was refused: %d %s", status, body)
			}
			got, err = h.store.GetOperationApproval(ctx, h.tenant, request.ID)
			if err != nil || got.ApprovalCount != 1 || got.Status != store.ApprovalStatusApproved {
				t.Fatalf("independent reviewer did not reach quorum: %+v, err=%v", got, err)
			}
		})
	}
}

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

	delegated := seedHistoricalDelegatedToken(t, h.srv.orch, h.tenant, "people-admin", "custodian-b", approverScopes)
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
