// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package intwire

import (
	"bytes"
	"testing"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/verify"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	tenantRelying      = "66666666-6666-6666-6666-666666666666"
	tenantRelyingOther = "77777777-7777-7777-7777-777777777777"
)

// TestAGID_Wire_RelyingPartyPinsIssuingCAAndReadsStatus_RealInfra is what a
// relying service relies on, against the real signer process: the tenant's
// published issuing CA verifies the tenant's real X.509 credentials (and another
// tenant's CA does not), it keeps verifying credentials issued after a signer
// restart, and the credential status turns from active to revoked once a
// revocation's cascade reaches the credential.
func TestAGID_Wire_RelyingPartyPinsIssuingCAAndReadsStatus_RealInfra(t *testing.T) {
	h := newHarness(t, tenantRelying)
	pinned, err := h.api.IssuingCA(h.ctx, h.tenant)
	if err != nil {
		t.Fatalf("IssuingCA: %v", err)
	}
	direct, err := h.client.AgentIssuingCA(h.ctx, h.tenant)
	if err != nil {
		t.Fatalf("AgentIssuingCA: %v", err)
	}
	spki, err := crypto.CertificateSubjectPublicKeyInfo(direct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pinned.CertificateDER, direct) || pinned.SPKISHA256 != crypto.SHA256Hex(spki) || pinned.TenantID != h.tenant {
		t.Fatalf("published issuing CA differs from the signer's: %+v", pinned)
	}

	issued := h.issueAgent(t, "agent-relying", "nonce-relying")
	der := issued.credential.CredentialDER
	if err := crypto.VerifyLeafSignedByCA(der, pinned.CertificateDER); err != nil {
		t.Fatalf("the pinned issuing CA does not verify the tenant's credential: %v", err)
	}
	other, err := h.client.AgentIssuingCA(h.ctx, tenantRelyingOther)
	if err != nil {
		t.Fatalf("AgentIssuingCA other tenant: %v", err)
	}
	if crypto.VerifyLeafSignedByCA(der, other) == nil {
		t.Fatal("another tenant's issuing CA verifies this tenant's credential")
	}
	policy := verify.NewLocalPolicy().
		ApproveAgentStack(delegation.AgentStackDigestOf(issued.reprBytes)).
		PermitClass("agent-worker").
		GrantOperations("agent-worker", "read").
		WithToolManifest("search")
	if _, err := verify.Verify(verify.Credential{Form: verify.FormX509, Bytes: der}, verify.TrustRoot{CACertDER: pinned.CertificateDER},
		policy, verify.Action{Operation: "read", Tool: "search"}, nil); err != nil {
		t.Fatalf("the relying-party verifier refused the real credential under the pinned CA: %v", err)
	}
	if _, err := verify.Verify(verify.Credential{Form: verify.FormX509, Bytes: der}, verify.TrustRoot{CACertDER: other},
		policy, verify.Action{Operation: "read", Tool: "search"}, nil); err == nil {
		t.Fatal("the relying-party verifier honored the credential under another tenant's CA")
	}

	status, err := h.api.CredentialStatus(h.ctx, h.tenant, issued.credentialID)
	if err != nil {
		t.Fatalf("CredentialStatus: %v", err)
	}
	if !status.Found || status.Status != agidapi.CredentialStatusActive || status.CredentialSHA256 != crypto.SHA256Hex(der) || status.RevokedAt != nil {
		t.Fatalf("status of a fresh credential = %+v", status)
	}
	if cross, err := h.api.CredentialStatus(h.ctx, tenantRelyingOther, issued.credentialID); err != nil || cross.Found || cross.Status != agidapi.CredentialStatusUnknown {
		t.Fatalf("another tenant read the credential's status: %+v, %v", cross, err)
	}

	// The CA key survives a signer restart: a credential issued afterwards still
	// verifies against the certificate pinned before it.
	h.restartSigner(t)
	later := h.issueAgent(t, "agent-relying-2", "nonce-relying-2")
	if err := crypto.VerifyLeafSignedByCA(later.credential.CredentialDER, pinned.CertificateDER); err != nil {
		t.Fatalf("a credential issued after a signer restart does not verify against the pinned CA: %v", err)
	}

	// Revoking the delegating principal: queued, the credential is still active;
	// once the cascade ran, it is revoked with the directive and its evidence.
	revoked, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{Subject: "manager", Reason: "compromise", PublishDownstream: true})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if queued, err := h.api.CredentialStatus(h.ctx, h.tenant, issued.credentialID); err != nil || queued.Status != agidapi.CredentialStatusActive {
		t.Fatalf("status before the cascade ran = %+v, %v", queued, err)
	}
	h.drain(t, 20)
	status, err = h.api.CredentialStatus(h.ctx, h.tenant, issued.credentialID)
	if err != nil {
		t.Fatalf("CredentialStatus after revocation: %v", err)
	}
	if status.Status != agidapi.CredentialStatusRevoked || status.DirectiveID != revoked.DirectiveID || status.RevokedAt == nil ||
		!status.RevocationEvidenced || status.RevocationReason != "compromise" {
		t.Fatalf("status after revocation = %+v", status)
	}
}
