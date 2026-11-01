// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// P9 (part 3): a signing approval binds the artifact digest, the signer, the
// mechanism, one use and an expiry. A stock tool waiting on a pending approval
// holds its request open — the same request, the same idempotency key — and
// signs once the approver grants it; a denial stops it with the reason. A
// modified artifact, another signer, another mechanism, a used approval, an
// expired approval and another tenant's approval cannot sign.
func TestServedCodeSigningApprovalsBindP9(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signingKey.Destroy)
	ca := newP9CA(t)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer", RequestedEKUs: []string{"codeSigning"}}, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{ca.issue(t, csr, "codeSigning"), ca.rootDER}
	const policy = `package trstctl.policy

default allow := false
default reason := "code-signing tuple is not authorized"

allow if {
	input.action == "code_sign"
	input.actor in {"release-bot", "other-bot"}
	input.subject == "release-key"
}
`
	const tenantB = "7a0e3c55-9b1d-4f6e-8c2a-5d4b3e2f1a09"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate, d.PolicyModule = true, policy
		d.RequireApproval, d.RequiredApprovals = true, 1
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": testOperationDigestSigner{DigestSigner: signingKey}}},
			KeyCertificates: map[string][][]byte{
				codeSigningKeyIdentity(servedTestTenant, "release-key"): chain,
				codeSigningKeyIdentity(tenantB, "release-key"):          chain,
			},
		}
	})
	registerServedTenantID(t, h, tenantB, "P9 second tenant")
	startServedExternalCADispatcher(t, h)
	ctx := context.Background()
	signer := seedServedAPIToken(t, ctx, h.store, h.tenant, "release-bot", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	other := seedServedAPIToken(t, ctx, h.store, h.tenant, "other-bot", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "security-approver", []string{string(authz.CertsIssue)})
	signerB := seedServedAPIToken(t, ctx, h.store, tenantB, "release-bot", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	approverB := seedServedAPIToken(t, ctx, h.store, tenantB, "security-approver", []string{string(authz.CertsIssue)})
	plugin := buildP9NotationPlugin(t)

	signingInput := func(size int) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"release-key"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"targetArtifact":{"digest":"sha256:` + strings.Repeat("cd", 32) + `","size":` + strings.Repeat("9", size) + `}}`))
		return header + "." + payload
	}
	generate := func(token, input, wait string) (int, []byte, []byte) {
		return runP9NotationPlugin(t, plugin, h, token, "generate-signature", map[string]any{
			"contractVersion": "1.0", "keyId": "release-key", "keySpec": "EC-256", "hashAlgorithm": "SHA-256", "payload": []byte(input),
		}, "TRSTCTL_APPROVAL_WAIT="+wait)
	}
	pendingFor := func(tenantID, digestHex string) store.OperationApprovalRequest {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			rows, err := h.store.ListOperationApprovals(ctx, tenantID, store.ApprovalStatusPending, 50)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if slices.Contains(row.EvidenceRefs, "artifact-sha256:"+digestHex) {
					return row
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("no pending approval for artifact %s", digestHex)
		return store.OperationApprovalRequest{}
	}
	decide := func(token string, request store.OperationApprovalRequest, decision string) (int, []byte) {
		body := map[string]string{"intent_digest": request.IntentDigest}
		if decision == "denials" {
			body["reason"] = "not this build"
		}
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/"+decision, token, "p9-"+decision+"-"+request.ID, body)
	}
	type result struct {
		code     int
		out, err []byte
	}

	// The tool waits on its pending approval and signs once it is granted.
	first := signingInput(3)
	firstDigest := crypto.SHA256Hex([]byte(first))
	done := make(chan result, 1)
	go func() {
		code, out, failure := generate(signer, first, "2m")
		done <- result{code, out, failure}
	}()
	request := pendingFor(h.tenant, firstDigest)
	if request.Requester != "release-bot" || !slices.Contains(request.EvidenceRefs, "artifact-type:notation:ECDSA-SHA-256") {
		t.Fatalf("the approval request does not bind the signer and mechanism: %+v", request)
	}
	if status, body := decide(approver, request, "approvals"); status != http.StatusOK {
		t.Fatalf("approve: HTTP %d %s", status, body)
	}
	var signed struct {
		Signature []byte `json:"signature"`
	}
	select {
	case r := <-done:
		if r.code != 0 || json.Unmarshal(r.out, &signed) != nil || len(signed.Signature) != 64 {
			t.Fatalf("the waiting plugin = %d %s %s", r.code, r.out, r.err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the plugin did not finish after the approval")
	}
	jwk, err := crypto.PublicJWK(signingKey.Public(), "release-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyJWT(first+"."+base64.RawURLEncoding.EncodeToString(signed.Signature), crypto.JWKS{Keys: []crypto.JWK{jwk}}); err != nil {
		t.Fatalf("the approved signature does not verify: %v", err)
	}
	if used, err := h.store.GetOperationApproval(ctx, h.tenant, request.ID); err != nil || used.Status != store.ApprovalStatusConsumed {
		t.Fatalf("the approval was not consumed: %+v %v", used, err)
	}

	// One use: the same request again returns the recorded signature and signs
	// nothing new; anything else needs a new approval.
	events := countP9CodeSigningEvents(t, h)
	code, out, failure := generate(signer, first, "0")
	var replay struct {
		Signature []byte `json:"signature"`
	}
	if code != 0 || json.Unmarshal(out, &replay) != nil || !bytes.Equal(replay.Signature, signed.Signature) {
		t.Fatalf("the approved request again = %d %s %s", code, out, failure)
	}
	if countP9CodeSigningEvents(t, h) != events {
		t.Fatal("repeating the approved request signed again")
	}
	modified := signingInput(4)
	if code, _, failure := generate(signer, modified, "0"); code == 0 || !strings.Contains(string(failure), "ACCESS_DENIED") || !strings.Contains(string(failure), "awaits") {
		t.Fatalf("a modified artifact signed on the used approval: %s", failure)
	}
	if fresh := pendingFor(h.tenant, crypto.SHA256Hex([]byte(modified))); fresh.ID == request.ID {
		t.Fatal("the modified artifact reused the consumed approval")
	}
	if code, _, failure := generate(other, first, "0"); code == 0 || !strings.Contains(string(failure), "awaits") {
		t.Fatalf("another signer used release-bot's approval: %s", failure)
	}
	digest := crypto.SHA256Sum([]byte(first))
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", signer, "p9-other-mechanism", map[string]any{
		"key_id": "release-key", "artifact_type": "pkcs11:CKM_ECDSA", "digest": digest,
	}); status != http.StatusForbidden || !bytes.Contains(body, []byte("approval_required:")) {
		t.Fatalf("the same digest under another mechanism signed: HTTP %d %s", status, body)
	}

	// A denial stops the waiting tool with the reason.
	third := signingInput(5)
	go func() {
		code, out, failure := generate(signer, third, "2m")
		done <- result{code, out, failure}
	}()
	denied := pendingFor(h.tenant, crypto.SHA256Hex([]byte(third)))
	if status, body := decide(approver, denied, "denials"); status != http.StatusOK {
		t.Fatalf("deny: HTTP %d %s", status, body)
	}
	select {
	case r := <-done:
		if r.code == 0 || !strings.Contains(string(r.err), "ACCESS_DENIED") || !strings.Contains(string(r.err), "denied") {
			t.Fatalf("a denied approval did not stop the tool: %d %s %s", r.code, r.out, r.err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the plugin kept waiting after a denial")
	}

	// An expired approval cannot be granted or used.
	fourth := signingInput(6)
	if code, _, _ := generate(signer, fourth, "0"); code == 0 {
		t.Fatal("an unapproved artifact signed")
	}
	expiring := pendingFor(h.tenant, crypto.SHA256Hex([]byte(fourth)))
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE operation_approval_requests SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 second' WHERE id = $1`, expiring.ID); err != nil {
		t.Fatal(err)
	}
	if status, body := decide(approver, expiring, "approvals"); status == http.StatusOK {
		t.Fatalf("an expired approval request was approved: %s", body)
	}
	if code, _, failure := generate(signer, fourth, "0"); code == 0 || !strings.Contains(string(failure), "expired") {
		t.Fatalf("an expired approval = %s", failure)
	}

	// Another tenant's approval authorizes nothing here, and its approver cannot
	// reach this tenant's request.
	if status, body := decide(approverB, request, "approvals"); status == http.StatusOK {
		t.Fatalf("tenant B's approver decided tenant A's request: %s", body)
	}
	if code, _, failure := generate(signerB, first, "0"); code == 0 || !strings.Contains(string(failure), "awaits") {
		t.Fatalf("tenant A's approval signed for tenant B: %s", failure)
	}
	pendingFor(tenantB, firstDigest)
}
