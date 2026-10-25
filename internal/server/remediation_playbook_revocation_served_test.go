// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The revocation publisher accepts only RFC 5280 reasons, and the revoke and
// rotate playbooks used to hand it the operator's free text, so their
// revocations never reached CRL or OCSP while the identity read revoked. The
// playbooks now revoke with an RFC 5280 revocation_reason and keep the free
// text on the run.
func TestServedPlaybookRevocationsCarryAnRFC5280Reason(t *testing.T) {
	cases := []struct {
		playbook, revocationReason, want string
		status                           int
	}{
		{"identity-revoke", "", "unspecified", http.StatusCreated},
		{"identity-revoke", "privilegeWithdrawn", "privilegeWithdrawn", http.StatusCreated},
		// credential-rotate revokes only after its replacement's signed
		// verification, where TestServedCredentialRotateRevokesOnlyAfterSigned
		// Verification asserts its superseded default; this unbound identity
		// can never be verified, so the run is refused up front.
		{"credential-rotate", "", "", http.StatusConflict},
		{"credential-rotate", "credential exposed", "", http.StatusBadRequest},
		{"identity-revoke", "credential exposed", "", http.StatusBadRequest},
		{"identity-revoke", "removeFromCRL", "", http.StatusBadRequest},
		{"identity-revoke", "keyCompromise", "", http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.playbook+"/"+tc.revocationReason, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{})
			identity := operatorGateIdentity(t, h, tc.playbook)
			token := seedScopedToken(t, h.store, h.tenant, "incidents:write", "incidents:read", "certs:issue")
			body := map[string]any{"target_identity_id": identity.ID, "reason": "credential exposed in a build log"}
			if tc.revocationReason != "" {
				body["revocation_reason"] = tc.revocationReason
			}
			status, resp := secretsReqKey(t, h, http.MethodPost, "/api/v1/remediation/playbooks/"+tc.playbook+"/runs", token, "playbook-reason", body)
			if status != tc.status {
				t.Fatalf("run = HTTP %d %s; want %d", status, resp, tc.status)
			}
			if tc.want == "" {
				return
			}
			var run struct {
				Reason       string   `json:"reason"`
				EvidenceRefs []string `json:"evidence_refs"`
			}
			if err := json.Unmarshal(resp, &run); err != nil || run.Reason != "credential exposed in a build log" {
				t.Fatalf("run lost the operator's reason: %s", resp)
			}
			var payload []byte
			if err := h.store.SystemPool().QueryRow(t.Context(),
				`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'revocation.publish'`, h.tenant).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			var intent struct {
				IdentityID string `json:"identity_id"`
				Reason     string `json:"reason"`
			}
			if err := json.Unmarshal(payload, &intent); err != nil || intent.IdentityID != identity.ID || intent.Reason != tc.want ||
				!crypto.IsValidRevocationReason(intent.Reason) {
				t.Fatalf("revocation intent = %+v (%v); want reason %q the publisher accepts", intent, err, tc.want)
			}
			if !containsString(run.EvidenceRefs, "revocation_reason:"+tc.want) {
				t.Fatalf("run evidence %v does not name the revocation reason", run.EvidenceRefs)
			}
		})
	}
}
