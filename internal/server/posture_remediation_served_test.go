// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/policy"
)

// A47: a tenant posture rule that asks for "renew" makes the lifecycle
// scheduler queue a renewal for the deployed identity whose served certificate
// fires it, with the rule in the reason; a second sweep queues nothing more,
// and a rule without a remediation is reported but never acted on.
func TestServedPostureRemediationRenewsTheViolatingIdentity(t *testing.T) {
	const allowAll = "package trstctl.policy\ndefault allow := false\nallow if { true }\n"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.PolicyModule = allowAll
		d.LifecycleRenewBefore = 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read", "policy:read", "policy:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a47-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	newIdentity := func(name string) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"kind": "x509_certificate", "name": name, "owner_id": owner.ID,
			"attributes": map[string]any{"connector": "nginx", "target": "edge-" + name},
		})
		if status != http.StatusCreated {
			t.Fatalf("create identity %s = %d %s", name, status, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &ident)
		transitionBurstIdentity(t, h, tok, ident.ID, "issued", "a47 issue")
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		transitionBurstIdentity(t, h, tok, ident.ID, "deployed", "a47 deploy")
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		return ident.ID
	}
	violating := newIdentity("renew.a47.test")
	reported := newIdentity("report.a47.test")
	identityStatus := func(id string) (string, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("get identity = %d %s", status, body)
		}
		var ident struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &ident)
		return ident.Status, string(body)
	}
	if st, _ := identityStatus(violating); st != "deployed" {
		t.Fatalf("fixture identity status = %q, want deployed", st)
	}

	// Fresh leaves are not due: the sweep queues nothing before a rule asks.
	if queued, err := h.srv.RunLifecycleOnce(t.Context()); err != nil || queued != 0 {
		t.Fatalf("sweep before any posture rule queued %d err=%v", queued, err)
	}

	module := allowAll + `
certificate_posture contains {"rule": "renew-test-leaves", "severity": "high", "reason": "test leaves must be replaced", "remediation": "renew"} if {
	input.action == "certificate_posture"
	endswith(input.certificate.subject, "renew.a47.test")
}
certificate_posture contains {"rule": "report-only", "severity": "low", "reason": "reported, never remediated", "remediation": "revoke-everything"} if {
	input.action == "certificate_posture"
	endswith(input.certificate.subject, "report.a47.test")
}
`
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions", tok, "a47-policy-create", map[string]any{
		"kind": "lifecycle", "description": "posture remediation", "change_ref": "github:security/posture#47",
		"evidence_refs": []string{"pr:posture-47"}, "module": module,
	})
	if status != http.StatusCreated {
		t.Fatalf("create policy version = %d %s", status, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &created)
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions/"+created.ID+"/activate", tok, "a47-policy-activate",
		map[string]any{"reason": "reviewed", "evidence_refs": []string{"pr:posture-47"}})
	if status != http.StatusOK {
		t.Fatalf("activate policy = %d %s", status, raw)
	}

	// The listing carries the remediation each rule asked for; the
	// unrecognized one reads as none.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/revocation/rogue-certificates", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"rule":"renew-test-leaves","severity":"high","reason":"test leaves must be replaced","remediation":"renew"`) {
		t.Fatalf("listing = %d %s; want the renew remediation on the rule", status, body)
	}
	if strings.Contains(string(body), `revoke-everything`) {
		t.Fatalf("an unrecognized remediation must be dropped, not served: %s", body)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil || queued != 1 {
		t.Fatalf("sweep with a renew rule queued %d err=%v, want exactly the violating identity", queued, err)
	}
	if st, body := identityStatus(violating); st != "renewing" {
		t.Fatalf("violating identity = %q %s; want renewing", st, body)
	}
	// The transition records the rule as the renewal's reason.
	var reasons []string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		transitions, err := h.store.ListIdentityTransitions(t.Context(), tx, h.tenant, violating)
		for _, tr := range transitions {
			if tr.ToState == "renewing" {
				reasons = append(reasons, tr.Reason)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !containsString(reasons, "posture:renew-test-leaves") {
		t.Fatalf("renewing transitions %v name no posture rule as the reason", reasons)
	}
	if st, _ := identityStatus(reported); st != "deployed" {
		t.Fatalf("report-only identity = %q, want untouched", st)
	}
	if queued, err := h.srv.RunLifecycleOnce(t.Context()); err != nil || queued != 0 {
		t.Fatalf("second sweep queued %d err=%v, want nothing more while the renewal is in flight", queued, err)
	}
	_ = policy.PostureRemediationRenew
}
