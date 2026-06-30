package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// TestServedSelfServiceIssuancePortalCAPISS11 proves CAP-ISS-11 on the served
// control-plane path: a requester submits a profile-bound certificate request, the
// requester cannot self-issue, a distinct approver records approval, and the RA
// completes issuance through the real signer-backed outbox path.
func TestServedSelfServiceIssuancePortalCAPISS11(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})

	admin := seedScopedTokenSubject(t, h.store, h.tenant, "profile-admin", string(authz.OwnersWrite), string(authz.ProfilesWrite))
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "dev@example.test",
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite), string(authz.CertsRequest))
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "ra@example.test",
		string(authz.IdentitiesWrite), string(authz.CertsIssue), string(authz.CertsRead))
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "security@example.test", string(authz.CertsIssue))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", admin, "cap-iss-11-owner", map[string]any{
		"kind": "workload",
		"name": "payments",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode owner: %v body=%s", err, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", admin, "cap-iss-11-profile", map[string]any{
		"name": "self-service-web",
		"spec": map[string]any{
			"subject":         map[string]any{"common_name": "payments-api.example.test"},
			"max_ttl_seconds": 3600,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create profile: status %d body %s", status, body)
	}
	var profile struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
		Active  bool   `json:"active"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatalf("decode profile: %v body=%s", err, body)
	}
	if profile.Name != "self-service-web" || profile.Version != 1 || !profile.Active {
		t.Fatalf("profile response = %+v, want active v1 self-service-web", profile)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", requester, "cap-iss-11-request", map[string]any{
		"kind":     "x509_certificate",
		"name":     "payments-api.example.test",
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"requester":       "dev@example.test",
			"profile_name":    profile.Name,
			"profile_version": profile.Version,
			"purpose":         "staging TLS",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create self-service identity request: status %d body %s", status, body)
	}
	var identity struct {
		ID         string          `json:"id"`
		Status     string          `json:"status"`
		Attributes json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(body, &identity); err != nil || identity.ID == "" {
		t.Fatalf("decode requested identity: %v body=%s", err, body)
	}
	if identity.Status != "requested" {
		t.Fatalf("identity status = %q, want requested", identity.Status)
	}
	var attrs struct {
		Requester      string `json:"requester"`
		ProfileName    string `json:"profile_name"`
		ProfileVersion int    `json:"profile_version"`
		Purpose        string `json:"purpose"`
	}
	if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
		t.Fatalf("decode identity attrs: %v body=%s", err, identity.Attributes)
	}
	if attrs.Requester != "dev@example.test" || attrs.ProfileName != profile.Name || attrs.ProfileVersion != 1 || attrs.Purpose != "staging TLS" {
		t.Fatalf("identity attrs = %+v, want requester/profile/purpose binding", attrs)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("list requester identities: status %d body %s", status, body)
	}
	var listed struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode identity list: %v body=%s", err, body)
	}
	var sawRequest bool
	for _, item := range listed.Items {
		if item.ID == identity.ID && item.Status == "requested" {
			sawRequest = true
			break
		}
	}
	if !sawRequest {
		t.Fatalf("requester portal list did not include requested identity %s: %+v", identity.ID, listed.Items)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", requester, "cap-iss-11-requester-self-issue", map[string]string{
		"to":     "issued",
		"reason": "requester tried to bypass approval",
	})
	if status != http.StatusForbidden {
		t.Fatalf("requester self-issue status = %d body %s, want 403", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", issuer, "cap-iss-11-issue-before-approval", map[string]string{
		"to":     "issued",
		"reason": "RA issue before approval",
	})
	if status != http.StatusForbidden {
		t.Fatalf("issue before profile approval status = %d body %s, want 403", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/approvals", issuer, "cap-iss-11-ra-self-approval", map[string]string{
		"action": "issue",
	})
	if status == http.StatusOK {
		t.Fatalf("RA self-approval unexpectedly succeeded: body=%s", body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/approvals", approver, "cap-iss-11-distinct-approval", map[string]string{
		"action": "issue",
	})
	if status != http.StatusOK {
		t.Fatalf("distinct approval status = %d body %s, want 200", status, body)
	}
	var approval struct {
		Resource  string `json:"resource"`
		Action    string `json:"action"`
		Approver  string `json:"approver"`
		Approvals int    `json:"approvals"`
	}
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatalf("decode approval: %v body=%s", err, body)
	}
	if approval.Resource != identity.ID || approval.Action != "issue" || approval.Approver != "security@example.test" || approval.Approvals != 1 {
		t.Fatalf("approval response = %+v", approval)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", issuer, "cap-iss-11-issued", map[string]string{
		"to":     "issued",
		"reason": "CAP-ISS-11 approved self-service request",
	})
	if status != http.StatusOK {
		t.Fatalf("issue after approval status = %d body %s, want 200", status, body)
	}
	var issued struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issued identity: %v body=%s", err, body)
	}
	if issued.Status != "issued" {
		t.Fatalf("issued response status = %q, want issued", issued.Status)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain self-service issuance outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", issuer, nil)
	if status != http.StatusOK {
		t.Fatalf("list issued certificates: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			OwnerID            string `json:"owner_id"`
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v body=%s", err, body)
	}
	var sawIssuedCert bool
	for _, cert := range certs.Items {
		if cert.OwnerID == owner.ID && cert.Source == "issued" && cert.Fingerprint != "" {
			sawIssuedCert = true
			break
		}
	}
	if !sawIssuedCert {
		t.Fatalf("certificate inventory missing self-service issued leaf: %+v", certs.Items)
	}
	for _, eventType := range []string{"profile.created", "identity.created", "identity.issued", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for served self-service issuance", eventType)
		}
	}
}
