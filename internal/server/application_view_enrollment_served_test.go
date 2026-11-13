// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A244-L4 Done-when (served): an identity's Application view names the
// enrollment path that issued its certificate, apart from the protocols its
// profile permits. Bound to a profile permitting acme and api, the identity is
// issued through the control plane: the view reads the permitted methods acme
// and api, and an enrollment of api for both its first certificate and the
// active one, and the certificate row records the path.
func TestServedApplicationViewNamesTheEnrollmentMethodA244L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "profiles:read", "profiles:write")
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", tok, "a244l4-profile", map[string]any{
		"name": "a244l4-acme-api", "spec": map[string]any{"allowed_protocols": []string{"acme", "api"}},
	}); status != http.StatusCreated {
		t.Fatalf("create the profile: HTTP %d %s", status, raw)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", tok, "a244l4-owner", map[string]any{"kind": "workload", "name": "a244l4-owner"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &owner) != nil {
		t.Fatalf("create the owner: HTTP %d %s", status, raw)
	}
	attrs, _ := json.Marshal(map[string]string{"profile_name": "a244l4-acme-api"})
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate,
		Name: "a244l4-orders.example.test", OwnerID: owner.ID, Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	type view struct {
		Profile struct {
			EnrollmentMethods []string `json:"enrollment_methods"`
		} `json:"profile"`
		Certificate struct {
			ID string `json:"id"`
		} `json:"certificate"`
		Enrollment *struct {
			FirstMethod        string `json:"first_method"`
			FirstCertificateID string `json:"first_certificate_id"`
			CurrentMethod      string `json:"current_method"`
		} `json:"enrollment"`
	}
	read := func(stage string) view {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+ident.ID+"/application", tok, nil)
		var v view
		if status != http.StatusOK || json.Unmarshal(raw, &v) != nil {
			t.Fatalf("%s: application view HTTP %d %s", stage, status, raw)
		}
		return v
	}
	transition := func(key, to string) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, key,
			map[string]any{"to": to, "reason": "A244-L4 enrollment method"}); status != http.StatusOK {
			t.Fatalf("%s: HTTP %d %s", to, status, raw)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}

	transition("a244l4-issue", "issued")
	first := read("after issuance")
	if len(first.Profile.EnrollmentMethods) != 2 || first.Enrollment == nil || first.Certificate.ID == "" {
		t.Fatalf("after issuance the view reads profile %v, enrollment %+v, certificate %q", first.Profile.EnrollmentMethods, first.Enrollment, first.Certificate.ID)
	}
	if e := first.Enrollment; e.FirstMethod != "api" || e.CurrentMethod != "api" || e.FirstCertificateID != first.Certificate.ID {
		t.Fatalf("after issuance the enrollment reads %+v, want api for the first and active certificate %s", e, first.Certificate.ID)
	}
	cert, err := h.store.GetCertificate(ctx, h.tenant, first.Certificate.ID)
	if err != nil || cert.EnrollmentProtocol != "api" {
		t.Fatalf("the certificate row records enrollment path %q (%v), want api", cert.EnrollmentProtocol, err)
	}

	t.Logf("A244L4_ENROLLMENT_OK certificate=%s", first.Certificate.ID)
}
