// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func issueCR069Identity(t *testing.T, h *servedHarness, tenantID, name string) ([]byte, string) {
	t.Helper()
	token := seedScopedToken(t, h.store, tenantID,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", token, map[string]any{
		"kind": "workload", "name": "owner-" + strings.ReplaceAll(name, ".", "-"), "email": "owner@example.test",
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner in %s = %d %s", tenantID, code, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", token, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": name,
	})
	if code != http.StatusCreated {
		t.Fatalf("create identity in %s = %d %s", tenantID, code, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", token, map[string]any{
		"to": "issued", "reason": "cr069 tenant-bound revocation proof", "subject_csr_pem": string(subjectCSR(t, name)),
	})
	if code != http.StatusOK {
		t.Fatalf("issue in %s = %d %s", tenantID, code, body)
	}
	if err := h.srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	certs, err := h.store.ListCertificatesPage(context.Background(), tenantID, "00000000-0000-0000-0000-000000000000", nil, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range certs {
		info, err := certinfo.Inspect(cert.CertificateDER)
		if err == nil && info.CommonName == name {
			return cert.CertificateDER, cert.ID
		}
	}
	t.Fatalf("no certificate for %s in tenant %s", name, tenantID)
	return nil, ""
}

// CR-069: a platform CA shared by two tenants must give each leaf the tenant's
// own public status routes. The CRL at the leaf's CDP must carry an IDP for that
// URL and list its revocation; the OCSP AIA must answer revoked, not unknown.
func TestPlatformLeafRevocationPointersFollowItsTenantCR069(t *testing.T) {
	const origin = "http://cp.example.test"
	const pointerTenant = servedTestTenant
	const victimTenant = "88888888-8888-4888-8888-888888888888"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LeafProfile = crypto.LeafProfile{
			CRLDistributionPoints: []string{origin + "/crl/" + pointerTenant},
			OCSPServers:           []string{origin + "/ocsp/" + pointerTenant},
		}
	})
	registerServedTenantID(t, h, victimTenant, "CR-069 victim tenant")
	issueCR069Identity(t, h, pointerTenant, "pointer-tenant.example.test")
	victimDER, victimID := issueCR069Identity(t, h, victimTenant, "victim.example.test")
	victim, err := certinfo.Inspect(victimDER)
	if err != nil {
		t.Fatal(err)
	}
	wantCDP, wantOCSP := origin+"/crl/"+victimTenant, origin+"/ocsp/"+victimTenant
	if len(victim.CRLDistributionPoints) != 1 || victim.CRLDistributionPoints[0] != wantCDP ||
		len(victim.OCSPServers) != 1 || victim.OCSPServers[0] != wantOCSP {
		t.Fatalf("victim leaf points to CDP=%v OCSP=%v, want %s / %s", victim.CRLDistributionPoints, victim.OCSPServers, wantCDP, wantOCSP)
	}
	revoker := seedScopedToken(t, h.store, victimTenant, "identities:read", "identities:write", "certs:read", "certs:issue")
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", revoker, "cr069-victim-revoke", map[string]any{
		"certificate_ids": []string{victimID}, "reason": "keyCompromise",
	})
	if code != http.StatusOK {
		t.Fatalf("victim revocation = %d %s", code, body)
	}
	if err := h.srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	crlResp, err := h.ts.Client().Get(h.ts.URL + strings.TrimPrefix(wantCDP, origin))
	if err != nil {
		t.Fatal(err)
	}
	crlDER, readErr := io.ReadAll(crlResp.Body)
	_ = crlResp.Body.Close()
	if readErr != nil || crlResp.StatusCode != http.StatusOK {
		t.Fatalf("leaf CDP = HTTP %d read %v", crlResp.StatusCode, readErr)
	}
	crl, err := crypto.ParseCRL(crlDER, h.srv.caCertDER)
	if err != nil || len(crl.IssuingDistributionPointURLs) != 1 || crl.IssuingDistributionPointURLs[0] != wantCDP {
		t.Fatalf("leaf CDP served CRL with scope %v: %v", crl.IssuingDistributionPointURLs, err)
	}
	listed := false
	for _, serial := range crl.RevokedSerials {
		listed = listed || strings.EqualFold(strings.TrimLeft(serial, "0"), strings.TrimLeft(victim.SerialNumber, "0"))
	}
	if !listed {
		t.Fatalf("leaf CDP omitted revoked serial %s", victim.SerialNumber)
	}
	requestDER, err := crypto.BuildOCSPRequestForSerial(h.srv.caCertDER, victim.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, h.ts.URL+strings.TrimPrefix(wantOCSP, origin), bytes.NewReader(requestDER))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/ocsp-request")
	response, err := h.ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseDER, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("leaf OCSP AIA = HTTP %d read %v", response.StatusCode, readErr)
	}
	status, err := crypto.ParseOCSPResponse(responseDER, h.srv.caCertDER)
	if err != nil || status.Status != crypto.OCSPRevoked {
		t.Fatalf("leaf OCSP AIA reported %q, want revoked: %v", status.Status, err)
	}
}
