// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type adcsIssuerHealthView struct {
	Items []struct {
		ID                     string  `json:"id"`
		Status                 string  `json:"status"`
		IssuedInWindow         int     `json:"issued_in_window"`
		LastSuccessAt          *string `json:"last_success_at"`
		LastFailureCause       string  `json:"last_failure_cause"`
		LastFailureRemediation string  `json:"last_failure_remediation"`
	} `json:"items"`
}

func readADCSIssuerHealth(t *testing.T, h *servedHarness, token string) adcsIssuerHealthView {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/adcs/issuers/health", token, nil)
	var view adcsIssuerHealthView
	if status != http.StatusOK || json.Unmarshal(body, &view) != nil || len(view.Items) != 1 || view.Items[0].ID != "corp-adcs-web" {
		t.Fatalf("issuer health = %d %s", status, body)
	}
	return view
}

func issueThroughADCS(t *testing.T, h *servedHarness, token, name string) int {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/issue", token, "a161-"+name, map[string]any{
		"csr_pem":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"dns_names": []string{name}, "ttl_seconds": 86400,
	})
	return status
}

// A161: the AD CS issuer health view says whether issuance through each adcs
// issuer is working, from the evidence trstctl records: an issuer with no
// activity is idle, a successful AD CS issuance makes it healthy, and a refusal
// after that makes it failing with the classified cause and remediation.
// Another tenant sees the same issuer with none of this tenant's evidence.
func TestServedADCSIssuerHealthFollowsIssuanceAndRefusals(t *testing.T) {
	standIn, certsrv := newADCSCertsrvStandIn(t)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.ExternalCAs = adcsUpstreamConfig(t, certsrv.URL) })
	startServedOutboxPump(t, h.srv)
	registerServedTenant(t, h, "AD CS issuer health tenant")
	token := seedScopedToken(t, h.store, h.tenant, "issuers:read", "certs:issue")

	if view := readADCSIssuerHealth(t, h, token); view.Items[0].Status != "idle" {
		t.Fatalf("before any issuance status = %q; want idle", view.Items[0].Status)
	}
	if status := issueThroughADCS(t, h, token, "web01.corp.example"); status != http.StatusCreated {
		t.Fatalf("issue through AD CS = %d", status)
	}
	view := readADCSIssuerHealth(t, h, token)
	if item := view.Items[0]; item.Status != "healthy" || item.IssuedInWindow != 1 || item.LastSuccessAt == nil {
		t.Fatalf("after a success = %+v; want healthy with one issuance", item)
	}

	standIn.mu.Lock()
	standIn.deny = true
	standIn.mu.Unlock()
	if status := issueThroughADCS(t, h, token, "web02.corp.example"); status == http.StatusCreated {
		t.Fatal("the denying AD CS stand-in issued a certificate")
	}
	view = readADCSIssuerHealth(t, h, token)
	if item := view.Items[0]; item.Status != "failing" || item.LastFailureCause != "template_acl_denied" || item.LastFailureRemediation == "" {
		t.Fatalf("after a refusal = %+v; want failing with the template ACL cause and a remediation", item)
	}

	const otherTenant = "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, otherTenant, "AD CS issuer health neighbor")
	other := seedScopedToken(t, h.store, otherTenant, "issuers:read")
	if neighbor := readADCSIssuerHealth(t, h, other); neighbor.Items[0].Status != "idle" || neighbor.Items[0].IssuedInWindow != 0 {
		t.Fatalf("another tenant sees %+v; want idle with none of this tenant's evidence", neighbor.Items[0])
	}
}
