// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type servedHeldIssue struct {
	CARequestID    int      `json:"ca_request_id"`
	DNSNames       []string `json:"dns_names"`
	Status         string   `json:"status"`
	Serial         string   `json:"serial"`
	CertificatePEM string   `json:"certificate_pem"`
}

// TestServedADCSIssuanceHeldForApprovalResumesByRequestIDN1L1 is N1-L1: an
// issuance through an AD CS template that needs a CA manager's approval gives
// up waiting with the CA's request id recorded; resuming it while the CA still
// holds it answers 409 and records nothing; once a manager approves it,
// resuming reads the request back by its id and records the certificate under
// the issuance's own key, so the issuance's caller gets it by replaying its
// request. The CA saw one submission per issuance, never a second. A denied
// request resumes as denied, and another tenant sees none of it.
func TestServedADCSIssuanceHeldForApprovalResumesByRequestIDN1L1(t *testing.T) {
	standIn, certsrv := newADCSCertsrvStandIn(t)
	standIn.mu.Lock()
	standIn.hold = true
	// Request ids of its own: served tests share a tenant and a database, and
	// a CA's request id names one request.
	standIn.seq = 4100
	standIn.mu.Unlock()
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.ExternalCAs = adcsUpstreamConfig(t, certsrv.URL) })
	startServedOutboxPump(t, h.srv)
	registerServedTenant(t, h, "N1-L1 held issuance tenant")
	token := seedScopedToken(t, h.store, h.tenant, "issuers:read", "certs:read", "certs:issue")

	csrFor := func(name string) string {
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
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	}
	issue := func(key, name, csrPEM string) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/issue", token, key, map[string]any{
			"csr_pem": csrPEM, "dns_names": []string{name}, "ttl_seconds": 86400,
		})
	}
	heldList := func(tok string) []servedHeldIssue {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/external-cas/corp-adcs-web/held-issues", tok, nil)
		var list struct {
			Items []servedHeldIssue `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("held issuances = %d %s", status, body)
		}
		var mine []servedHeldIssue
		for _, item := range list.Items {
			if item.CARequestID > 4100 && item.CARequestID < 4200 {
				mine = append(mine, item)
			}
		}
		return mine
	}
	waitHeld := func(n int) []servedHeldIssue {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			items := heldList(token)
			if len(items) >= n || time.Now().After(deadline) {
				return items
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	resume := func(key string, requestID int) (int, servedHeldIssue, []byte) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, fmt.Sprintf("/api/v1/external-cas/corp-adcs-web/held-issues/%d/resume", requestID), token, key, nil)
		var view servedHeldIssue
		_ = json.Unmarshal(body, &view)
		return status, view, body
	}

	// The CA holds the request: the issuance gives up waiting, and trstctl
	// records the CA's request id.
	heldCSR := csrFor("held.served.test")
	if status, body := issue("n1l1-issue-held", "held.served.test", heldCSR); status == http.StatusCreated {
		t.Fatalf("an issuance the CA holds for approval completed: %s", body)
	}
	items := waitHeld(1)
	if len(items) != 1 || items[0].CARequestID != 4101 || items[0].Status != "held" || len(items[0].DNSNames) != 1 || items[0].DNSNames[0] != "held.served.test" {
		t.Fatalf("held issuances = %+v; want request 4101 for held.served.test, held", items)
	}

	// Resuming while the CA still holds it records nothing.
	if status, _, body := resume("n1l1-resume-early", 4101); status != http.StatusConflict {
		t.Fatalf("resume while held = %d %s; want 409", status, body)
	}
	if items := heldList(token); items[0].Status != "held" {
		t.Fatalf("after resuming early = %+v", items[0])
	}

	// A CA manager approves it; resuming records the certificate.
	standIn.approveHeld(t, 4101)
	status, resumed, body := resume("n1l1-resume-1", 4101)
	if status != http.StatusOK || resumed.Status != "issued" || resumed.Serial == "" || resumed.CertificatePEM == "" {
		t.Fatalf("resume after approval = %d %s", status, body)
	}
	// The issuance's own caller replays its request and gets that certificate.
	status, body = issue("n1l1-issue-held", "held.served.test", heldCSR)
	var replayed struct {
		Serial string `json:"serial"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &replayed) != nil || replayed.Serial != resumed.Serial {
		t.Fatalf("the issuance's replay = %d %s; want the resumed certificate %s", status, body, resumed.Serial)
	}
	// Resuming again answers the same.
	if status, again, body := resume("n1l1-resume-2", 4101); status != http.StatusOK || again.Status != "issued" || again.Serial != resumed.Serial {
		t.Fatalf("resume again = %d %s", status, body)
	}
	if items := heldList(token); items[0].Status != "issued" || items[0].Serial != resumed.Serial {
		t.Fatalf("held issuance after resuming = %+v", items[0])
	}

	// A request the CA manager denies resumes as denied.
	if status, body := issue("n1l1-issue-denied", "denied.served.test", csrFor("denied.served.test")); status == http.StatusCreated {
		t.Fatalf("a second held issuance completed: %s", body)
	}
	if items := waitHeld(2); len(items) != 2 || items[0].CARequestID != 4102 {
		t.Fatalf("held issuances = %+v; want request 4102 first", items)
	}
	standIn.denyHeld(t, 4102)
	if status, denied, body := resume("n1l1-resume-denied", 4102); status != http.StatusOK || denied.Status != "denied" || denied.CertificatePEM != "" {
		t.Fatalf("resume a denied request = %d %s", status, body)
	}

	// The CA saw one submission per issuance, never a second.
	standIn.mu.Lock()
	submissions := len(standIn.templates)
	standIn.mu.Unlock()
	if submissions != 2 {
		t.Fatalf("the CA saw %d submissions for two issuances", submissions)
	}

	// Another tenant sees none of it and cannot resume it.
	const otherTenant = "33333333-3333-4333-8333-333333333333"
	registerServedTenantID(t, h, otherTenant, "N1-L1 neighbor")
	other := seedScopedToken(t, h.store, otherTenant, "issuers:read", "certs:read", "certs:issue")
	if items := heldList(other); len(items) != 0 {
		t.Fatalf("another tenant sees held issuances: %+v", items)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/held-issues/4101/resume", other, "n1l1-other", nil); status != http.StatusNotFound {
		t.Fatalf("another tenant resumed request 4101: %d", status)
	}
}
