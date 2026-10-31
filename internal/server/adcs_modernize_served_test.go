// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/store"
)

func estEnrollStatus(t *testing.T, h *servedHarness, token string, tmpl crypto.CertificateRequestTemplate) int {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(csr))))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("EST simpleenroll: %v", err)
	}
	_, _ = readAllClose(resp)
	return resp.StatusCode
}

// A160 Done-when: an ESC1-prone template becomes a trstctl profile without the
// requester-supplied subject. A relay observed UserAuth (the requester supplies
// the subject, client authentication, Domain Users may enroll) published by
// CORP-CA at ca01.corp.example; the effect-free preview names what changes,
// modernize creates the profile, and enrollment under it accepts an in-domain
// host but refuses another account's email name and an out-of-domain host.
func TestServedESC1TemplateModernizesIntoAProfileWithoutTheRequesterSuppliedSubject(t *testing.T) {
	const profileName = "adcs-userauth-modern"
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.DefaultProfile = profileName })
	registerServedTenant(t, h, "AD CS modernize tenant")
	observed, err := json.Marshal(adcsdiscovery.Template{
		Name: "UserAuth", DisplayName: "User Authentication", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		EKUs: []string{adcsdiscovery.EKUClientAuth, adcsdiscovery.EKUSmartcardLogon}, EnrollmentPrincipals: []string{`CORP\Domain Users`},
		PublishedBy: []string{"CORP-CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyADCSPostureObservedTx(t.Context(), tx, h.tenant, "CORP-CA", "relay-1",
			[]store.ADCSTemplatePosture{{Domain: "CORP-CA", Template: "UserAuth", DisplayName: "User Authentication", SchemaVersion: 4,
				PublishedBy: []string{"CORP-CA"}, WorstSeverity: "critical", FindingCount: 1, Findings: json.RawMessage(`[]`),
				ObservedBy: "relay-1", ObservedTemplate: observed}},
			[]store.ADCSEnrollmentServicePosture{{Domain: "CORP-CA", Service: "CORP-CA", DNSName: "ca01.corp.example",
				AgentRestrictionState: "unobserved", AgentRestrictionSource: "none",
				Findings: json.RawMessage(`[]`), ObservedService: json.RawMessage(`{}`), ObservedBy: "relay-1"}},
			time.Now().UTC())
	}); err != nil {
		t.Fatalf("seed the observed template: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "profiles:read", "profiles:write")
	request := map[string]any{"domain": "CORP-CA", "template": "UserAuth"}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize/preview", tok, request)
	var plan struct {
		Ready       bool            `json:"ready"`
		EffectFree  bool            `json:"effect_free"`
		DNSSuffix   string          `json:"dns_suffix"`
		ProfileName string          `json:"profile_name"`
		Spec        json.RawMessage `json:"spec"`
		Changes     []struct {
			Code string `json:"code"`
		} `json:"changes"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &plan) != nil || !plan.Ready || !plan.EffectFree ||
		plan.DNSSuffix != "corp.example" || plan.ProfileName != profileName {
		t.Fatalf("preview = %d %s", status, body)
	}
	codes := map[string]bool{}
	for _, change := range plan.Changes {
		codes[change.Code] = true
	}
	if !codes["requester_supplied_subject_removed"] || !codes["eku_removed"] {
		t.Fatalf("preview changes = %s; want the requester-supplied subject and Smart Card Logon removed", body)
	}
	if _, err := h.store.GetActiveProfile(t.Context(), h.tenant, profileName); err == nil {
		t.Fatal("the preview created the profile")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize", tok, request)
	if status != http.StatusCreated || !strings.Contains(string(body), `"state":"created"`) {
		t.Fatalf("modernize = %d %s", status, body)
	}
	rec, err := h.store.GetActiveProfile(t.Context(), h.tenant, profileName)
	if err != nil {
		t.Fatalf("the modernized profile was not stored: %v", err)
	}
	var stored struct {
		AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
		AllowedEKUs        []string `json:"allowed_ekus"`
	}
	if err := json.Unmarshal(rec.Spec, &stored); err != nil || strings.Join(stored.AllowedDNSSuffixes, ",") != "corp.example" ||
		strings.Join(stored.AllowedEKUs, ",") != "clientAuth" {
		t.Fatalf("stored spec = %s; want names confined to corp.example and clientAuth only", rec.Spec)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize", tok, request); status != http.StatusConflict {
		t.Fatalf("modernize twice = %d %s; want a conflict naming the existing profile", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize/preview", tok,
		map[string]any{"domain": "CORP-CA", "template": "NeverObserved"}); status != http.StatusOK || !strings.Contains(string(body), `"ready":false`) {
		t.Fatalf("preview of an unobserved template = %d %s; want not ready", status, body)
	}

	enroll := seedAPIToken(t, h.store, servedTestTenant)
	if code := estEnrollStatus(t, h, enroll, crypto.CertificateRequestTemplate{CommonName: "laptop-17.corp.example", DNSNames: []string{"laptop-17.corp.example"}}); code != http.StatusOK {
		t.Fatalf("an in-domain host under the modernized profile = %d; want issued", code)
	}
	for name, tmpl := range map[string]crypto.CertificateRequestTemplate{
		"another account's email name": {CommonName: "laptop-17.corp.example", DNSNames: []string{"laptop-17.corp.example"}, EmailAddresses: []string{"administrator@corp.example"}},
		"an out-of-domain host":        {CommonName: "dc01.other.example", DNSNames: []string{"dc01.other.example"}},
	} {
		if code := estEnrollStatus(t, h, enroll, tmpl); code == http.StatusOK {
			t.Errorf("%s was issued under the modernized profile", name)
		}
	}
}
