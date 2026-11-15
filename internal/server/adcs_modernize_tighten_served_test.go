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

// estEnrollWith enrolls over EST with a fresh key of the given algorithm.
func estEnrollWith(t *testing.T, h *servedHarness, token string, algorithm crypto.Algorithm, tmpl crypto.CertificateRequestTemplate) int {
	t.Helper()
	key, err := crypto.GenerateLockedKey(algorithm)
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

// TestServedTemplateModernizationTightensButNeverWeakensA160L2 is A160-L2's
// Done-when (served): modernizing a template takes an optional validity
// ceiling, key algorithms and RSA floor, and never anything weaker than the
// baseline (90 days, ECDSA or RSA, RSA of 2048 bits). A longer validity, an
// algorithm outside the baseline, a lower RSA floor, an RSA floor without RSA
// and a non-positive validity are refused (400) on both the preview and the
// apply, with nothing created. A tighter choice (30 days, RSA only, 3072
// bits) previews with those values and the changes naming them, and applies
// into a profile that enrollment then enforces: an ECDSA key and a 2048-bit
// RSA key are refused, a 3072-bit RSA key is issued.
func TestServedTemplateModernizationTightensButNeverWeakensA160L2(t *testing.T) {
	const profileName = "adcs-userauth-tight"
	// Its own tenant: the profile, posture and certificates it records stay
	// out of the shared served tenant's other tests.
	const tenant = "a1600002-60a2-4a60-8a60-0000a1600002"
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: tenant}},
		func(d *Deps) { d.DefaultProfile = profileName })
	registerServedTenantID(t, h, tenant, "AD CS modernize tightening tenant")
	observed, err := json.Marshal(adcsdiscovery.Template{
		Name: "UserAuth", DisplayName: "User Authentication", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		EKUs: []string{adcsdiscovery.EKUClientAuth}, PublishedBy: []string{"CORP-CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		return h.store.ApplyADCSPostureObservedTx(t.Context(), tx, tenant, "CORP-CA", "relay-1",
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
	tok := seedScopedToken(t, h.store, tenant, "profiles:read", "profiles:write")
	request := func(extra map[string]any) map[string]any {
		out := map[string]any{"domain": "CORP-CA", "template": "UserAuth", "profile_name": profileName}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	for name, weaker := range map[string]map[string]any{
		"a longer validity":             {"max_validity_days": 120},
		"a non-positive validity":       {"max_validity_days": -1},
		"an algorithm outside":          {"key_algorithms": []string{"DSA"}},
		"a lower RSA floor":             {"min_rsa_bits": 1024},
		"an RSA floor without RSA":      {"key_algorithms": []string{"ECDSA"}, "min_rsa_bits": 3072},
		"an RSA floor beyond its bound": {"min_rsa_bits": 32768},
	} {
		for _, path := range []string{"/api/v1/posture/adcs/templates/modernize/preview", "/api/v1/posture/adcs/templates/modernize"} {
			if status, body := secretsReq(t, h, http.MethodPost, path, tok, request(weaker)); status != http.StatusBadRequest {
				t.Fatalf("%s at %s = %d %s; want 400", name, path, status, body)
			}
		}
	}
	if _, err := h.store.GetActiveProfile(t.Context(), tenant, profileName); err == nil {
		t.Fatal("a refused request created the profile")
	}

	tight := request(map[string]any{"max_validity_days": 30, "key_algorithms": []string{"rsa"}, "min_rsa_bits": 3072})
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize/preview", tok, tight)
	var plan struct {
		Ready bool `json:"ready"`
		Spec  struct {
			MaxValidity          string   `json:"max_validity"`
			AllowedKeyAlgorithms []string `json:"allowed_key_algorithms"`
			MinRSABits           int      `json:"min_rsa_bits"`
		} `json:"spec"`
		Changes []struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		} `json:"changes"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &plan) != nil || !plan.Ready || plan.Spec.MaxValidity != "720h0m0s" ||
		strings.Join(plan.Spec.AllowedKeyAlgorithms, ",") != "RSA" || plan.Spec.MinRSABits != 3072 {
		t.Fatalf("tight preview = %d %s", status, body)
	}
	details := map[string]string{}
	for _, c := range plan.Changes {
		details[c.Code] = c.Detail
	}
	if !strings.Contains(details["validity_shortened"], "at most 30 days") || details["key_algorithms_narrowed"] != "Keys must be RSA." ||
		details["rsa_floor_raised"] != "RSA keys must be at least 3072 bits." {
		t.Fatalf("tight preview changes = %v", details)
	}
	if _, err := h.store.GetActiveProfile(t.Context(), tenant, profileName); err == nil {
		t.Fatal("the preview created the profile")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/posture/adcs/templates/modernize", tok, tight)
	if status != http.StatusCreated || !strings.Contains(string(body), `"state":"created"`) {
		t.Fatalf("modernize = %d %s", status, body)
	}
	rec, err := h.store.GetActiveProfile(t.Context(), tenant, profileName)
	if err != nil {
		t.Fatalf("the tightened profile was not stored: %v", err)
	}
	var stored struct {
		MaxValidity          string   `json:"max_validity"`
		AllowedKeyAlgorithms []string `json:"allowed_key_algorithms"`
		MinRSABits           int      `json:"min_rsa_bits"`
	}
	if err := json.Unmarshal(rec.Spec, &stored); err != nil || stored.MaxValidity != "720h0m0s" ||
		strings.Join(stored.AllowedKeyAlgorithms, ",") != "RSA" || stored.MinRSABits != 3072 {
		t.Fatalf("stored spec = %s", rec.Spec)
	}

	// Enrollment enforces the tightened profile.
	enroll := seedAPIToken(t, h.store, tenant)
	host := crypto.CertificateRequestTemplate{CommonName: "laptop-17.corp.example", DNSNames: []string{"laptop-17.corp.example"}}
	if code := estEnrollWith(t, h, enroll, crypto.ECDSAP256, host); code == http.StatusOK {
		t.Fatal("an ECDSA key was issued under an RSA-only profile")
	}
	if code := estEnrollWith(t, h, enroll, crypto.RSA2048, host); code == http.StatusOK {
		t.Fatal("a 2048-bit RSA key was issued under a 3072-bit floor")
	}
	if code := estEnrollWith(t, h, enroll, crypto.RSA3072, host); code != http.StatusOK {
		t.Fatalf("a 3072-bit RSA key under the tightened profile = %d; want issued", code)
	}
	t.Log("A160L2_OK")
}
