// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
)

// fetchMDMSCEPChallenge plays the MDM: it fetches the challenge page with the
// policy's credential and parses it the way an MDM parses the dynamic
// challenge page (the value between <B> and </B> after the label).
func fetchMDMSCEPChallenge(t *testing.T, h *servedHarness, policyID, username, password string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+"/scep/mscep_admin/"+policyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("fetch challenge page: %v", err)
	}
	body, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	_, after, found := strings.Cut(string(body), "The enrollment challenge password is:")
	start, end := strings.Index(after, "<B>"), strings.Index(after, "</B>")
	if !found || start < 0 || end < start {
		t.Fatalf("challenge page is not the dynamic challenge shape: %s", body)
	}
	return resp.StatusCode, strings.TrimSpace(after[start+len("<B>") : end])
}

// scepEnrollDecision returns the served SCEP gate's audited decision for one
// transaction ("" when none was recorded).
func scepEnrollDecision(t *testing.T, h *servedHarness, transactionID string) (decision, profileName string) {
	t.Helper()
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID != h.tenant || event.Type != "protocol.scep.enroll" {
			return nil
		}
		var audit struct {
			Decision      string `json:"decision"`
			TransactionID string `json:"transaction_id"`
			Profile       string `json:"profile"`
		}
		if err := json.Unmarshal(event.Data, &audit); err != nil {
			return err
		}
		if audit.TransactionID == transactionID {
			decision, profileName = audit.Decision, audit.Profile
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return decision, profileName
}

func scepEnrollWithChallenge(t *testing.T, h *servedHarness, cn, challenge, transactionID string) int {
	t.Helper()
	caResp, err := h.ts.Client().Get(h.ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	caBody, _ := readAllClose(caResp)
	raCertDER := scepRARecipient(t, caBody)
	clientCertDER, clientKeyPKCS8, csrDER := newSCEPClientWithChallenge(t, cn, challenge)
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCertDER, clientKeyPKCS8, raCertDER, transactionID)
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("SCEP PKIOperation: %v", err)
	}
	_, _ = readAllClose(resp)
	return resp.StatusCode
}

// A154: a Jamf-managed Mac's enrollment with a dynamic challenge. A simulated
// Jamf Pro fetches a per-device challenge from the policy's challenge page
// with the policy's credential (the "Dynamic-Microsoft CA" SCEP payload
// shape); the device enrolls once with it; a wrong credential, an unknown
// policy and a replayed challenge are each refused. Live Jamf Pro is Track B.
func TestServedJamfDynamicChallengeEnrollsOnceA154(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		SCEP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Jamf dynamic challenge tenant")
	storeServerTestProfile(t, h.store, h.tenant, "mac-scep", profile.CertificateProfile{
		Name: "mac-scep", AllowedProtocols: []string{"scep"},
		MaxValidity: profile.Duration(7 * 24 * time.Hour),
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	const username, password = "jamf-scep", "correct horse battery staple"
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "mdm/jamf/scep-challenge", "value": username + ":" + password,
	})
	if status != http.StatusCreated {
		t.Fatalf("store the Jamf challenge credential: %d %s", status, body)
	}
	create := map[string]any{ // #nosec G101 -- a secret:// reference in a test fixture, not a credential value (CWE-798)
		"name": "jamf-macs", "provider": "jamf", "scep_profile": "mac-scep",
		"scep_endpoint": h.ts.URL + "/scep/pkiclient.exe", "challenge_mode": "hmac-dynamic",
		"challenge_credential_ref": "secret://mdm/jamf/scep-challenge", "enabled": true,
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies/preview", tok, create)
	var preview struct {
		Ready      bool     `json:"ready"`
		Configured bool     `json:"challenge_credential_configured"`
		Blockers   []string `json:"blockers"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || !preview.Ready || !preview.Configured {
		t.Fatalf("hmac-dynamic preview = %d %s; want ready with the credential configured", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, create)
	var policy struct {
		ID            string `json:"id"`
		ChallengePath string `json:"challenge_path"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &policy) != nil || policy.ChallengePath != "/scep/mscep_admin/"+policy.ID {
		t.Fatalf("create hmac-dynamic policy = %d %s", status, body)
	}
	if strings.Contains(string(body), password) {
		t.Fatalf("policy response leaked the credential: %s", body)
	}

	for _, probe := range []struct {
		name, policy, user, pass string
		want                     int
	}{
		{"no credential", policy.ID, "", "", http.StatusUnauthorized},
		{"wrong password", policy.ID, username, "wrong", http.StatusUnauthorized},
		{"wrong username", policy.ID, "other", password, http.StatusUnauthorized},
		{"unknown policy", "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e", username, password, http.StatusNotFound},
		{"not a policy id", "..%2F..%2Fetc", username, password, http.StatusNotFound},
	} {
		if code, _ := fetchMDMSCEPChallenge(t, h, probe.policy, probe.user, probe.pass); code != probe.want {
			t.Errorf("%s: challenge page = %d; want %d", probe.name, code, probe.want)
		}
	}
	code, challenge := fetchMDMSCEPChallenge(t, h, policy.ID, username, password)
	if code != http.StatusOK || !strings.HasPrefix(challenge, "h1."+policy.ID+".") {
		t.Fatalf("challenge page = %d %q", code, challenge)
	}

	if code := scepEnrollWithChallenge(t, h, "jamf-mac-01", challenge, "a154-first"); code != http.StatusOK {
		t.Fatalf("enroll with the dynamic challenge = %d", code)
	}
	if decision, profileName := scepEnrollDecision(t, h, "a154-first"); decision != "allow" || profileName != "mac-scep" {
		t.Fatalf("first enrollment decision = %q profile %q; want allow under the policy's profile", decision, profileName)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Fatal("the enrolled device certificate was not recorded in inventory")
	}
	_ = scepEnrollWithChallenge(t, h, "jamf-mac-02", challenge, "a154-replay")
	if decision, _ := scepEnrollDecision(t, h, "a154-replay"); decision == "allow" {
		t.Fatal("a replayed dynamic challenge enrolled a second device")
	}
	if !h.hasEvent(t, "mdm.intune_scep_challenge.replay_rejected") {
		t.Fatal("the replayed challenge left no replay-rejected decision event")
	}
	tampered := challenge[:len(challenge)-4] + "AAAA"
	if tampered == challenge {
		tampered = challenge[:len(challenge)-4] + "BBBB"
	}
	_ = scepEnrollWithChallenge(t, h, "jamf-mac-03", tampered, "a154-tampered")
	if decision, _ := scepEnrollDecision(t, h, "a154-tampered"); decision == "allow" {
		t.Fatal("a tampered dynamic challenge enrolled a device")
	}
}

// A155: stock sscep enrolls with a dynamic challenge fetched by the simulated
// MDM, and a second stock enrollment with the same challenge is refused.
func TestServedJamfDynamicChallengeStockSSCEPA155(t *testing.T) {
	sscep, err := exec.LookPath("sscep")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_SSCEP") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_SSCEP is set but sscep is not on PATH: %v", err)
		}
		t.Skip("sscep not on PATH; set TRSTCTL_REQUIRE_SSCEP=1 in CI to make the external SCEP client mandatory")
	}
	h := newServedHarness(t, config.Protocols{
		SCEP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Jamf dynamic challenge stock client tenant")
	storeServerTestProfile(t, h.store, h.tenant, "mac-scep", profile.CertificateProfile{
		Name: "mac-scep", AllowedProtocols: []string{"scep"},
		MaxValidity: profile.Duration(7 * 24 * time.Hour),
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "mdm/jamf/scep-challenge", "value": "jamf-scep:stock client credential",
	}); status != http.StatusCreated {
		t.Fatalf("store credential: %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, map[string]any{ // #nosec G101 -- a secret:// reference in a test fixture, not a credential value (CWE-798)
		"name": "jamf-macs", "provider": "jamf", "scep_profile": "mac-scep",
		"scep_endpoint": h.ts.URL + "/scep/pkiclient.exe", "challenge_mode": "hmac-dynamic",
		"challenge_credential_ref": "secret://mdm/jamf/scep-challenge", "enabled": true,
	})
	var policy struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &policy) != nil {
		t.Fatalf("create policy: %d %s", status, body)
	}
	code, challenge := fetchMDMSCEPChallenge(t, h, policy.ID, "jamf-scep", "stock client credential")
	if code != http.StatusOK {
		t.Fatalf("challenge page = %d", code)
	}
	dir := t.TempDir()
	scepURL := h.ts.URL + "/scep/pkiclient.exe"
	caFile := filepath.Join(dir, "sscep-ca.crt")
	getCA := exec.Command(sscep, "getca", "-u", scepURL, "-c", caFile, "-F", "sha256", "-v") // #nosec G204 -- test executes a fixed local tool (CWE-78)
	if out, err := getCA.CombinedOutput(); err != nil {
		t.Fatalf("sscep getca: %v\n%s", err, out)
	}
	servedIssuerDER := caCertDER(t, h.caPEM)
	caFiles, err := servedDiscoverSSCEPGetCACertFiles(caFile, servedIssuerDER)
	if err != nil {
		t.Fatalf("classify sscep GetCACert output: %v", err)
	}
	enroll := func(name string) ([]byte, string, error) {
		_, clientKey, csrDER := newSCEPClientWithChallenge(t, name, challenge)
		keyFile := servedWritePEMFile(t, dir, name+".key", "PRIVATE KEY", clientKey)
		csrFile := servedWritePEMFile(t, dir, name+".csr", "CERTIFICATE REQUEST", csrDER)
		issued := filepath.Join(dir, name+"-issued.crt")
		cmd := exec.Command(sscep, "enroll", "-u", scepURL, "-c", caFiles.RAPath, "-k", keyFile, "-r", csrFile, // #nosec G204 -- test executes a fixed local tool (CWE-78)
			"-l", issued, "-L", filepath.Join(dir, name+"-selfsigned.crt"), "-E", "aes256", "-S", "sha256", "-t", "1", "-n", "1", "-v")
		out, err := cmd.CombinedOutput()
		return out, issued, err
	}
	out, issued, err := enroll("jamf-mac-stock-01")
	if err != nil {
		t.Fatalf("stock sscep enrollment with the dynamic challenge: %v\n%s", err, out)
	}
	if err := crypto.VerifyLeafSignedByCA(servedReadCertificateFile(t, issued), servedIssuerDER); err != nil {
		t.Fatalf("issued certificate does not verify against the served CA: %v", err)
	}
	out, _, err = enroll("jamf-mac-stock-02")
	if err == nil {
		t.Fatalf("stock sscep reused a consumed dynamic challenge:\n%s", out)
	}
	if !h.hasEvent(t, "mdm.intune_scep_challenge.replay_rejected") {
		t.Fatalf("the refused stock enrollment was not the replay fence:\n%s", out)
	}
}
