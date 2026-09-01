// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedSSHAtScaleJourneyJOURNEY002EndToEnd proves the operator-facing SSH
// journey is one served product surface, not disconnected library pieces: create
// an SSH discovery source/run, record safe trust-rollout status, issue an
// attestation-gated SSH user cert, revoke it into the served KRL, and retire a
// host from the journey evidence.
func TestServedSSHAtScaleJourneyJOURNEY002EndToEnd(t *testing.T) {
	trust := servedDynamicK8sTrustFixture(t, "journey-ssh-k1")
	h := newServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			d.AttestedIssuance = AttestedIssuanceConfig{
				Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
			}
			d.AgentClaimableJobKinds = []string{"discovery.run"}
		},
		withAgentChannel,
	)
	token := seedScopedToken(t, h.store, h.tenant,
		"discovery:write", "discovery:read",
		"agents:write", "agents:read",
		"certs:issue", "certs:write", "certs:read",
		"identities:write", "identities:read",
	)
	// SSH fleet discovery is relay-owned. Bootstrap the prerequisite through the
	// real enrollment authority so the journey proves admission against an
	// enrolled, certificate-stamped network role instead of bypassing readiness.
	relayAgent := enrollAgentWithRoles(t, h, "journey-002-network-relay", "agent.trstctl.local", []string{mtls.AgentRoleNetwork})
	heartbeatEnrolledAgent(t, h, relayAgent)

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "journey-002-trust-create", map[string]any{
			"name": "ssh-canary-k8s", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": trust.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create SSH workload trust source: status %d body %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-rollouts", token, "journey-002-incomplete-rollout", map[string]any{
		"target_hosts": []string{"edge-1.internal"}, "status": "planned", "confirmed": true,
	})
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("candidate_ca_fingerprint")) {
		t.Fatalf("incomplete SSH rollout evidence should fail closed: status %d body %s", status, body)
	}

	sourceID, runID := createSSHDiscoverySourceAndRun(t, h, token)

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-rollouts", token, "journey-002-rollout", map[string]any{
		"source_id":                sourceID,
		"target_hosts":             []string{"edge-1.internal"},
		"candidate_ca_fingerprint": "SHA256:served-ssh-ca",
		"reload_command":           "systemctl reload sshd",
		"health_command":           "ssh -o BatchMode=yes localhost true",
		"rollback_plan":            "restore trusted_user_ca_keys backup and reload sshd",
		"status":                   "health_passed",
		"confirmed":                true,
	})
	if status != http.StatusCreated {
		t.Fatalf("record SSH trust rollout: status %d body %s", status, body)
	}
	var rollout struct {
		ID       string   `json:"id"`
		SourceID string   `json:"source_id"`
		Status   string   `json:"status"`
		Hosts    []string `json:"target_hosts"`
	}
	if err := json.Unmarshal(body, &rollout); err != nil {
		t.Fatalf("decode rollout: %v (%s)", err, body)
	}
	if rollout.ID == "" || rollout.SourceID != sourceID || rollout.Status != "health_passed" || len(rollout.Hosts) != 1 {
		t.Fatalf("bad rollout response: %+v", rollout)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	pubAuthorizedKeys := genSSHKey(t, keyPath)
	attestedRequest := map[string]any{
		"method":           "k8s_sat",
		"payload_base64":   base64.StdEncoding.EncodeToString([]byte(trust.SAT)),
		"public_key":       string(pubAuthorizedKeys),
		"key_id":           "deployer@edge-1",
		"ttl_seconds":      600,
		"approver":         "ssh-approver",
		"principals":       []string{"web"},
		"source_addresses": []string{"10.0.0.0/24"},
		"force_command":    "/usr/local/bin/deploy",
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs/preview", token, "", attestedRequest)
	if status != http.StatusOK {
		t.Fatalf("preview attested SSH user cert: status %d body %s", status, body)
	}
	var preview struct {
		Capability              string   `json:"capability"`
		Ready                   bool     `json:"ready"`
		EffectFree              bool     `json:"effect_free"`
		Method                  string   `json:"method"`
		Approver                string   `json:"approver"`
		Principals              []string `json:"principals"`
		SourceAddresses         []string `json:"source_addresses"`
		ForceCommand            string   `json:"force_command"`
		RequestedTTLSeconds     int64    `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds     int64    `json:"effective_ttl_seconds"`
		AttestationVerification string   `json:"attestation_verification"`
		PayloadSHA256           string   `json:"payload_sha256"`
		PublicKeyFingerprint    string   `json:"public_key_fingerprint"`
		PreviewWrites           []string `json:"preview_writes"`
		PreviewSignerCalls      []string `json:"preview_signer_calls"`
		RecoverySteps           []string `json:"recovery_steps"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode attested SSH preview: %v (%s)", err, body)
	}
	if preview.Capability != "F45" || !preview.Ready || !preview.EffectFree || preview.Method != "k8s_sat" || preview.Approver != "ssh-approver" {
		t.Fatalf("bad attested SSH preview: %+v", preview)
	}
	if preview.RequestedTTLSeconds != 600 || preview.EffectiveTTLSeconds != 600 || preview.AttestationVerification != "execution_only" {
		t.Fatalf("attested SSH preview did not preserve exact lifetime/gate: %+v", preview)
	}
	if len(preview.Principals) != 1 || preview.Principals[0] != "web" || len(preview.SourceAddresses) != 1 || preview.SourceAddresses[0] != "10.0.0.0/24" || preview.ForceCommand != "/usr/local/bin/deploy" {
		t.Fatalf("attested SSH preview did not preserve exact constraints: %+v", preview)
	}
	if preview.PayloadSHA256 == "" || preview.PublicKeyFingerprint == "" || len(preview.PreviewWrites) != 0 || len(preview.PreviewSignerCalls) != 0 || len(preview.RecoverySteps) == 0 {
		t.Fatalf("attested SSH preview omitted effect-free or recovery evidence: %+v", preview)
	}
	if h.hasEvent(t, "attestation.verified") || h.hasEvent(t, "ssh.attested_cert.issued") {
		t.Fatal("effect-free attested SSH preview emitted issuance evidence")
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", token, "journey-002-issue", attestedRequest)
	if status != http.StatusCreated {
		t.Fatalf("issue attested SSH user cert: status %d body %s", status, body)
	}
	var issued struct {
		Certificate     string   `json:"certificate"`
		Serial          uint64   `json:"serial"`
		KeyID           string   `json:"key_id"`
		Subject         string   `json:"subject"`
		Principals      []string `json:"principals"`
		Approver        string   `json:"approver"`
		SourceAddresses []string `json:"source_addresses"`
		ForceCommand    string   `json:"force_command"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issued SSH cert: %v (%s)", err, body)
	}
	if issued.Certificate == "" || issued.Serial == 0 || issued.Subject == "" {
		t.Fatalf("bad issued SSH cert response: %+v", issued)
	}
	if issued.Approver != "ssh-approver" || len(issued.Principals) != 1 || issued.Principals[0] != "web" {
		t.Fatalf("attested SSH response did not preserve approver/principal constraints: %+v", issued)
	}
	if len(issued.SourceAddresses) != 1 || issued.SourceAddresses[0] != "10.0.0.0/24" || issued.ForceCommand != "/usr/local/bin/deploy" {
		t.Fatalf("attested SSH response did not preserve session constraints: %+v", issued)
	}
	status, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", token, "journey-002-issue", attestedRequest)
	if status != http.StatusCreated || !bytes.Equal(body, replayBody) {
		t.Fatalf("unchanged attested SSH retry did not recover the original result: status %d first=%s replay=%s", status, body, replayBody)
	}
	conflictingRequest := make(map[string]any, len(attestedRequest))
	for key, value := range attestedRequest {
		conflictingRequest[key] = value
	}
	conflictingRequest["ttl_seconds"] = 601
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", token, "journey-002-issue", conflictingRequest)
	if status != http.StatusConflict {
		t.Fatalf("changed attested SSH retry should conflict: status %d body %s", status, body)
	}
	parsed, _, _, _, err := xssh.ParseAuthorizedKey([]byte(issued.Certificate))
	if err != nil {
		t.Fatalf("parse issued SSH cert: %v", err)
	}
	cert, ok := parsed.(*xssh.Certificate)
	if !ok {
		t.Fatalf("issued key is %T, want *ssh.Certificate", parsed)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "web" {
		t.Fatalf("issued SSH cert principals = %v", cert.ValidPrincipals)
	}
	if got := cert.CriticalOptions["source-address"]; got != "10.0.0.0/24" {
		t.Fatalf("issued SSH cert source-address = %q", got)
	}
	if got := cert.CriticalOptions["force-command"]; got != "/usr/local/bin/deploy" {
		t.Fatalf("issued SSH cert force-command = %q", got)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", token, "journey-002-expired-attestation", map[string]any{
		"method":         "k8s_sat",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte(trust.ExpiredSAT)),
		"public_key":     string(pubAuthorizedKeys),
		"key_id":         "deployer@edge-1-expired",
		"approver":       "ssh-approver",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expired SSH attestation should be rejected: status %d body %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", token, "journey-002-self-approval", map[string]any{
		"method":         "k8s_sat",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte(trust.SAT)),
		"public_key":     string(pubAuthorizedKeys),
		"key_id":         "deployer@edge-1-self",
		"approver":       issued.Subject,
	})
	if status != http.StatusForbidden {
		t.Fatalf("self-approved SSH attestation should be rejected: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/ssh/status", token, nil)
	if status != http.StatusOK {
		t.Fatalf("get SSH status before revoke: status %d body %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"krl_version":0`)) {
		t.Fatalf("initial KRL status should be version 0: %s", body)
	}
	if !bytes.Contains(body, []byte(`"attestors":["k8s_sat"]`)) {
		t.Fatalf("SSH status should publish the enabled tenant trust-source method: %s", body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", token, "journey-002-revoke", map[string]any{
		"serial": issued.Serial,
		"reason": "operator pulled SSH access before expiry",
	})
	if status != http.StatusOK {
		t.Fatalf("revoke SSH cert: status %d body %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"revoked_count":1`)) {
		t.Fatalf("revoke response should report one revoked item: %s", body)
	}

	krlResp, err := h.ts.Client().Get(h.ts.URL + "/ssh/krl")
	if err != nil {
		t.Fatalf("GET /ssh/krl: %v", err)
	}
	krl, _ := readAllClose(krlResp)
	if !bytes.HasPrefix(krl, []byte("SSHKRL\n\x00")) {
		t.Fatalf("served KRL is not OpenSSH binary format after API revoke: %q", firstBytes(krl, 8))
	}
	certPath := filepath.Join(dir, "id_ed25519-cert.pub")
	if err := os.WriteFile(certPath, []byte(issued.Certificate), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/hosts/retire", token, "journey-002-retire", map[string]any{
		"host":      "edge-1.internal",
		"source_id": sourceID,
		"run_id":    runID,
		"reason":    "standing SSH access replaced by short-lived certificates",
	})
	if status != http.StatusOK {
		t.Fatalf("retire SSH host: status %d body %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"status":"retired"`)) {
		t.Fatalf("host retire response should report retired: %s", body)
	}

	for _, eventType := range []string{
		"discovery.run.queued",
		"ssh.trust_rollout.recorded",
		"attestation.verified",
		"ssh.attested_cert.issued",
		"ssh.cert.revoked",
		"ssh.host.retired",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served SSH journey did not emit %s", eventType)
		}
	}
}

func createSSHDiscoverySourceAndRun(t *testing.T, h *servedHarness, token string) (sourceID, runID string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/segments", token,
		"journey-002-segment", map[string]any{
			"name": "ssh-fleet", "ranges": []string{"edge-1.internal"}, "staleness_hours": 24,
		})
	if status != http.StatusCreated {
		t.Fatalf("declare ssh discovery segment: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", token, map[string]any{
		"name":   "ssh-fleet",
		"kind":   "ssh",
		"config": map[string]any{"targets": []string{"edge-1.internal:22"}, "segment": "ssh-fleet"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create ssh discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode ssh discovery source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", token, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("queue ssh discovery run: status %d body %s", status, body)
	}
	var run struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode ssh discovery run: %v (%s)", err, body)
	}
	if source.ID == "" || run.ID == "" || run.Status != "queued" {
		t.Fatalf("bad ssh discovery source/run: source=%+v run=%+v", source, run)
	}
	return source.ID, run.ID
}
