// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	xssh "golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestServedSSHCertificatePreviewAndIssueF43 proves the product API exposes the
// signer-backed SSH CA as a reviewable workflow. Preview validates and
// normalizes the exact request without allocating a serial, emitting an event,
// changing the KRL, or calling the signer. Issue then mints exactly one host
// certificate, and an idempotent replay returns the same certificate.
func TestServedSSHCertificatePreviewAndIssueF43(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	publicKey := string(genSSHKey(t, filepath.Join(t.TempDir(), "ssh_host_ed25519_key")))
	request := map[string]any{
		"certificate_type": "host",
		"public_key":       publicKey,
		"key_id":           "edge-1.internal",
		"principals":       []string{"edge-1.internal", "edge-1.internal", "edge-1"},
		"ttl_seconds":      90_000,
	}

	issuedBefore := countSSHWorkflowEvents(t, h, "ssh.cert.issued")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/ssh/certificates/preview", token, request)
	if status != http.StatusOK {
		t.Fatalf("preview host certificate: status %d body %s", status, body)
	}
	var preview struct {
		Ready                bool              `json:"ready"`
		EffectFree           bool              `json:"effect_free"`
		CertificateType      string            `json:"certificate_type"`
		KeyID                string            `json:"key_id"`
		Principals           []string          `json:"principals"`
		RequestedTTLSeconds  int64             `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds  int64             `json:"effective_ttl_seconds"`
		TTLClamped           bool              `json:"ttl_clamped"`
		PublicKeyFingerprint string            `json:"public_key_fingerprint"`
		AuthorityFingerprint string            `json:"authority_fingerprint"`
		CriticalOptions      map[string]string `json:"critical_options"`
		Extensions           map[string]string `json:"extensions"`
		PreviewWrites        []string          `json:"preview_writes"`
		PreviewSignerCalls   []string          `json:"preview_signer_calls"`
		IssuanceWrites       []string          `json:"issuance_writes"`
		IssuanceSignerCalls  []string          `json:"issuance_signer_calls"`
		RecoverySteps        []string          `json:"recovery_steps"`
		SecretDataHandling   []string          `json:"secret_data_handling"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode SSH preview: %v (%s)", err, body)
	}
	if !preview.Ready || !preview.EffectFree || preview.CertificateType != "host" || preview.KeyID != "edge-1.internal" {
		t.Fatalf("bad SSH preview identity: %+v", preview)
	}
	if preview.RequestedTTLSeconds != 90_000 || preview.EffectiveTTLSeconds != 86_400 || !preview.TTLClamped {
		t.Fatalf("preview did not disclose the 24-hour TTL clamp: %+v", preview)
	}
	if len(preview.Principals) != 2 || preview.Principals[0] != "edge-1" || preview.Principals[1] != "edge-1.internal" {
		t.Fatalf("preview principals were not stable/deduplicated: %v", preview.Principals)
	}
	if preview.PublicKeyFingerprint == "" || preview.AuthorityFingerprint == "" ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewSignerCalls) != 0 ||
		len(preview.IssuanceWrites) == 0 || len(preview.IssuanceSignerCalls) == 0 ||
		len(preview.RecoverySteps) == 0 || len(preview.SecretDataHandling) == 0 {
		t.Fatalf("preview omitted proof/effect/recovery data: %+v", preview)
	}
	if got := countSSHWorkflowEvents(t, h, "ssh.cert.issued"); got != issuedBefore {
		t.Fatalf("effect-free preview emitted ssh.cert.issued: before=%d after=%d", issuedBefore, got)
	}
	if h.srv.protocols.ssh.KRLVersion() != 0 {
		t.Fatalf("effect-free preview changed KRL version to %d", h.srv.protocols.ssh.KRLVersion())
	}
	request["ttl_seconds"] = int64(1) << 62
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/ssh/certificates/preview", token, request)
	if status != http.StatusOK {
		t.Fatalf("preview overflow-sized TTL: status %d body %s", status, body)
	}
	var hugeTTL struct {
		EffectiveTTLSeconds int64 `json:"effective_ttl_seconds"`
		TTLClamped          bool  `json:"ttl_clamped"`
	}
	if err := json.Unmarshal(body, &hugeTTL); err != nil || hugeTTL.EffectiveTTLSeconds != 86_400 || !hugeTTL.TTLClamped {
		t.Fatalf("overflow-sized TTL was not safely clamped: err=%v preview=%+v body=%s", err, hugeTTL, body)
	}
	request["ttl_seconds"] = 90_000

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", token, "f43-host-issue", request)
	if status != http.StatusCreated {
		t.Fatalf("issue host certificate: status %d body %s", status, body)
	}
	first := append([]byte(nil), body...)
	var issued struct {
		Certificate     string            `json:"certificate"`
		CertificateType string            `json:"certificate_type"`
		Serial          uint64            `json:"serial"`
		KeyID           string            `json:"key_id"`
		Principals      []string          `json:"principals"`
		ValidBefore     string            `json:"valid_before"`
		Extensions      map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issued host certificate: %v (%s)", err, body)
	}
	if issued.Certificate == "" || issued.CertificateType != "host" || issued.Serial == 0 || issued.ValidBefore == "" {
		t.Fatalf("bad issued host certificate: %+v", issued)
	}
	parsed, _, _, _, err := xssh.ParseAuthorizedKey([]byte(issued.Certificate))
	if err != nil {
		t.Fatalf("parse issued host certificate: %v", err)
	}
	cert, ok := parsed.(*xssh.Certificate)
	if !ok || cert.CertType != xssh.HostCert || len(cert.ValidPrincipals) != 2 {
		t.Fatalf("issued key = %#v, want host certificate with two principals", parsed)
	}
	if got := countSSHWorkflowEvents(t, h, "ssh.cert.issued"); got != issuedBefore+1 {
		t.Fatalf("issue event count=%d, want %d", got, issuedBefore+1)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", token, "f43-host-issue", request)
	if status != http.StatusCreated || !bytes.Equal(body, first) {
		t.Fatalf("stable idempotent replay changed response: status %d first=%s replay=%s", status, first, body)
	}
	if got := countSSHWorkflowEvents(t, h, "ssh.cert.issued"); got != issuedBefore+1 {
		t.Fatalf("idempotent replay signed again: event count=%d", got)
	}

	userRequest := map[string]any{
		"certificate_type": "user",
		"public_key":       publicKey,
		"key_id":           "deployer@payments",
		"principals":       []string{"ops", "deployer", "ops"},
		"ttl_seconds":      900,
		"critical_options": map[string]string{
			"source-address": "10.0.0.19/24,10.0.0.0/24",
			"force-command":  "/usr/local/bin/deploy",
		},
		"extensions": map[string]string{"permit-X11-forwarding": ""},
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/ssh/certificates/preview", token, userRequest)
	if status != http.StatusOK {
		t.Fatalf("preview user certificate: status %d body %s", status, body)
	}
	var userPreview struct {
		CriticalOptions map[string]string `json:"critical_options"`
		Extensions      map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(body, &userPreview); err != nil {
		t.Fatalf("decode user preview: %v (%s)", err, body)
	}
	if userPreview.CriticalOptions["source-address"] != "10.0.0.0/24" || userPreview.CriticalOptions["force-command"] != "/usr/local/bin/deploy" {
		t.Fatalf("user preview did not normalize critical options: %+v", userPreview.CriticalOptions)
	}
	for _, extension := range []string{"permit-pty", "permit-user-rc", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"} {
		if _, ok := userPreview.Extensions[extension]; !ok {
			t.Fatalf("user preview omitted applied extension %q: %+v", extension, userPreview.Extensions)
		}
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", token, "f43-user-issue", userRequest)
	if status != http.StatusCreated {
		t.Fatalf("issue user certificate: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issued user certificate: %v (%s)", err, body)
	}
	parsed, _, _, _, err = xssh.ParseAuthorizedKey([]byte(issued.Certificate))
	if err != nil {
		t.Fatalf("parse issued user certificate: %v", err)
	}
	userCert, ok := parsed.(*xssh.Certificate)
	if !ok || userCert.CertType != xssh.UserCert || userCert.CriticalOptions["source-address"] != "10.0.0.0/24" ||
		userCert.CriticalOptions["force-command"] != "/usr/local/bin/deploy" {
		t.Fatalf("issued user certificate did not preserve reviewed constraints: %#v", parsed)
	}
	if got := countSSHWorkflowEvents(t, h, "ssh.cert.issued"); got != issuedBefore+2 {
		t.Fatalf("host and user issue event count=%d, want %d", got, issuedBefore+2)
	}
}

func TestServedSSHCertificatePreviewRejectsUnsafeOptions(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	publicKey := string(genSSHKey(t, filepath.Join(t.TempDir(), "id_ed25519")))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/ssh/certificates/preview", token, map[string]any{
		"certificate_type": "host",
		"public_key":       publicKey,
		"key_id":           "edge-1",
		"principals":       []string{"edge-1.internal"},
		"critical_options": map[string]string{"force-command": "/bin/sh"},
	})
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("host certificates do not allow critical options")) {
		t.Fatalf("unsafe host option should fail closed: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/ssh/certificates/preview", token, map[string]any{
		"certificate_type": "user",
		"public_key":       publicKey,
		"key_id":           "deployer",
		"principals":       []string{"deployer"},
		"critical_options": map[string]string{"source-address": "not-a-cidr"},
	})
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("must be an IP address or CIDR")) {
		t.Fatalf("invalid user source-address should fail closed: status %d body %s", status, body)
	}
}

func countSSHWorkflowEvents(t *testing.T, h *servedHarness, eventType string) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type == eventType {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay SSH workflow events: %v", err)
	}
	return count
}
