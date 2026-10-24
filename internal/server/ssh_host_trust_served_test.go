// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/projections"
)

// hostTrustKey is a fixed OpenSSH host public key the tenant CA certifies.
const hostTrustKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt"

type hostTrustView struct {
	HostTrust struct {
		Summary struct {
			Hosts               int    `json:"hosts"`
			TenantCAConfigured  bool   `json:"tenant_ca_configured"`
			TenantCAFingerprint string `json:"tenant_ca_fingerprint"`
			ServedKRLSHA256     string `json:"served_krl_sha256"`
			TrustsTenantCA      int    `json:"trusts_tenant_ca"`
			TrustsOtherCAOnly   int    `json:"trusts_other_ca_only"`
			TenantHostCert      int    `json:"tenant_host_certificate"`
			EnforcesServedKRL   int    `json:"enforces_served_krl"`
			StandingKeysOn      int    `json:"standing_keys_on"`
		} `json:"summary"`
		Hosts []struct {
			AgentID          string `json:"agent_id"`
			Agent            string `json:"agent"`
			SSHDConfig       string `json:"sshd_config"`
			UserCA           string `json:"user_ca"`
			HostCertificate  string `json:"host_certificate"`
			HostCertificates []struct {
				Judgment          string   `json:"judgment"`
				SignatureVerified bool     `json:"signature_verified"`
				KeyID             string   `json:"key_id"`
				Principals        []string `json:"principals"`
			} `json:"host_certificates"`
			RevocationList string  `json:"revocation_list"`
			KRLVersion     *uint64 `json:"krl_version"`
			StandingKeys   string  `json:"standing_keys"`
			MatchBlocks    int     `json:"match_blocks"`
		} `json:"hosts"`
	} `json:"host_trust"`
}

func sshFleetHostTrust(t *testing.T, h *servedHarness, token string) (hostTrustView, []byte) {
	t.Helper()
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/ssh/fleet", token, nil)
	var view hostTrustView
	if code != http.StatusOK || json.Unmarshal(body, &view) != nil {
		t.Fatalf("SSH fleet = %d %s", code, body)
	}
	return view, body
}

// A115: each host agent's reported sshd posture is judged against this
// tenant's SSH CA and served KRL. The control plane names the host from the
// agent's certificate, not from the report; a host that trusts this CA,
// presents a certificate it signed and enforces the current list reads as
// under the CA; one trusting another CA, enforcing nothing and still allowing
// authorized_keys reads as outside it; a new revocation makes the first host's
// list another one until it reports again, and the newest report wins.
func TestServedSSHFleetJudgesEachHostsSSHDTrust(t *testing.T) {
	ctx := context.Background()
	h := newServedHarnessWithEventOptions(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		nil, withAgentChannel)
	registerServedTenant(t, h, "SSH host trust tenant")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	inside := enrollKRLAgent(t, h, ln.Addr().String(), "edge-1", []string{mtls.AgentRoleHost})
	outside := enrollKRLAgent(t, h, ln.Addr().String(), "edge-2", []string{mtls.AgentRoleHost})
	for _, a := range []*krlAgent{inside, outside} {
		if _, err := a.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", Version: "a115"}); err != nil {
			t.Fatalf("heartbeat %s: %v", a.name, err)
		}
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", "certs:issue")

	sp, err := h.srv.sshWorkflowProtocol(h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := sp.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := sshkeys.ParsePublicKey(authority)
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", token, "a115-host-cert", map[string]any{
		"certificate_type": "host", "public_key": hostTrustKey, "key_id": "edge-1 host", "principals": []string{"edge-1.example.test"}, "ttl_seconds": 86400,
	})
	var issued struct {
		Certificate string `json:"certificate"`
	}
	if status != http.StatusOK && status != http.StatusCreated || json.Unmarshal(body, &issued) != nil || issued.Certificate == "" {
		t.Fatalf("issue host certificate = %d %s", status, body)
	}
	cert, err := sshkeys.ParseCertificate([]byte(issued.Certificate))
	if err != nil || !cert.SignatureVerified || cert.CAFingerprintSHA256 != ca.FingerprintSHA256 {
		t.Fatalf("issued host certificate = %+v (%v)", cert, err)
	}
	served := servedKRL(t, h)
	servedVersion := strconv.FormatUint(sp.KRLVersion(), 10)

	certificates, err := json.Marshal([]map[string]any{{
		"path": "/etc/ssh/ssh_host_ed25519_key-cert.pub", "state": "certificate", "kind": cert.Kind,
		"ca_fingerprint": cert.CAFingerprintSHA256, "signature_verified": cert.SignatureVerified,
		"key_fingerprint": cert.KeyFingerprintSHA256, "key_id": cert.KeyID, "serial": cert.Serial, "principals": cert.Principals,
		"valid_after": cert.ValidAfter.Format(time.RFC3339), "valid_before": cert.ValidBefore.Format(time.RFC3339),
	}})
	if err != nil {
		t.Fatal(err)
	}
	report := func(a *krlAgent, meta map[string]string) {
		t.Helper()
		digest, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "ssh", Findings: []transport.InventoryFinding{{
			Kind: "ssh_trust", Ref: "/etc/ssh/sshd_config", Provenance: "ssh:sshd-trust:/etc/ssh/sshd_config",
			Fingerprint: crypto.SHA256Hex(digest), RiskScore: 20, Metadata: meta,
		}}})
		if err != nil || resp.Recorded != 1 {
			t.Fatalf("report %s posture = %+v (%v)", a.name, resp, err)
		}
	}
	insideMeta := map[string]string{
		"sshd_config": "/etc/ssh/sshd_config", "config_state": "read",
		"trusted_user_ca_keys": "/etc/ssh/trstctl/trusted_user_ca_keys", "trusted_ca_state": "read",
		"trusted_ca_fingerprints": ca.FingerprintSHA256,
		"revoked_keys":            "/etc/ssh/revoked_keys", "revocation_state": "krl", "krl_version": servedVersion,
		"revoked_keys_sha256": crypto.SHA256Hex(served), "host_certificates": string(certificates),
		"authorized_keys_file": "none", "authorized_principals_file": "none", "match_blocks": "0",
		// A report cannot name another host: the certificate does.
		"host": "spoofed-host", "agent_id": "00000000-0000-4000-8000-000000000000",
	}
	report(inside, insideMeta)
	report(outside, map[string]string{
		"sshd_config": "/etc/ssh/sshd_config", "config_state": "read",
		"trusted_user_ca_keys": "/etc/ssh/legacy_ca.pub", "trusted_ca_state": "read",
		"trusted_ca_fingerprints": "SHA256:eg0upccGdZXXLvQU+nKO1PwItOw1TX8CCe3NwH6DnLE",
		"revoked_keys":            "none", "revocation_state": "none", "host_certificates": "[]",
		"authorized_keys_file": ".ssh/authorized_keys .ssh/authorized_keys2", "authorized_principals_file": "none", "match_blocks": "1",
	})

	view, body := sshFleetHostTrust(t, h, token)
	s := view.HostTrust.Summary
	if !s.TenantCAConfigured || s.TenantCAFingerprint != ca.FingerprintSHA256 || s.ServedKRLSHA256 != crypto.SHA256Hex(served) ||
		s.Hosts != 2 || s.TrustsTenantCA != 1 || s.TrustsOtherCAOnly != 1 || s.TenantHostCert != 1 || s.EnforcesServedKRL != 1 || s.StandingKeysOn != 1 {
		t.Fatalf("host trust summary: %s", body)
	}
	byAgent := map[string]int{}
	for i, host := range view.HostTrust.Hosts {
		byAgent[host.Agent] = i
	}
	in, ok := byAgent["edge-1"]
	if !ok {
		t.Fatalf("edge-1 missing (a spoofed host name must not replace it): %s", body)
	}
	got := view.HostTrust.Hosts[in]
	if got.AgentID != agentRowID(h.tenant, "edge-1") || got.UserCA != "tenant_ca" || got.HostCertificate != "tenant_ca" ||
		got.RevocationList != "served" || got.KRLVersion == nil || got.StandingKeys != "off" || len(got.HostCertificates) != 1 ||
		got.HostCertificates[0].KeyID != "edge-1 host" || !got.HostCertificates[0].SignatureVerified {
		t.Fatalf("edge-1 judged: %s", body)
	}
	got = view.HostTrust.Hosts[byAgent["edge-2"]]
	if got.UserCA != "other_ca" || got.HostCertificate != "none" || got.RevocationList != "none" || got.StandingKeys != "on" || got.MatchBlocks != 1 {
		t.Fatalf("edge-2 judged: %s", body)
	}

	// A new revocation changes the served list: edge-1 now enforces another one.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", token, "a115-revoke", map[string]any{"serial": 99}); status != http.StatusOK {
		t.Fatalf("revoke = %d %s", status, body)
	}
	if view, body := sshFleetHostTrust(t, h, token); view.HostTrust.Hosts[in].RevocationList != "not_served" || view.HostTrust.Summary.EnforcesServedKRL != 0 {
		t.Fatalf("after a revocation: %s", body)
	}
	// It takes the new list and reports again; the newest posture wins.
	served = servedKRL(t, h)
	insideMeta["revoked_keys_sha256"], insideMeta["krl_version"] = crypto.SHA256Hex(served), strconv.FormatUint(sp.KRLVersion(), 10)
	report(inside, insideMeta)
	if view, body := sshFleetHostTrust(t, h, token); view.HostTrust.Hosts[in].RevocationList != "served" || view.HostTrust.Summary.Hosts != 2 {
		t.Fatalf("after the new report: %s", body)
	}
	// The postures are projected discovery findings: a rebuild reproduces the view.
	before, _ := sshFleetHostTrust(t, h, token)
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if after, body := sshFleetHostTrust(t, h, token); len(after.HostTrust.Hosts) != len(before.HostTrust.Hosts) ||
		after.HostTrust.Summary != before.HostTrust.Summary {
		t.Fatalf("rebuild changed the view: %s", body)
	}
}
