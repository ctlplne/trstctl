// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// TestServedNetworkDeviceSessionsA270: each of the five network device
// platforms is registered as a netdevice access target whose account is
// vaulted in an application secret its provider rotates. A reviewed session
// to each is delivered only through the access gateway: a stock ssh client
// holding no credential reaches the device through the CLI tunnel, the
// gateway signs in as the vaulted account with its password, the device runs
// the client's command as that account, and the sealed recording holds the
// command but never the password. Under a template's netdevice command rule
// blocking "write", the abbreviation "wr mem" is refused before the device
// sees it and is recorded as blocked evidence, and an interactive shell
// (whose typed lines are not inspected) is refused under the rule. The
// enable secret and a provider without an SSH route cannot be targets.
func TestServedNetworkDeviceSessionsA270(t *testing.T) {
	if testing.Short() {
		t.Skip("gateway session proof")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("the stock ssh client is required: %v", err)
	}
	type device struct {
		id, providerType string
		dialect          netdevicetest.Dialect
		apiDialect       netdevicetest.Dialect
		level, show      string
		ssh              *netdevicetest.Device
	}
	devices := []*device{
		{id: "core", providerType: "iosxe", dialect: netdevicetest.IOSXE, level: "privilege 15", show: "terminal length 0"},
		{id: "edge", providerType: "junos", dialect: netdevicetest.Junos, level: "super-user", show: "set cli screen-length 0"},
		{id: "leaf", providerType: "eos", dialect: netdevicetest.EOS, apiDialect: netdevicetest.EOS, level: "15", show: "show version"},
		{id: "fw", providerType: "fortigate", dialect: netdevicetest.FortiOS, apiDialect: netdevicetest.FortiOS, level: "super_admin", show: "get system status"},
		{id: "lb", providerType: "bigip", dialect: netdevicetest.BIGIP, apiDialect: netdevicetest.BIGIP, level: "admin", show: "show sys version"},
	}
	var configs []config.DynamicSecretProviderConfig
	for _, d := range devices {
		var err error
		if d.ssh, err = netdevicetest.Start(d.dialect, "netadmin", "admin-password-1", d.level); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.ssh.Close)
		d.ssh.AddAccount("ops", "ops-password-1", d.level)
		c := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: d.id + "-device", Type: d.providerType, Addr: d.ssh.Addr(),
			HostKeyFingerprint: d.ssh.FingerprintSHA256(), AdminUser: "netadmin", AllowedRoles: []string{"net/" + d.id},
			RoleBindings: map[string]string{"net/" + d.id: "ops"}, MaxTTL: "1h", AllowStaticRotation: true}
		if d.providerType == "iosxe" {
			c.AllowedRoles = append(c.AllowedRoles, "net/core-enable")
			c.RoleBindings["net/core-enable"] = "enable"
		}
		if d.apiDialect != "" {
			// The rotation side of an HTTPS device; sessions use its SSH.
			apiDevice, err := netdevicetest.StartAPI(d.apiDialect, "netadmin", "admin-password-1", d.level)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(apiDevice.Close)
			c.Endpoint, c.TLSCARef = apiDevice.URL(), writeServedCredentialFile(t, d.id+"-ca", string(apiDevice.CAPEM()))
			c.AllowPrivate, c.PrivateEgressCIDRs = true, []string{"127.0.0.1/32"}
		}
		if d.providerType == "fortigate" {
			c.APIKeyRef = writeServedCredentialFile(t, d.id+"-token", "admin-password-1")
		} else {
			c.PasswordRef = writeServedCredentialFile(t, d.id+"-admin", "admin-password-1")
		}
		configs = append(configs, c)
	}
	unrouted := configs[2]
	unrouted.ID, unrouted.Addr, unrouted.HostKeyFingerprint = "leaf-unrouted", "", ""
	unrouted.AllowedRoles, unrouted.RoleBindings = []string{"net/unrouted"}, map[string]string{"net/unrouted": "ops"}
	configs = append(configs, unrouted)
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &gatewayFixture{t: t, objects: s3test.NewServer(t), gatewayLog: &lockedBuffer{}, dir: t.TempDir()}
	if f.auditKey, err = jose.GenerateRSASigningKey("audit-export"); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.gatewayAddr = raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	kinds := []string{relay.KindAccessGatewayNetDeviceSession, relay.KindAccessGatewayNetDeviceRulesSession}
	f.h = newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleGateway}, kinds, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.ArchiveObjectStore = f.objects.Open(t)
		d.AuditSigningKey = f.auditKey
	})
	h := f.h
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a270", Status: "active",
		Executors: &transport.ExecutorReport{Version: "a270", Kinds: []transport.ExecutorKind{{Kind: relay.KindAccessGatewayNetDeviceSession}, {Kind: relay.KindAccessGatewayNetDeviceRulesSession}}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)
	f.requester = seedScopedTokenSubject(t, h.store, h.tenant, "a270-requester", "access:read", "access:write")
	f.reviewerOne = seedScopedTokenSubject(t, h.store, h.tenant, "a270-reviewer-one", "access:approve")
	f.reviewerTwo = seedScopedTokenSubject(t, h.store, h.tenant, "a270-reviewer-two", "access:approve")
	f.operator = seedScopedTokenSubject(t, h.store, h.tenant, "a270-operator", "access:read", "access:targets.write", "access:terminate")
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a270-custodian", "secrets:read", "secrets:write")

	register := func(key, id, provider, role string) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, key, map[string]any{
			"id": id, "target_type": "netdevice", "provider_id": provider, "allowed_roles": []string{role}, "account_secret": role,
			"gateway_agent_id": gatewayID, "gateway_address": f.gatewayAddr})
	}
	seed := func(name, username string) {
		t.Helper()
		value, _ := json.Marshal(map[string]string{"username": username, "password": "ops-password-1"})
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a270-seed-"+name,
			map[string]any{"name": name, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", name, status, body)
		}
	}
	seed("net/core-enable", "enable")
	seed("net/unrouted", "ops")
	if status, body := register("a270-enable-target", "core-enable", "core-device", "net/core-enable"); status == http.StatusCreated {
		t.Fatalf("the enable secret was registered as a session target: %s", body)
	}
	if status, body := register("a270-unrouted-target", "leaf-unrouted", "leaf-unrouted", "net/unrouted"); status == http.StatusCreated {
		t.Fatalf("a device with no SSH route was registered as a session target: %s", body)
	}
	revoke := func(id string) {
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/revoke", f.requester, "a270-revoke-"+id,
			map[string]any{"reason": "A270 proof complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke %s = %d %s", id, status, body)
		}
	}

	for _, d := range devices {
		role := "net/" + d.id
		seed(role, "ops")
		if status, body := register("a270-target-"+d.id, d.id+"-ops", d.id+"-device", role); status != http.StatusCreated ||
			!strings.Contains(string(body), `"target_type":"netdevice"`) {
			t.Fatalf("register %s = %d %s", d.id, status, body)
		}
	}
	// The gateway's server certificate names the address its targets bind.
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	f.gw, err = accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = f.gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = f.gw.Run(ctx) }()
	f.api = httptest.NewServer(h.srv.Handler())
	t.Cleanup(f.api.Close)

	for _, d := range devices {
		role := "net/" + d.id
		session := f.open("a270-open-"+d.id, map[string]any{"target_type": "netdevice", "target_id": d.id + "-ops", "role": role, "ttl_seconds": 120})
		if session.Delivery != "gateway" || session.Gateway == nil {
			t.Fatalf("%s: the session was not delivered through its gateway: %+v", d.id, session)
		}
		command, stop := f.sshTunnel(session)
		if output, err := command(d.show).CombinedOutput(); err != nil {
			stop()
			t.Fatalf("%s: %q through the gateway: %v %s (gateway: %s)", d.id, d.show, err, output, f.gatewayLog.String())
		}
		stop()
		if ran := d.ssh.Ran(); !slices.Contains(ran, d.show) {
			t.Fatalf("%s: the device ran %q", d.id, ran)
		}
		revoke(session.ID)
		a201Await(t, d.id+" recording seals", func() bool {
			status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
			return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
		})
		text := recordingText(t, h, session.ID)
		if !strings.Contains(text, d.show) || strings.Contains(text, "ops-password-1") || strings.Contains(text, "admin-password-1") {
			t.Fatalf("%s: the recording lacks the command or keeps a password:\n%s", d.id, text)
		}
	}

	// Command rules: block "write" on the IOS-XE device.
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a270-template", map[string]any{
		"name": "a270-device-maintenance", "reason": "Reviewed device maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": ruleID, "name": "No configuration saves", "enabled": true, "protocol": "netdevice", "operations": []string{"write"}, "effect": "block"}}})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save the netdevice rule = %d %s", status, body)
	}
	core := devices[0]
	session := f.open("a270-open-ruled", map[string]any{"target_type": "netdevice", "target_id": "core-ops", "role": "net/core", "ttl_seconds": 60, "template_id": template.ID})
	command, stop := f.sshTunnel(session)
	writesBefore := core.ssh.Writes()
	if output, err := command("wr mem").CombinedOutput(); err == nil {
		t.Fatalf("an abbreviated write escaped the device rule: %s", output)
	}
	if output, err := command("terminal length 0").CombinedOutput(); err != nil {
		t.Fatalf("an unruled command was refused: %v %s", err, output)
	}
	if output, err := command().CombinedOutput(); err == nil {
		t.Fatalf("an uninspected interactive shell was accepted under the rule: %s", output)
	}
	stop()
	if slices.Contains(core.ssh.Ran(), "wr mem") || core.ssh.Writes() != writesBefore {
		t.Fatal("the blocked command reached the device")
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("the device refusal evidence = %d %s", status, body)
	}
	var execBlocked, shellBlocked bool
	for _, item := range page.Items {
		switch {
		case item.Phase == "exec" && item.Status == "blocked" && slices.Equal(item.Operations, []string{"write"}) && slices.Equal(item.RuleIDs, []string{ruleID}) && item.Protocol == "netdevice":
			execBlocked = true
		case item.Phase == "control" && item.Status == "blocked" && item.Reason == "unsupported_control":
			shellBlocked = true
		}
	}
	if !execBlocked || !shellBlocked || len(page.Items) != 2 || strings.Contains(string(body), "wr mem") {
		t.Fatalf("the device refusal evidence = %s", body)
	}
	revoke(session.ID)
}
