//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const dodConnectorTenant = "d0d00000-0000-4000-8000-000000000001"

const (
	dodConnectorAgentProcess    = "TRSTCTL_DOD_CONNECTOR_AGENT_PROCESS"
	dodConnectorAgentServerName = "connector-agent.trstctl.local"
	dodConnectorAgentHeartbeat  = "TRSTCTL_DOD_CONNECTOR_AGENT_HEARTBEAT_ONLY"
)

var dodConnectorAgentRuntimes sync.Map // map[*Server]*dodConnectorAgentRuntime

type dodConnectorAgentRuntime struct {
	address, commonName, serverName string
	caPath, keyPath, certPath       string
	hostProfilePaths                map[string]string
}

// TestDODNativeConnectorAgentProcessHelper is one poll of the shipped shared
// agent executor in a fresh OS process. It reloads an enrolled mTLS identity
// and an operator-owned host profile from disk; no certificate/key payload is
// copied through argv or the environment.
func TestDODNativeConnectorAgentProcessHelper(t *testing.T) {
	if os.Getenv(dodConnectorAgentProcess) != "1" {
		return
	}
	required := func(name string) string {
		t.Helper()
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("connector agent helper missing %s", name)
		}
		return value
	}
	caPEM, err := os.ReadFile(required("TRSTCTL_DOD_CONNECTOR_AGENT_CA_PATH")) // #nosec G304 -- parent-created public CA fixture (CWE-22)
	if err != nil {
		t.Fatalf("read connector agent CA: %v", err)
	}
	a := agent.New(agent.Config{
		CommonName: required("TRSTCTL_DOD_CONNECTOR_AGENT_COMMON_NAME"),
		KeyPath:    required("TRSTCTL_DOD_CONNECTOR_AGENT_KEY_PATH"), CertPath: required("TRSTCTL_DOD_CONNECTOR_AGENT_CERT_PATH"),
		ServerName: required("TRSTCTL_DOD_CONNECTOR_AGENT_SERVER_NAME"), ServerCAPEM: caPEM,
	}, nil)
	if err := a.Bootstrap(t.Context()); err != nil {
		t.Fatalf("reload connector agent identity: %v", err)
	}
	credentials, err := a.Credentials()
	if err != nil {
		t.Fatalf("connector agent credentials: %v", err)
	}
	connection, err := transport.Dial(required("TRSTCTL_DOD_CONNECTOR_AGENT_CHANNEL_ADDR"), credentials)
	if err != nil {
		t.Fatalf("dial connector agent channel: %v", err)
	}
	defer func() { _ = connection.Close() }()
	transportClient := transport.NewAgentClient(connection)
	if os.Getenv(dodConnectorAgentHeartbeat) == "1" {
		if _, err := transportClient.Heartbeat(t.Context(), &transport.HeartbeatRequest{
			AgentID: a.Identity().CommonName(), Version: "dod-connector-agent/1", Status: "active",
		}); err != nil {
			t.Fatalf("refresh connector agent heartbeat: %v", err)
		}
		return
	}
	hostProfile := connector.LocalOpsConfig{}
	if path := strings.TrimSpace(os.Getenv("TRSTCTL_DOD_CONNECTOR_AGENT_HOST_PROFILE")); path != "" {
		hostProfile, err = agentrelay.LoadHostProfile(path)
		if err != nil {
			t.Fatalf("load connector agent host profile: %v", err)
		}
	}
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	channel := &servedHostRelayChannel{client: transportClient, identity: a}
	executed, err := agentrelay.RunOnceWithHost(t.Context(), channel, client, hostProfile, 1, 60)
	if err != nil || executed != 1 || !channel.lastAccepted {
		t.Fatalf("connector agent pass = executed %d accepted %t err %v outcome=%q detail=%q",
			executed, channel.lastAccepted, err, channel.lastOutcome, channel.lastDetail)
	}
	if channel.lastOutcome != transport.JobOutcomeExecuted && channel.lastOutcome != transport.JobOutcomeVerified {
		t.Fatalf("connector agent outcome=%q detail=%q, want executed or verified", channel.lastOutcome, channel.lastDetail)
	}
}

type dodConnectorTarget struct {
	entryID      string
	connector    string
	external     *proof.ExternalSubstrate
	config       json.RawMessage
	target       string
	readbackPath string
}

type dodConnectorDispatchDiagnostic struct {
	inner   orchestrator.Handler
	mu      sync.Mutex
	classes map[string]string
}

func (d *dodConnectorDispatchDiagnostic) Deliver(ctx context.Context, message orchestrator.Message) error {
	err := d.inner.Deliver(ctx, message)
	if err == nil {
		return nil
	}
	d.mu.Lock()
	d.classes[message.Destination] = dodConnectorDispatchErrorClass(err.Error())
	d.mu.Unlock()
	return err
}

func (d *dodConnectorDispatchDiagnostic) DeliverTerminalFailure(ctx context.Context, message orchestrator.Message, cause error) error {
	terminal, ok := d.inner.(orchestrator.TerminalFailureHandler)
	if !ok {
		return nil
	}
	return terminal.DeliverTerminalFailure(ctx, message, cause)
}

func (d *dodConnectorDispatchDiagnostic) errorClass(destination string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if class := d.classes[destination]; class != "" {
		return class
	}
	return "none"
}

func dodConnectorDispatchErrorClass(raw string) string {
	value := strings.ToLower(raw)
	for _, candidate := range []struct {
		contains string
		class    string
	}{
		{"tenant cryptographic access unavailable", "tenant-custody"},
		{"load identity", "identity-load"},
		{"issuance admission", "issuance-admission"},
		{"signer unavailable", "signer-unavailable"},
		{"signer timed out", "signer-timeout"},
		{"issuance failed", "signer-issuance"},
		{"certificate profile", "certificate-profile"},
		{"record certificate", "certificate-record"},
		{"seal connector deploy", "connector-intent-seal"},
		{"transition", "lifecycle-transition"},
		{"crl", "crl"},
		{"tenant", "tenant-other"},
		{"sign", "signing-other"},
		{"certificate", "certificate-other"},
		{"owner", "owner"},
		{"idempot", "idempotency"},
		{"projection", "projection"},
		{"event", "event-log"},
		{"no rows", "not-found"},
		{"not found", "not-found"},
		{"uuid", "identifier"},
		{"policy", "policy"},
		{"approval", "approval"},
		{"state", "state"},
		{"postgres", "postgres"},
	} {
		if strings.Contains(value, candidate.contains) {
			return candidate.class
		}
	}
	return dodSecretIntegrationErrorClass(raw)
}

// dodRuntimeSelection makes a shared runtime test fail before starting any
// substrate when the gate accidentally gives it an entry owned by another
// group. An empty selection is the deliberate full-group mode.
func dodRuntimeSelection(t *testing.T, allowed ...string) string {
	t.Helper()
	only := proof.OnlyExpectation(t)
	if err := dodValidateRuntimeSelection(only, allowed); err != nil {
		t.Fatalf("DOD-CENSUS: %v", err)
	}
	return only
}

func dodValidateRuntimeSelection(only string, allowed []string) error {
	if len(allowed) == 0 {
		return fmt.Errorf("runtime proof group has no allowed entries")
	}
	seen := make(map[string]struct{}, len(allowed))
	for _, id := range allowed {
		if id == "" {
			return fmt.Errorf("runtime proof group contains an empty entry")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("runtime proof group contains duplicate entry %q", id)
		}
		seen[id] = struct{}{}
	}
	if only == "" {
		return nil
	}
	if _, ok := seen[only]; !ok {
		return fmt.Errorf("selected expectation %q is not owned by this runtime proof group", only)
	}
	return nil
}

func dodRuntimeEntrySelected(only, id string) bool {
	return only == "" || only == id
}

func TestRuntimeProofSelectionValidation(t *testing.T) {
	allowed := []string{"connector.nginx", "connector.apache"}
	for _, only := range []string{"", "connector.nginx", "connector.apache"} {
		if err := dodValidateRuntimeSelection(only, allowed); err != nil {
			t.Errorf("valid selection %q rejected: %v", only, err)
		}
	}
	for name, test := range map[string]struct {
		only    string
		allowed []string
	}{
		"foreign":   {only: "connector.envoy", allowed: allowed},
		"empty-set": {only: "connector.nginx"},
		"empty-id":  {allowed: []string{"connector.nginx", ""}},
		"duplicate": {allowed: []string{"connector.nginx", "connector.nginx"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := dodValidateRuntimeSelection(test.only, test.allowed); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
	if !dodRuntimeEntrySelected("", "connector.nginx") || !dodRuntimeEntrySelected("", "connector.apache") {
		t.Fatal("empty selection did not preserve full-group execution")
	}
	selected := 0
	for _, id := range allowed {
		if dodRuntimeEntrySelected("connector.nginx", id) {
			selected++
		}
	}
	if selected != 1 {
		t.Fatalf("focused selection matched %d entries, want exactly one", selected)
	}
}

// TestDODNativeConnectorsProductionAssembly is shared by the 25 granular
// connector census rows. A focused gate run starts exactly its selected
// substrate. A direct full-group run preserves the single-composition sweep.
func TestDODNativeConnectorsProductionAssembly(t *testing.T) {
	only := dodRuntimeSelection(t,
		"connector.registry", "connector.nginx", "connector.apache", "connector.caddy",
		"connector.envoy", "connector.iis", "connector.haproxy", "connector.f5",
		"connector.netscaler", "connector.a10", "connector.kemp", "connector.cisco",
		"connector.fortigate", "connector.paloalto", "connector.postfix", "connector.traefik",
		"connector.acm", "connector.azurekv", "connector.gcpcm", "connector.javakeystore",
		"connector.postgresql", "connector.mysql", "connector.rabbitmq",
		"connector.elasticsearch", "connector.tomcat",
	)
	if only == "" {
		dodRunAllNativeConnectorsProductionAssembly(t)
		return
	}
	if only == "connector.registry" {
		external := proof.StartCommand(t, "connector.registry")
		dodRunFocusedNativeConnector(t, "connector.registry", "a10", external)
		return
	}
	if only == "connector.nginx" {
		external := proof.StartCommand(t, "connector.nginx")
		dodRunFocusedNativeConnector(t, "connector.nginx", "nginx", external)
		return
	}
	if only == "connector.apache" {
		external := proof.StartCommand(t, "connector.apache")
		dodRunFocusedNativeConnector(t, "connector.apache", "apache", external)
		return
	}
	if only == "connector.caddy" {
		external := proof.StartCommand(t, "connector.caddy")
		dodRunFocusedNativeConnector(t, "connector.caddy", "caddy", external)
		return
	}
	if only == "connector.envoy" {
		external := proof.StartCommand(t, "connector.envoy")
		dodRunFocusedNativeConnector(t, "connector.envoy", "envoy", external)
		return
	}
	if only == "connector.iis" {
		external := proof.StartCommand(t, "connector.iis")
		dodRunFocusedNativeConnector(t, "connector.iis", "iis", external)
		return
	}
	if only == "connector.haproxy" {
		external := proof.StartCommand(t, "connector.haproxy")
		dodRunFocusedNativeConnector(t, "connector.haproxy", "haproxy", external)
		return
	}
	if only == "connector.f5" {
		external := proof.StartCommand(t, "connector.f5")
		dodRunFocusedNativeConnector(t, "connector.f5", "f5", external)
		return
	}
	if only == "connector.netscaler" {
		external := proof.StartCommand(t, "connector.netscaler")
		dodRunFocusedNativeConnector(t, "connector.netscaler", "netscaler", external)
		return
	}
	if only == "connector.a10" {
		external := proof.StartCommand(t, "connector.a10")
		dodRunFocusedNativeConnector(t, "connector.a10", "a10", external)
		return
	}
	if only == "connector.kemp" {
		external := proof.StartCommand(t, "connector.kemp")
		dodRunFocusedNativeConnector(t, "connector.kemp", "kemp", external)
		return
	}
	if only == "connector.cisco" {
		external := proof.StartCommand(t, "connector.cisco")
		dodRunFocusedNativeConnector(t, "connector.cisco", "cisco", external)
		return
	}
	if only == "connector.fortigate" {
		external := proof.StartCommand(t, "connector.fortigate")
		dodRunFocusedNativeConnector(t, "connector.fortigate", "fortigate", external)
		return
	}
	if only == "connector.paloalto" {
		external := proof.StartCommand(t, "connector.paloalto")
		dodRunFocusedNativeConnector(t, "connector.paloalto", "paloalto", external)
		return
	}
	if only == "connector.postfix" {
		external := proof.StartCommand(t, "connector.postfix")
		dodRunFocusedNativeConnector(t, "connector.postfix", "postfix", external)
		return
	}
	if only == "connector.traefik" {
		external := proof.StartCommand(t, "connector.traefik")
		dodRunFocusedNativeConnector(t, "connector.traefik", "traefik", external)
		return
	}
	if only == "connector.acm" {
		external := proof.StartCommand(t, "connector.acm")
		dodRunFocusedNativeConnector(t, "connector.acm", "aws-acm", external)
		return
	}
	if only == "connector.azurekv" {
		external := proof.StartCommand(t, "connector.azurekv")
		dodRunFocusedNativeConnector(t, "connector.azurekv", "azure-keyvault", external)
		return
	}
	if only == "connector.gcpcm" {
		external := proof.StartCommand(t, "connector.gcpcm")
		dodRunFocusedNativeConnector(t, "connector.gcpcm", "gcp-certificate-manager", external)
		return
	}
	if only == "connector.javakeystore" {
		external := proof.StartCommand(t, "connector.javakeystore")
		dodRunFocusedNativeConnector(t, "connector.javakeystore", "java-keystore", external)
		return
	}
	if only == "connector.postgresql" {
		external := proof.StartCommand(t, "connector.postgresql")
		dodRunFocusedNativeConnector(t, "connector.postgresql", "postgresql", external)
		return
	}
	if only == "connector.mysql" {
		external := proof.StartCommand(t, "connector.mysql")
		dodRunFocusedNativeConnector(t, "connector.mysql", "mysql", external)
		return
	}
	if only == "connector.rabbitmq" {
		external := proof.StartCommand(t, "connector.rabbitmq")
		dodRunFocusedNativeConnector(t, "connector.rabbitmq", "rabbitmq", external)
		return
	}
	if only == "connector.elasticsearch" {
		external := proof.StartCommand(t, "connector.elasticsearch")
		dodRunFocusedNativeConnector(t, "connector.elasticsearch", "elasticsearch", external)
		return
	}
	external := proof.StartCommand(t, "connector.tomcat")
	dodRunFocusedNativeConnector(t, "connector.tomcat", "tomcat", external)
}

func dodRunAllNativeConnectorsProductionAssembly(t *testing.T) {
	registryExternal := proof.StartCommand(t, "connector.registry")
	nginxExternal := proof.StartCommand(t, "connector.nginx")
	apacheExternal := proof.StartCommand(t, "connector.apache")
	caddyExternal := proof.StartCommand(t, "connector.caddy")
	envoyExternal := proof.StartCommand(t, "connector.envoy")
	iisExternal := proof.StartCommand(t, "connector.iis")
	haproxyExternal := proof.StartCommand(t, "connector.haproxy")
	f5External := proof.StartCommand(t, "connector.f5")
	netscalerExternal := proof.StartCommand(t, "connector.netscaler")
	a10External := proof.StartCommand(t, "connector.a10")
	kempExternal := proof.StartCommand(t, "connector.kemp")
	ciscoExternal := proof.StartCommand(t, "connector.cisco")
	fortigateExternal := proof.StartCommand(t, "connector.fortigate")
	paloaltoExternal := proof.StartCommand(t, "connector.paloalto")
	postfixExternal := proof.StartCommand(t, "connector.postfix")
	traefikExternal := proof.StartCommand(t, "connector.traefik")
	acmExternal := proof.StartCommand(t, "connector.acm")
	azureExternal := proof.StartCommand(t, "connector.azurekv")
	gcpExternal := proof.StartCommand(t, "connector.gcpcm")
	javaExternal := proof.StartCommand(t, "connector.javakeystore")
	postgresExternal := proof.StartCommand(t, "connector.postgresql")
	mysqlExternal := proof.StartCommand(t, "connector.mysql")
	rabbitExternal := proof.StartCommand(t, "connector.rabbitmq")
	elasticExternal := proof.StartCommand(t, "connector.elasticsearch")
	tomcatExternal := proof.StartCommand(t, "connector.tomcat")
	productionEndpoints := map[*proof.ExternalSubstrate]string{}
	productionEndpoint := func(external *proof.ExternalSubstrate) string {
		if endpoint := productionEndpoints[external]; endpoint != "" {
			return endpoint
		}
		endpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
		productionEndpoints[external] = endpoint
		return endpoint
	}

	local := map[string]struct {
		external *proof.ExternalSubstrate
		logical  []string
	}{
		"nginx":         {nginxExternal, []string{"nginx"}},
		"apache":        {apacheExternal, []string{"apachectl"}},
		"caddy":         {caddyExternal, []string{"caddy"}},
		"iis":           {iisExternal, []string{"powershell", "netsh"}},
		"haproxy":       {haproxyExternal, []string{"haproxy", "systemctl"}},
		"postfix":       {postfixExternal, []string{"postfix", "doveconf", "doveadm"}},
		"traefik":       {traefikExternal, nil},
		"java-keystore": {javaExternal, nil},
		"postgresql":    {postgresExternal, []string{"pg_ctl"}},
		"mysql":         {mysqlExternal, []string{"mysql-tls-reload"}},
		"rabbitmq":      {rabbitExternal, []string{"rabbitmqctl"}},
		"elasticsearch": {elasticExternal, nil},
		"tomcat":        {tomcatExternal, []string{"catalina.sh"}},
	}

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	dodConfigureConnectorAgent(cfg, t.TempDir())
	cfg.Connectors.Enabled = append([]string(nil), config.NativeConnectorNames...)
	cfg.Connectors.AllowPrivateCIDRs = []string{"127.0.0.0/8"}
	cfg.Connectors.AllowInsecureHTTP = true
	cfg.Connectors.LocalProfiles = map[string]config.LocalConnectorProfile{}
	roots := map[string]string{}
	for name, item := range local {
		root := dodConnectorExternalRoot(t, item.external)
		roots[name] = root
		endpoint := ""
		if len(item.logical) != 0 {
			endpoint = productionEndpoint(item.external)
		}
		cfg.Connectors.LocalProfiles[name] = dodConnectorLocalProfile(t, root, endpoint, "connector."+manifestConnectorID(name), item.logical)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	t.Cleanup(runSecrets.Close)
	dodSeedConnectorSecrets(t, st, runSecrets.kek)
	signer := dodConnectorSigner(t)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dodStartConnectorAgentRuntime(t, srv, cfg.Connectors.LocalProfiles)
	token := dodSeedConnectorToken(t, st)
	ownerID := dodConnectorCreateOwner(t, srv, token)

	registryCfg := dodJSON(t, map[string]any{"endpoint": productionEndpoint(registryExternal), "username": "dod-user", "password_ref": "secret://dod/password"})
	dodRunConnector(t, "connector.registry", "a10", registryExternal, srv, token, ownerID, registryCfg, "dod-target", "")
	dodRunConnector(t, "connector.nginx", "nginx", nginxExternal, srv, token, ownerID, dodPairConfig(t, "nginx", roots["nginx"]), "dod-target", filepath.Join(roots["nginx"], "server.crt"))
	dodRunConnector(t, "connector.apache", "apache", apacheExternal, srv, token, ownerID, dodPairConfig(t, "apache", roots["apache"]), "dod-target", filepath.Join(roots["apache"], "server.crt"))
	dodRunConnector(t, "connector.caddy", "caddy", caddyExternal, srv, token, ownerID, dodPairConfig(t, "caddy", roots["caddy"]), "dod-target", filepath.Join(roots["caddy"], "server.crt"))
	dodRunConnector(t, "connector.envoy", "envoy", envoyExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(envoyExternal), "secret_name": "dod-secret"}), "dod-target", "")
	iisImport := filepath.Join(roots["iis"], "import")
	if err := os.MkdirAll(iisImport, 0o700); err != nil {
		t.Fatal(err)
	}
	dodRunConnector(t, "connector.iis", "iis", iisExternal, srv, token, ownerID, dodJSON(t, map[string]any{"profile": "iis", "binding": "0.0.0.0:443", "import_dir": iisImport}), "dod-target", "")
	dodRunConnector(t, "connector.haproxy", "haproxy", haproxyExternal, srv, token, ownerID, dodJSON(t, map[string]any{"profile": "haproxy", "crt_path": filepath.Join(roots["haproxy"], "bundle.pem"), "config_path": filepath.Join(roots["haproxy"], "haproxy.cfg")}), "dod-target", filepath.Join(roots["haproxy"], "bundle.pem"))
	dodRunConnector(t, "connector.f5", "f5", f5External, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(f5External), "client_ssl_profile": "dod-profile", "object_name": "dod-object", "username": "dod-user", "password_ref": "secret://dod/password"}), "dod-target", "")
	dodRunConnector(t, "connector.netscaler", "netscaler", netscalerExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(netscalerExternal), "username": "dod-user", "password_ref": "secret://dod/password"}), "dod-target", "")
	dodRunConnector(t, "connector.a10", "a10", a10External, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(a10External), "username": "dod-user", "password_ref": "secret://dod/password"}), "dod-target", "")
	dodRunConnector(t, "connector.kemp", "kemp", kempExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(kempExternal), "token_ref": "secret://dod/token"}), "dod-target", "")
	dodRunConnector(t, "connector.cisco", "cisco", ciscoExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(ciscoExternal), "username": "dod-user", "password_ref": "secret://dod/password"}), "dod-target", "")
	dodRunConnector(t, "connector.fortigate", "fortigate", fortigateExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(fortigateExternal), "token_ref": "secret://dod/token"}), "dod-target", "")
	dodRunConnector(t, "connector.paloalto", "paloalto", paloaltoExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(paloaltoExternal), "api_key_ref": "secret://dod/api-key"}), "dod-target", "")
	postfixCfg := dodJSON(t, map[string]any{"profile": "postfix", "postfix_cert_path": filepath.Join(roots["postfix"], "postfix.crt"), "postfix_key_path": filepath.Join(roots["postfix"], "postfix.key"), "dovecot_cert_path": filepath.Join(roots["postfix"], "dovecot.crt"), "dovecot_key_path": filepath.Join(roots["postfix"], "dovecot.key")})
	dodRunConnector(t, "connector.postfix", "postfix", postfixExternal, srv, token, ownerID, postfixCfg, "dod-target", filepath.Join(roots["postfix"], "postfix.crt"))
	dodRunConnector(t, "connector.traefik", "traefik", traefikExternal, srv, token, ownerID, dodTraefikConfig(t, roots["traefik"]), "dod-target", filepath.Join(roots["traefik"], "server.crt"))
	dodRunConnector(t, "connector.acm", "aws-acm", acmExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(acmExternal), "region": "us-east-1", "access_key_id": "AKIADODTEST", "secret_access_key_ref": "secret://dod/aws-secret"}), "arn:aws:acm:us-east-1:123456789012:certificate/dod", "")
	dodRunConnector(t, "connector.azurekv", "azure-keyvault", azureExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(azureExternal), "bearer_token_ref": "secret://dod/bearer"}), "dod-target", "")
	dodRunConnector(t, "connector.gcpcm", "gcp-certificate-manager", gcpExternal, srv, token, ownerID, dodJSON(t, map[string]any{"endpoint": productionEndpoint(gcpExternal), "project": "dod-project", "location": "global", "bearer_token_ref": "secret://dod/bearer", "poll_interval": "1ms"}), "dod-target", "")
	javaPath := filepath.Join(roots["java-keystore"], "keystore.p12")
	dodRunConnector(t, "connector.javakeystore", "java-keystore", javaExternal, srv, token, ownerID, dodJSON(t, map[string]any{"profile": "java-keystore", "keystore_path": javaPath, "keystore_password_ref": "secret://dod/password", "alias": "dod", "format": "pkcs12"}), "dod-target", javaPath)
	dodRunConnector(t, "connector.postgresql", "postgresql", postgresExternal, srv, token, ownerID, dodPairConfig(t, "postgresql", roots["postgresql"]), "dod-target", filepath.Join(roots["postgresql"], "server.crt"))
	dodRunConnector(t, "connector.mysql", "mysql", mysqlExternal, srv, token, ownerID, dodPairConfig(t, "mysql", roots["mysql"]), "dod-target", filepath.Join(roots["mysql"], "server.crt"))
	dodRunConnector(t, "connector.rabbitmq", "rabbitmq", rabbitExternal, srv, token, ownerID, dodPairConfig(t, "rabbitmq", roots["rabbitmq"]), "dod-target", filepath.Join(roots["rabbitmq"], "server.crt"))
	dodRunConnector(t, "connector.elasticsearch", "elasticsearch", elasticExternal, srv, token, ownerID, dodPairConfig(t, "elasticsearch", roots["elasticsearch"]), "dod-target", filepath.Join(roots["elasticsearch"], "server.crt"))
	dodRunConnector(t, "connector.tomcat", "tomcat", tomcatExternal, srv, token, ownerID, dodPairConfig(t, "tomcat", roots["tomcat"]), "dod-target", filepath.Join(roots["tomcat"], "server.crt"))
}

func dodRunFocusedNativeConnector(t *testing.T, entryID, connectorName string, external *proof.ExternalSubstrate) {
	t.Helper()
	productionEndpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	dodConfigureConnectorAgent(cfg, t.TempDir())
	cfg.Connectors.Enabled = append([]string(nil), config.NativeConnectorNames...)
	cfg.Connectors.AllowPrivateCIDRs = []string{"127.0.0.0/8"}
	cfg.Connectors.AllowInsecureHTTP = true
	cfg.Connectors.LocalProfiles = map[string]config.LocalConnectorProfile{}

	target := "dod-target"
	readbackPath := ""
	var targetConfig json.RawMessage
	local := func(profile string, logical []string) string {
		root := dodConnectorExternalRoot(t, external)
		endpoint := ""
		if len(logical) != 0 {
			endpoint = productionEndpoint
		}
		cfg.Connectors.LocalProfiles[profile] = dodConnectorLocalProfile(t, root, endpoint, entryID, logical)
		return root
	}
	switch entryID {
	case "connector.registry":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "username": "dod-user", "password_ref": "secret://dod/password"})
	case "connector.nginx":
		root := local("nginx", []string{"nginx"})
		targetConfig, readbackPath = dodPairConfig(t, "nginx", root), filepath.Join(root, "server.crt")
	case "connector.apache":
		root := local("apache", []string{"apachectl"})
		targetConfig, readbackPath = dodPairConfig(t, "apache", root), filepath.Join(root, "server.crt")
	case "connector.caddy":
		root := local("caddy", []string{"caddy"})
		targetConfig, readbackPath = dodPairConfig(t, "caddy", root), filepath.Join(root, "server.crt")
	case "connector.envoy":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "secret_name": "dod-secret"})
	case "connector.iis":
		root := local("iis", []string{"powershell", "netsh"})
		importDir := filepath.Join(root, "import")
		if err := os.MkdirAll(importDir, 0o700); err != nil {
			t.Fatal(err)
		}
		targetConfig = dodJSON(t, map[string]any{"profile": "iis", "binding": "0.0.0.0:443", "import_dir": importDir})
	case "connector.haproxy":
		root := local("haproxy", []string{"haproxy", "systemctl"})
		readbackPath = filepath.Join(root, "bundle.pem")
		targetConfig = dodJSON(t, map[string]any{"profile": "haproxy", "crt_path": readbackPath, "config_path": filepath.Join(root, "haproxy.cfg")})
	case "connector.f5":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "client_ssl_profile": "dod-profile", "object_name": "dod-object", "username": "dod-user", "password_ref": "secret://dod/password"})
	case "connector.netscaler":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "username": "dod-user", "password_ref": "secret://dod/password"})
	case "connector.a10":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "username": "dod-user", "password_ref": "secret://dod/password"})
	case "connector.kemp":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "token_ref": "secret://dod/token"})
	case "connector.cisco":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "username": "dod-user", "password_ref": "secret://dod/password"})
	case "connector.fortigate":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "token_ref": "secret://dod/token"})
	case "connector.paloalto":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "api_key_ref": "secret://dod/api-key"})
	case "connector.postfix":
		root := local("postfix", []string{"postfix", "doveconf", "doveadm"})
		readbackPath = filepath.Join(root, "postfix.crt")
		targetConfig = dodJSON(t, map[string]any{"profile": "postfix", "postfix_cert_path": readbackPath, "postfix_key_path": filepath.Join(root, "postfix.key"), "dovecot_cert_path": filepath.Join(root, "dovecot.crt"), "dovecot_key_path": filepath.Join(root, "dovecot.key")})
	case "connector.traefik":
		root := local("traefik", nil)
		targetConfig, readbackPath = dodTraefikConfig(t, root), filepath.Join(root, "server.crt")
	case "connector.acm":
		target = "arn:aws:acm:us-east-1:123456789012:certificate/dod"
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "region": "us-east-1", "access_key_id": "AKIADODTEST", "secret_access_key_ref": "secret://dod/aws-secret"})
	case "connector.azurekv":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "bearer_token_ref": "secret://dod/bearer"})
	case "connector.gcpcm":
		targetConfig = dodJSON(t, map[string]any{"endpoint": productionEndpoint, "project": "dod-project", "location": "global", "bearer_token_ref": "secret://dod/bearer", "poll_interval": "1ms"})
	case "connector.javakeystore":
		root := local("java-keystore", nil)
		readbackPath = filepath.Join(root, "keystore.p12")
		targetConfig = dodJSON(t, map[string]any{"profile": "java-keystore", "keystore_path": readbackPath, "keystore_password_ref": "secret://dod/password", "alias": "dod", "format": "pkcs12"})
	case "connector.postgresql":
		root := local("postgresql", []string{"pg_ctl"})
		targetConfig, readbackPath = dodPairConfig(t, "postgresql", root), filepath.Join(root, "server.crt")
	case "connector.mysql":
		root := local("mysql", []string{"mysql-tls-reload"})
		targetConfig, readbackPath = dodPairConfig(t, "mysql", root), filepath.Join(root, "server.crt")
	case "connector.rabbitmq":
		root := local("rabbitmq", []string{"rabbitmqctl"})
		targetConfig, readbackPath = dodPairConfig(t, "rabbitmq", root), filepath.Join(root, "server.crt")
	case "connector.elasticsearch":
		root := local("elasticsearch", nil)
		targetConfig, readbackPath = dodPairConfig(t, "elasticsearch", root), filepath.Join(root, "server.crt")
	case "connector.tomcat":
		root := local("tomcat", []string{"catalina.sh"})
		targetConfig, readbackPath = dodPairConfig(t, "tomcat", root), filepath.Join(root, "server.crt")
	default:
		t.Fatalf("focused connector proof has no configuration for %q", entryID)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	t.Cleanup(runSecrets.Close)
	dodSeedConnectorSecrets(t, st, runSecrets.kek)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, dodConnectorSigner(t), runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dodStartConnectorAgentRuntime(t, srv, cfg.Connectors.LocalProfiles)
	token := dodSeedConnectorToken(t, st)
	ownerID := dodConnectorCreateOwner(t, srv, token)
	dodRunConnector(t, entryID, connectorName, external, srv, token, ownerID, targetConfig, target, readbackPath)
}

func manifestConnectorID(name string) string {
	switch name {
	case "aws-acm":
		return "acm"
	case "azure-keyvault":
		return "azurekv"
	case "gcp-certificate-manager":
		return "gcpcm"
	case "java-keystore":
		return "javakeystore"
	default:
		return name
	}
}

func dodConnectorLocalProfile(t *testing.T, root, endpoint, entryID string, logical []string) config.LocalConnectorProfile {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(repo, "tools", "dodcensus", "substrates", "connector_target.py")
	profile := config.LocalConnectorProfile{AllowedRoots: []string{root}}
	for _, name := range logical {
		profile.Actions = append(profile.Actions, config.LocalConnectorAction{
			LogicalName: name, Command: command, PassArgs: true,
			Args:    []string{"signal", "--endpoint", endpoint, "--entry", entryID, "--logical", name, "--"},
			Timeout: "5s",
		})
	}
	return profile
}

func dodConfigureConnectorAgent(cfg *config.Config, dir string) {
	cfg.AgentChannel.Enabled = true
	cfg.AgentChannel.CACertFile = filepath.Join(dir, "agent-ca.crt")
	cfg.AgentChannel.ServerName = dodConnectorAgentServerName
	cfg.AgentChannel.HeartbeatInterval = "30s"
	cfg.AgentChannel.ClaimableJobKinds = []string{"connector.deploy", "connector.test"}
}

func dodStartConnectorAgentRuntime(
	t *testing.T,
	srv *Server,
	profiles map[string]config.LocalConnectorProfile,
) *dodConnectorAgentRuntime {
	t.Helper()
	if !srv.AgentChannelServed() || !srv.OutOfProcessAgentCA() {
		t.Fatal("connector proof did not assemble the signer-custodied agent mTLS channel")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for connector agent channel: %v", err)
	}
	channelCtx, stopChannel := context.WithCancel(context.Background())
	channelDone := make(chan struct{})
	go func() {
		defer close(channelDone)
		srv.serveAgentChannel(channelCtx, listener)
	}()
	t.Cleanup(func() {
		stopChannel()
		<-channelDone
	})

	const commonName = "dod-native-connector-agent"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bootstrapToken, err := srv.agentEnroll.IssueBootstrapTokenWithRoles(ctx, dodConnectorTenant, commonName,
		[]string{mtls.AgentRoleHost, mtls.AgentRoleNetwork})
	if err != nil {
		t.Fatalf("issue connector agent bootstrap token: %v", err)
	}
	a := agent.New(agent.Config{
		CommonName: commonName, BootstrapToken: bootstrapToken,
		ServerName: dodConnectorAgentServerName, ServerCAPEM: srv.AgentCACertPEM(), Version: "dod-connector-agent/1",
	}, &dodConnectorBootstrapEnroller{authority: srv.agentEnroll})
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap connector agent: %v", err)
	}
	credentials, err := a.Credentials()
	if err != nil {
		t.Fatalf("connector agent credentials: %v", err)
	}
	connection, err := transport.Dial(listener.Addr().String(), credentials)
	if err != nil {
		t.Fatalf("dial connector agent channel for heartbeat: %v", err)
	}
	client := transport.NewAgentClient(connection)
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: commonName, Version: "dod-connector-agent/1", Status: "active",
	}); err != nil {
		_ = connection.Close()
		t.Fatalf("heartbeat connector agent roles: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close connector agent heartbeat connection: %v", err)
	}

	dir := t.TempDir()
	runtime := &dodConnectorAgentRuntime{
		address: listener.Addr().String(), commonName: commonName, serverName: dodConnectorAgentServerName,
		caPath: filepath.Join(dir, "agent-ca.crt"), keyPath: filepath.Join(dir, "agent.key"),
		certPath: filepath.Join(dir, "agent.crt"), hostProfilePaths: map[string]string{},
	}
	if err := a.Identity().Save(runtime.keyPath, runtime.certPath); err != nil {
		t.Fatalf("persist connector agent identity: %v", err)
	}
	if err := os.WriteFile(runtime.caPath, srv.AgentCACertPEM(), 0o644); err != nil { // #nosec G306 -- public CA fixture (CWE-276)
		t.Fatalf("persist connector agent CA: %v", err)
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		hostProfile, err := dodConnectorHostProfile(profiles[name])
		if err != nil {
			t.Fatalf("build %s connector agent host profile: %v", name, err)
		}
		hostProfilePath := filepath.Join(dir, "host-profile-"+manifestConnectorID(name)+".json")
		profileJSON, err := json.Marshal(hostProfile)
		if err != nil {
			t.Fatalf("marshal %s connector agent host profile: %v", name, err)
		}
		if err := os.WriteFile(hostProfilePath, profileJSON, 0o600); err != nil {
			t.Fatalf("persist %s connector agent host profile: %v", name, err)
		}
		runtime.hostProfilePaths[name] = hostProfilePath
	}
	dodConnectorAgentRuntimes.Store(srv, runtime)
	t.Cleanup(func() { dodConnectorAgentRuntimes.Delete(srv) })
	return runtime
}

type dodConnectorBootstrapEnroller struct {
	authority interface {
		EnrollBootstrap(context.Context, []byte, []byte) ([]byte, error)
	}
}

func (e *dodConnectorBootstrapEnroller) EnrollBootstrap(ctx context.Context, token, csrDER []byte) ([]byte, error) {
	return e.authority.EnrollBootstrap(ctx, token, csrDER)
}

func (*dodConnectorBootstrapEnroller) EnrollRenewal(context.Context, []byte) ([]byte, error) {
	return nil, context.Canceled
}

func dodConnectorHostProfile(configured config.LocalConnectorProfile) (agentrelay.HostProfile, error) {
	profile := agentrelay.HostProfile{}
	profile.AllowedRoots = append(profile.AllowedRoots, configured.AllowedRoots...)
	for _, action := range configured.Actions {
		timeout, err := action.TimeoutDuration()
		if err != nil {
			return agentrelay.HostProfile{}, err
		}
		seconds := int(timeout / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		profile.Actions = append(profile.Actions, agentrelay.HostAction{
			LogicalName: action.LogicalName, LogicalArgs: action.LogicalArgs,
			Command: action.Command, Args: action.Args, PassArgs: action.PassArgs, TimeoutSecs: seconds,
		})
	}
	return profile, nil
}

func (r *dodConnectorAgentRuntime) run(t *testing.T, connectorName string) error {
	return r.runHelper(t, connectorName, false)
}

func (r *dodConnectorAgentRuntime) heartbeat(t *testing.T) error {
	return r.runHelper(t, "", true)
}

func (r *dodConnectorAgentRuntime) runHelper(t *testing.T, connectorName string, heartbeatOnly bool) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDODNativeConnectorAgentProcessHelper$", "-test.v") // #nosec G204,G702 -- fixed current test binary and fixed argv (CWE-78).
	cmd.Env = append(os.Environ(),
		dodConnectorAgentProcess+"=1",
		"TRSTCTL_DOD_CONNECTOR_AGENT_CA_PATH="+r.caPath,
		"TRSTCTL_DOD_CONNECTOR_AGENT_COMMON_NAME="+r.commonName,
		"TRSTCTL_DOD_CONNECTOR_AGENT_KEY_PATH="+r.keyPath,
		"TRSTCTL_DOD_CONNECTOR_AGENT_CERT_PATH="+r.certPath,
		"TRSTCTL_DOD_CONNECTOR_AGENT_SERVER_NAME="+r.serverName,
		"TRSTCTL_DOD_CONNECTOR_AGENT_CHANNEL_ADDR="+r.address,
		"TRSTCTL_DOD_CONNECTOR_AGENT_HOST_PROFILE="+r.hostProfilePaths[connectorName],
	)
	if heartbeatOnly {
		cmd.Env = append(cmd.Env, dodConnectorAgentHeartbeat+"=1")
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("separate connector agent process: %w\n%s", err, output)
	}
	return nil
}

func dodConnectorFailureDiagnostic(external *proof.ExternalSubstrate) string {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(external.Endpoint() + "/dod/diagnostic")
	if err != nil {
		return "diagnostic unavailable: " + err.Error()
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if err != nil {
		return "diagnostic unreadable: " + err.Error()
	}
	return fmt.Sprintf("status=%d body=%s", response.StatusCode, body)
}

func dodConnectorExternalRoot(t *testing.T, external *proof.ExternalSubstrate) string {
	t.Helper()
	response, err := http.Get(external.Endpoint() + "/dod/config")
	if err != nil {
		t.Fatalf("read connector substrate config: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var body struct {
		Root string `json:"root"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&body) != nil || body.Root == "" {
		t.Fatalf("invalid connector substrate config response")
	}
	return body.Root
}

func dodPairConfig(t *testing.T, profile, root string) json.RawMessage {
	t.Helper()
	return dodJSON(t, map[string]any{
		"profile": profile, "cert_path": filepath.Join(root, "server.crt"), "key_path": filepath.Join(root, "server.key"),
	})
}

func dodTraefikConfig(t *testing.T, root string) json.RawMessage {
	t.Helper()
	configPath := filepath.Join(root, "dynamic.yml")
	config := []byte("tls:\n  certificates: []\n")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatalf("write Traefik file-provider fixture: %v", err)
	}
	return dodJSON(t, map[string]any{
		"profile": "traefik", "cert_path": filepath.Join(root, "server.crt"),
		"key_path": filepath.Join(root, "server.key"), "config_path": configPath,
	})
}

func dodJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dodConnectorSigner(t *testing.T) runSigner {
	t.Helper()
	return dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
}

func dodSeedConnectorToken(t *testing.T, st *store.Store) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: dodConnectorTenant, TokenHash: hash, Subject: "dod-connector-operator",
		Scopes: []string{
			string(authz.OwnersRead), string(authz.OwnersWrite),
			string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
			string(authz.CertsRead), string(authz.CertsIssue),
			string(authz.ConnectorsRead), string(authz.ConnectorsWrite),
		},
	}); err != nil {
		secret.Wipe(raw)
		t.Fatal(err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}

func dodSeedConnectorSecrets(t *testing.T, st *store.Store, kek seal.KeyWrapper) {
	t.Helper()
	values := map[string][]byte{
		"dod/password":   []byte("dod-password-connector"),
		"dod/token":      []byte("dod-token-connector"),
		"dod/api-key":    []byte("dod-api-key"),
		"dod/aws-secret": []byte("dod-aws-secret-key-material"),
		"dod/bearer":     []byte("dod-bearer-token"),
	}
	for name, value := range values {
		sealed, err := seal.Seal(kek, value, []byte(dodConnectorTenant+"/secret-store/"+name))
		if err != nil {
			t.Fatal(err)
		}
		seedApplicationSecretFixture(t, st, dodConnectorTenant, name, sealed)
	}
}

type dodConnectorResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *dodConnectorResponse) Header() http.Header    { return w.header }
func (w *dodConnectorResponse) WriteHeader(status int) { w.status = status }
func (w *dodConnectorResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func dodConnectorRequest(t *testing.T, srv *Server, token, method, path, idempotencyKey string, body any, want int) []byte {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response := &dodConnectorResponse{header: make(http.Header)}
	srv.Handler().ServeHTTP(response, request)
	if response.status != want {
		t.Fatalf("%s %s = %d, want %d; body=%s", method, path, response.status, want, response.body.Bytes())
	}
	return append([]byte(nil), response.body.Bytes()...)
}

func dodConnectorCreateOwner(t *testing.T, srv *Server, token string) string {
	t.Helper()
	body := dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/owners", "dod-connector-owner", map[string]any{
		"kind": "workload", "name": "trstctl DoD connector owner",
		"email": "dod-connectors@example.test", "application_id": "APP-DOD-CONNECTORS",
		"service": "native-connector-proof", "business_unit": "security",
		"environment": "test", "escalation_chain": []string{"dod-connectors@example.test"},
	}, http.StatusCreated)
	var owner struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &owner) != nil || owner.ID == "" {
		t.Fatalf("decode connector proof owner: %s", body)
	}
	attested := dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/owners/"+owner.ID+"/attest",
		"dod-connector-owner-attestation", nil, http.StatusOK)
	var authority struct {
		VerifiedBy string `json:"ownership_verified_by"`
		Current    bool   `json:"ownership_current"`
	}
	if json.Unmarshal(attested, &authority) != nil || authority.VerifiedBy != "dod-connector-operator" || !authority.Current {
		t.Fatalf("connector proof owner is not current attested authority: %s", attested)
	}
	return owner.ID
}

func dodRunConnector(t *testing.T, entryID, connectorName string, external *proof.ExternalSubstrate, srv *Server, token, ownerID string, targetConfig json.RawMessage, target, readbackPath string, runtimes ...*dodConnectorAgentRuntime) {
	t.Helper()
	if len(runtimes) > 1 {
		t.Fatalf("%s connector proof received %d agent runtimes, want at most one", entryID, len(runtimes))
	}
	var agentRuntime *dodConnectorAgentRuntime
	if len(runtimes) == 1 {
		agentRuntime = runtimes[0]
	} else if value, ok := dodConnectorAgentRuntimes.Load(srv); ok {
		agentRuntime, _ = value.(*dodConnectorAgentRuntime)
	}
	stem := strings.ReplaceAll(entryID, ".", "-")
	targetBody := dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/connectors/targets", "dod-target-"+stem, map[string]any{
		"name": target, "connector": connectorName, "config": targetConfig,
	}, http.StatusCreated)
	var configured struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(targetBody, &configured) != nil || configured.ID == "" {
		t.Fatalf("decode %s target: %s", entryID, targetBody)
	}

	// F27 preview gate: every shipped connector must perform a real target-
	// vantage dress rehearsal before credential issuance/deploy. The target
	// process hashes only mutable receiver state (not its request transcript), so
	// equal before/after digests prove preview changed no target bytes while the
	// terminal receipt proves it still reached and authenticated where required.
	beforePreview := dodConnectorEffectDigest(t, external)
	previewBody := dodConnectorRequest(t, srv, token, http.MethodPost,
		"/api/v1/connectors/targets/"+configured.ID+"/test", "dod-preview-"+stem, nil, http.StatusAccepted)
	var queuedPreview struct {
		Status         string `json:"status"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if json.Unmarshal(previewBody, &queuedPreview) != nil || queuedPreview.Status != "dry_run_queued" || queuedPreview.IdempotencyKey == "" {
		t.Fatalf("decode %s queued preview: %s", entryID, previewBody)
	}
	vantage := nativeConnectorVantage(connectorName)
	previewAgentOwned := vantage != connector.VantageControlPlane
	if previewAgentOwned {
		if agentRuntime == nil {
			t.Fatalf("%s preview requires %s execution but the connector agent runtime is absent", entryID, vantage)
		}
		if err := agentRuntime.heartbeat(t); err != nil {
			t.Fatalf("%s refresh enrolled agent presence before preview: %v", entryID, err)
		}
	}
	if err := srv.Drain(context.Background()); err != nil {
		t.Fatalf("drain %s preview: %v", entryID, err)
	}
	if previewAgentOwned {
		if err := agentRuntime.run(t, connectorName); err != nil {
			t.Fatalf("%s agent preview: %v; substrate %s", entryID, err, dodConnectorFailureDiagnostic(external))
		}
	}
	afterPreview := dodConnectorEffectDigest(t, external)
	if beforePreview != afterPreview {
		t.Fatalf("%s preview changed target state: before=%s after=%s", entryID, beforePreview, afterPreview)
	}
	previewReceipts := dodConnectorRequest(t, srv, token, http.MethodGet,
		"/api/v1/connectors/deliveries?limit=100", "", nil, http.StatusOK)
	var previewPage struct {
		Items []struct {
			Connector      string `json:"connector"`
			Target         string `json:"target"`
			Status         string `json:"status"`
			Reason         string `json:"reason"`
			IdempotencyKey string `json:"idempotency_key"`
		} `json:"items"`
	}
	if err := json.Unmarshal(previewReceipts, &previewPage); err != nil {
		t.Fatalf("decode %s preview receipts: %v body=%s", entryID, err, previewReceipts)
	}
	previewMatched := 0
	for _, receipt := range previewPage.Items {
		if receipt.Connector == connectorName && receipt.Target == target &&
			receipt.Status == "dry_run_planned" && receipt.Reason == "dry_run_planned" &&
			receipt.IdempotencyKey == queuedPreview.IdempotencyKey+":result" {
			previewMatched++
		}
	}
	if previewMatched != 1 {
		t.Fatalf("%s terminal zero-write preview receipts=%d, want exactly one; body=%s", entryID, previewMatched, previewReceipts)
	}

	identityBody := dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/identities", "dod-identity-"+stem, map[string]any{
		"kind": "x509_certificate", "name": stem + ".dod.test", "owner_id": ownerID,
	}, http.StatusCreated)
	var identity struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(identityBody, &identity) != nil || identity.ID == "" {
		t.Fatalf("decode %s identity: %s", entryID, identityBody)
	}
	dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/identities/"+identity.ID+"/connector-target", "dod-bind-"+stem, map[string]any{
		"target_id": configured.ID,
	}, http.StatusOK)
	dodConnectorRequest(t, srv, token, http.MethodPost, "/api/v1/connectors/targets/"+configured.ID+"/deploy", "dod-deploy-"+stem, map[string]any{
		"identity_id": identity.ID, "reason": "DoD production connector deployment",
	}, http.StatusOK)
	diagnostic := &dodConnectorDispatchDiagnostic{
		inner: srv.obHandler, classes: make(map[string]string),
	}
	srv.obHandler = diagnostic
	vantage = nativeConnectorVantage(connectorName)
	// Relay-vantage is the target topology, while RelayMigrated is the switch
	// that has actually retired control-plane fallback. Cisco, FortiGate, and
	// Palo Alto deliberately retain that fallback until their device APIs can
	// prove rollback/readback, so the DoD journey must not invent a relay-only
	// production policy for them.
	agentOwned := vantage == connector.VantageHostAgent ||
		(vantage == connector.VantageNetworkRelay && connector.RelayMigrated(connectorName))
	if agentOwned {
		if agentRuntime == nil {
			t.Fatalf("%s requires %s execution but the connector agent runtime is absent", entryID, vantage)
		}
		if err := agentRuntime.heartbeat(t); err != nil {
			t.Fatalf("%s refresh enrolled agent presence: %v", entryID, err)
		}
	}
	drainErr := srv.Drain(context.Background())
	srv.obHandler = diagnostic.inner
	if drainErr != nil {
		t.Fatalf("drain %s deployment: %v", entryID, drainErr)
	}
	if agentOwned {
		if err := agentRuntime.run(t, connectorName); err != nil {
			t.Fatalf("%s agent execution: %v; substrate %s", entryID, err, dodConnectorFailureDiagnostic(external))
		}
	}
	request, err := http.NewRequest(http.MethodGet, "/api/v1/connectors/deliveries?limit=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	session := proof.Start(t, entryID, srv.Handler(), request)
	var deliveries struct {
		Items []struct {
			OutboxID       *int64  `json:"outbox_id"`
			IdentityID     *string `json:"identity_id"`
			Connector      string  `json:"connector"`
			Target         string  `json:"target"`
			Status         string  `json:"status"`
			IdempotencyKey string  `json:"idempotency_key"`
		} `json:"items"`
	}
	decodeErr := json.Unmarshal(session.ResponseBody(), &deliveries)
	matched := 0
	for _, item := range deliveries.Items {
		if item.IdentityID != nil && *item.IdentityID == identity.ID &&
			item.OutboxID != nil && item.Connector == connectorName && item.Target == target &&
			item.Status == "delivered" && strings.TrimSpace(item.IdempotencyKey) != "" {
			matched++
		}
	}
	if decodeErr != nil || matched != 1 {
		pending, pendingErr := srv.outbox.Pending(context.Background(), dodConnectorTenant)
		states := make([]string, 0, len(pending))
		for _, item := range pending {
			states = append(states, fmt.Sprintf("%s:%s:%d", item.Destination, item.Status, item.Attempts))
		}
		t.Fatalf("%s delivery receipt is not exact user-visible delivered evidence: matches=%d decode_err=%v body=%s pending=%v pending_err=%v ca_issue_error_class=%s",
			entryID, matched, decodeErr, session.ResponseBody(), states, pendingErr, diagnostic.errorClass("ca.issue"))
	}
	ident, err := srv.store.GetIdentity(context.Background(), dodConnectorTenant, identity.ID)
	if err != nil {
		t.Fatalf("load %s identity after deploy: %v", entryID, err)
	}
	certificates, err := srv.store.ListActiveIssuedCertificatesForIdentity(context.Background(), dodConnectorTenant, ident.OwnerID, ident.Name)
	if err != nil || len(certificates) != 1 || len(certificates[0].CertificateDER) == 0 {
		t.Fatalf("load %s issued certificate after deploy: count=%d err=%v", entryID, len(certificates), err)
	}
	written := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificates[0].CertificateDER})
	readback := dodConnectorReadback(t, external.Endpoint(), readbackPath)
	if !bytes.Equal(written, readback) {
		first := firstDifferentByte(written, readback)
		leftEnd, rightEnd := min(first+8, len(written)), min(first+8, len(readback))
		t.Fatalf("%s independent readback differs from issued leaf: written_bytes=%d readback_bytes=%d first_difference=%d written_window=%q readback_window=%q", entryID, len(written), len(readback), first, written[max(0, first-3):leftEnd], readback[max(0, first-3):rightEnd])
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{
		Destination: []byte("native-connector://" + entryID + "/" + target),
		Written:     written, ReadBack: readback, ExecutionReceipt: executionReceipt,
	}))
}

func dodConnectorEffectDigest(t *testing.T, external *proof.ExternalSubstrate) string {
	t.Helper()
	response, err := http.Get(external.Endpoint() + "/dod/effect-digest")
	if err != nil {
		t.Fatalf("read connector target effect digest: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var body struct {
		SHA256 string `json:"sha256"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&body) != nil || len(body.SHA256) != 64 {
		t.Fatalf("invalid connector target effect digest response")
	}
	return body.SHA256
}

func firstDifferentByte(left, right []byte) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func dodConnectorReadback(t *testing.T, endpoint, path string) []byte {
	t.Helper()
	raw := endpoint + "/dod/readback"
	if path != "" {
		query := url.Values{"path": []string{path}}
		query.Set("certificate", "1")
		raw += "?" + query.Encode()
	}
	response, err := http.Get(raw)
	if err != nil {
		t.Fatalf("external readback: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	readback, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(readback) < 16 {
		t.Fatalf("external readback status=%d bytes=%d err=%v", response.StatusCode, len(readback), err)
	}
	return readback
}
