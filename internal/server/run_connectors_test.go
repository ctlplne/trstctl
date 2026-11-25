// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/caddy"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/native"
	"trstctl.com/trstctl/internal/connector/postfix"
	"trstctl.com/trstctl/internal/connector/traefik"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	nativeReplayCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBiDCCAS2gAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpjb25mb3Jt
YW5jZS5jb25uZWN0b3IudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw
MDBaMCUxIzAhBgNVBAMTGmNvbmZvcm1hbmNlLmNvbm5lY3Rvci50ZXN0MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE4TYNtNbbVlPcVpyznJuujANXTbsaRNL5D41K
VfB5GdJEG372Pgtn59Mp7+1+PUbyHTbaKJ1RU0n6vgW5/BCC1aNOMEwwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCUGA1UdEQQeMByCGmNvbmZv
cm1hbmNlLmNvbm5lY3Rvci50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQD2NqiRyoq8
T1vJogCsCMRDiEMMsA04Qhbs5uF149egpgIhALTX3I6Xe4dQk3GMTEaXC5GWXkaj
O9xXOtFRqPTY0dXn
-----END CERTIFICATE-----
`)
	nativeReplayKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2drNvkGQeqFUx3xE
zejpKQlXChZFd7J3qw/JXoL+x72hRANCAAThNg201ttWU9xWnLOcm66MA1dNuxpE
0vkPjUpV8HkZ0kQbfvY+C2fn0ynv7X49RvIdNtoonVFTSfq+Bbn8EILV
-----END PRIVATE KEY-----
`)
)

func TestConnectorRegistryFromConfigBuildsTargetScopedLocalFactory(t *testing.T) {
	root := t.TempDir()
	certPath := filepath.Join(root, "server.crt")
	keyPath := filepath.Join(root, "server.key")
	cfg := config.Connectors{
		Enabled: []string{"nginx"},
		LocalProfiles: map[string]config.LocalConnectorProfile{
			"shared-volume": {
				AllowedRoots: []string{root},
				Actions: []config.LocalConnectorAction{{
					LogicalName: "nginx", Command: regularHostCommand(t, "/usr/bin/true"), PassArgs: true,
				}},
			},
		},
	}
	registry, err := connectorRegistryFromConfig(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("connectorRegistryFromConfig: %v", err)
	}
	if !registry.Has("nginx") {
		t.Fatal("production registry did not expose configured nginx factory")
	}
	targetConfig, err := json.Marshal(map[string]any{
		"profile": "shared-volume", "cert_path": certPath, "key_path": keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := []byte("-----BEGIN CERTIFICATE-----\nproduction-factory-cert\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN PRIVATE KEY-----\nproduction-factory-key\n-----END PRIVATE KEY-----\n")
	if err := registry.Deploy(context.Background(), connector.DeployPayload{
		Connector: "nginx", Target: "edge", TargetConfig: targetConfig,
		CertPEM: cert, KeyPEM: key, Fingerprint: crypto.SHA256Hex(cert),
	}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	for path, want := range map[string][]byte{certPath: cert, keyPath: key} {
		got, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s = %q, want %q", path, got, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", path, info.Mode().Perm())
		}
	}
}

func TestProductionNativeRegistryAdvertisesTLSPostureOnlyForImplementedReceiver(t *testing.T) {
	registry, err := connectorRegistryFromConfig(config.Connectors{Enabled: []string{"envoy", "nginx"}}, nil, nil, nil)
	if err != nil {
		t.Fatalf("connectorRegistryFromConfig: %v", err)
	}
	if !registry.SupportsTLSPosture("envoy") {
		t.Fatal("shipped Envoy factory is not wired to the TLS posture contract")
	}
	for _, unsupported := range []string{"nginx", "future-signed-plugin", ""} {
		if registry.SupportsTLSPosture(unsupported) {
			t.Fatalf("unsupported connector %q advertised TLS posture mutation", unsupported)
		}
	}
}

func TestProductionNativeConnectorReplaySafetyIsExplicitAndConservative(t *testing.T) {
	reconciled := []string{
		"caddy", "postfix", "traefik", "java-keystore",
		"envoy", "kemp", "fortigate",
	}
	atMostOnce := []string{
		"nginx", "apache", "iis", "haproxy", "postgresql", "mysql", "rabbitmq",
		"elasticsearch", "tomcat", "f5", "netscaler", "a10", "cisco", "paloalto",
		"azure-keyvault", "aws-acm", "gcp-certificate-manager",
	}
	proof := map[string]func(*testing.T){
		"caddy":         func(t *testing.T) { proveNativeFileReplayNoop(t, caddy.New("/tls/cert.pem", "/tls/key.pem")) },
		"postfix":       func(t *testing.T) { proveNativeFileReplayNoop(t, postfix.New(postfix.Config{})) },
		"traefik":       func(t *testing.T) { proveNativeFileReplayNoop(t, traefik.New("/tls/cert.pem", "/tls/key.pem")) },
		"java-keystore": proveNativeJavaKeystoreReplay,
		"envoy":         proveNativeEnvoyReplay,
		"kemp":          proveNativeKempReplay,
		"fortigate":     proveNativeFortiGateReplay,
	}
	enabled := append(append([]string(nil), reconciled...), atMostOnce...)
	registry, err := connectorRegistryFromConfig(config.Connectors{Enabled: enabled}, nil, nil, nil)
	if err != nil {
		t.Fatalf("connectorRegistryFromConfig: %v", err)
	}
	for _, name := range reconciled {
		prove := proof[name]
		if prove == nil {
			t.Fatalf("%s has no linked receiver replay proof", name)
		}
		if got := registry.ReplaySafetyFor(name); got != connector.ReplaySafetyReconciled {
			t.Errorf("%s replay safety = %v, want deterministic reconciliation", name, got)
		}
		t.Run(name+"-receiver-proof", prove)
	}
	for _, name := range atMostOnce {
		if got := registry.ReplaySafetyFor(name); got != connector.ReplaySafetyAtMostOnce {
			t.Errorf("%s replay safety = %v, want at-most-once", name, got)
		}
	}
	if got := registry.ReplaySafetyFor("future-signed-plugin"); got != connector.ReplaySafetyAtMostOnce {
		t.Fatalf("unknown connector replay safety = %v, want conservative at-most-once", got)
	}
}

type nativeReplayOps struct {
	*connector.MemoryOps
	writes int
}

func (o *nativeReplayOps) WriteFile(path string, data []byte) error {
	o.writes++
	return o.MemoryOps.WriteFile(path, data)
}

func nativeReplayDeployment(t *testing.T) connector.Deployment {
	t.Helper()
	dep := connector.NewDeployment("replay-target", nativeReplayCert, nativeReplayKey)
	info, err := certinfo.Inspect(nativeReplayCert)
	if err != nil {
		t.Fatalf("inspect replay certificate: %v", err)
	}
	if dep.Fingerprint != info.SHA256Fingerprint {
		t.Fatalf("replay proof fingerprint = %q, want shipped DER fingerprint %q", dep.Fingerprint, info.SHA256Fingerprint)
	}
	return dep
}

func proveNativeFileReplayNoop(t *testing.T, conn connector.Connector) {
	t.Helper()
	ops := &nativeReplayOps{MemoryOps: connector.NewMemoryOps()}
	dep := nativeReplayDeployment(t)
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	writes, execs := ops.writes, len(ops.Execs())
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("reconciled deploy: %v", err)
	}
	if ops.writes != writes || len(ops.Execs()) != execs {
		t.Fatalf("reconciled deploy repeated receiver mutation: writes %d->%d execs %d->%d", writes, ops.writes, execs, len(ops.Execs()))
	}
}

func proveNativeJavaKeystoreReplay(t *testing.T) {
	ops := &nativeReplayOps{MemoryOps: connector.NewMemoryOps()}
	conn := javakeystore.New("/tls/keystore.p12", []byte("changeit"), "server")
	t.Cleanup(conn.Close)
	dep := nativeReplayDeployment(t)
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	first, ok := ops.File("/tls/keystore.p12")
	if !ok {
		t.Fatal("first deploy did not write the keystore")
	}
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("reconciled deploy: %v", err)
	}
	second, _ := ops.File("/tls/keystore.p12")
	if !bytes.Equal(first, second) {
		t.Fatal("reconciled Java keystore deploy changed deterministic receiver bytes")
	}
}

type nativeReplayEnvoyOps struct {
	*connector.MemoryOps
	secret []byte
	puts   int
}

func (o *nativeReplayEnvoyOps) Request(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodGet:
		if len(o.secret) == 0 {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(o.secret)), Header: make(http.Header), Request: req}, nil
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		o.secret = append(o.secret[:0], body...)
		o.puts++
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header), Request: req}, nil
	default:
		return nil, errors.New("unexpected Envoy replay-proof method")
	}
}

func proveNativeEnvoyReplay(t *testing.T) {
	ops := &nativeReplayEnvoyOps{MemoryOps: connector.NewMemoryOps()}
	conn := envoy.New("https://envoy-replay.test", "server-cert")
	dep := nativeReplayDeployment(t)
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", attempt, err)
		}
	}
	if ops.puts != 1 {
		t.Fatalf("Envoy reconciled PUTs = %d, want one", ops.puts)
	}
}

func proveNativeKempReplay(t *testing.T) {
	conn := kemp.New("https://kemp-replay.test", []byte("token"))
	t.Cleanup(conn.Close)
	proveNativeFixedHTTPState(t, conn)
}

func proveNativeFortiGateReplay(t *testing.T) {
	conn := fortigate.New("https://fortigate-replay.test", []byte("token"))
	t.Cleanup(conn.Close)
	proveNativeFixedHTTPState(t, conn)
}

func proveNativeFixedHTTPState(t *testing.T, conn connector.Connector) {
	t.Helper()
	ops := connector.NewMemoryOps()
	dep := nativeReplayDeployment(t)
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	first := ops.Requests()
	if _, err := connector.Run(context.Background(), conn, ops, dep); err != nil {
		t.Fatalf("reconciled deploy: %v", err)
	}
	if !reflect.DeepEqual(first, ops.Requests()) {
		t.Fatal("reconciled deploy changed the fixed named receiver request set")
	}
}

func TestValidateConnectorEndpointRestrictsInsecureHTTPToLoopback(t *testing.T) {
	cfg := config.Connectors{AllowInsecureHTTP: true, AllowPrivateCIDRs: []string{"127.0.0.0/8", "10.0.0.0/8"}}
	if err := validateConnectorEndpoint("http://127.0.0.1:18080", cfg); err != nil {
		t.Fatalf("loopback emulator endpoint: %v", err)
	}
	for _, endpoint := range []string{"http://10.0.0.8:8080", "http://receiver.example.test"} {
		if err := validateConnectorEndpoint(endpoint, cfg); err == nil {
			t.Fatalf("non-loopback insecure endpoint %q was accepted", endpoint)
		}
	}
}

func TestBuildHTTPConnectorUsesClosedTargetSchemasAndTenantCredentialRuntime(t *testing.T) {
	client, err := connectorHTTPClientFromConfig(config.Connectors{AllowInsecureHTTP: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := nativeConnectorRuntime{cfg: config.Connectors{AllowInsecureHTTP: true}, httpClient: client}
	targets := map[string]map[string]any{
		"envoy":                   {"endpoint": "https://envoy.example.test", "secret_name": "edge"},
		"a10":                     {"endpoint": "https://a10.example.test", "username": "admin", "password_ref": "secret://connectors/a10"},
		"f5":                      {"endpoint": "https://f5.example.test", "client_ssl_profile": "edge", "username": "admin", "password_ref": "secret://connectors/f5"},
		"netscaler":               {"endpoint": "https://netscaler.example.test", "username": "admin", "password_ref": "secret://connectors/netscaler", "file_location": "/nsconfig/ssl"},
		"kemp":                    {"endpoint": "https://kemp.example.test", "token_ref": "secret://connectors/kemp"},
		"cisco":                   {"endpoint": "https://cisco.example.test", "username": "admin", "password_ref": "secret://connectors/cisco"},
		"fortigate":               {"endpoint": "https://fortigate.example.test", "token_ref": "secret://connectors/fortigate"},
		"paloalto":                {"endpoint": "https://paloalto.example.test", "api_key_ref": "secret://connectors/paloalto"},
		"aws-acm":                 {"endpoint": "https://acm.us-east-1.amazonaws.com", "region": "us-east-1", "access_key_id": "AKID", "secret_access_key_ref": "secret://connectors/aws"},
		"azure-keyvault":          {"endpoint": "https://vault.example.test", "bearer_token_ref": "secret://connectors/azure", "api_version": "7.4"},
		"gcp-certificate-manager": {"endpoint": "https://certificatemanager.googleapis.com", "project": "project-a", "location": "global", "bearer_token_ref": "secret://connectors/gcp"},
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			built, ops, cleanup, err := buildHTTPConnector(runtime, context.Background(), name, connector.DeployPayload{
				TenantID: "tenant-a", TargetConfig: raw,
			})
			if name == "envoy" {
				if err != nil || built == nil || ops == nil || cleanup == nil {
					t.Fatalf("credential-free Envoy build = %T, %T, cleanup=%t, err=%v", built, ops, cleanup != nil, err)
				}
				cleanup()
				return
			}
			if err == nil || !strings.Contains(err.Error(), "secret-store runtime is unavailable") {
				t.Fatalf("%s without tenant secret-store custody = %v", name, err)
			}
			if built != nil || ops != nil || cleanup != nil {
				t.Fatalf("%s returned partial connector after credential failure", name)
			}
		})
	}
	if got := httpConnectorClient(runtime, "https://envoy.example.test"); got != client {
		t.Fatal("HTTPS connector did not retain the configured safe client")
	}
	if got := httpConnectorClient(runtime, "http://127.0.0.1:18080"); got == client || got.Timeout != client.Timeout {
		t.Fatal("explicit loopback emulator did not receive an isolated insecure-loopback client")
	}
}

func TestParseConnectorSecretRefIsVersionedAndClosed(t *testing.T) {
	name, version, err := parseConnectorSecretRef(" secret://team/edge-token ")
	if err != nil || name != "team/edge-token" || version != nil {
		t.Fatalf("unversioned ref = %q, %v, %v", name, version, err)
	}
	name, version, err = parseConnectorSecretRef("secret://team/edge%20token?version=7")
	if err != nil || name != "team/edge token" || version == nil || *version != 7 {
		t.Fatalf("versioned ref = %q, %v, %v", name, version, err)
	}
	for _, ref := range []string{
		"literal", "secret://", "secret://user@team/token", "secret://team/../token",
		"secret://team/token#fragment", "secret://team/token?other=1",
		"secret://team/token?version=0", "secret://team/token?version=not-a-number",
	} {
		if _, _, err := parseConnectorSecretRef(ref); err == nil {
			t.Fatalf("parseConnectorSecretRef(%q) succeeded", ref)
		}
	}
}

func TestConnectorSecretReferenceRejectsNoncanonicalGrammar(t *testing.T) {
	for _, ref := range []string{
		"Secret://fixture/team/token",
		"secret:/fixture/team/token",
		"secret:///fixture/team/token",
		"secret://fixture/team/%74oken",
		"secret://fixture/team/token#",
		"secret://fixture/team/token?",
		"secret://fixture/team/token?version=",
		"secret://fixture/team/token?version=01",
		"secret://fixture/team/token?version=1&version=2",
		"secret://fixture/team/token?version=2147483648",
	} {
		if _, _, err := parseConnectorSecretRef(ref); err == nil {
			t.Errorf("redeemer accepted noncanonical stored credential reference %q", ref)
		}
	}
}

func TestRelayCollectorRetainsNoncanonicalReferencesForRejection(t *testing.T) {
	got := collectSecretRefs(json.RawMessage(`{"credential_ref":"Secret://fixture/team/token","note":"ordinary fixture"}`))
	if !reflect.DeepEqual(got, []string{"Secret://fixture/team/token"}) {
		t.Error("relay silently dropped a stored credential candidate before validation")
	}
}

func TestAzureKeyVaultChecksStoredReferenceBeforeCustody(t *testing.T) {
	lease := &connectorCredentialLease{}
	_, _, err := native.Build("azure-keyvault", native.Target{
		BearerTokenRef: "Secret://fixture/team/token",
	}, lease.requirer(t.Context(), nil))
	if err == nil || !strings.Contains(err.Error(), "canonical secret://") {
		t.Fatalf("Azure Key Vault bearer reference did not fail at format validation: %v", err)
	}
}

func TestRelayChecksAllStoredReferenceSyntaxBeforeCustody(t *testing.T) {
	resolver := &relayCredentialResolver{}
	refs := []string{"secret://fixture/public/token", "Secret://fixture/team/token"}
	if _, err := resolver.resolveReferenceNames(t.Context(), "fixture-tenant", refs); err == nil ||
		!strings.Contains(err.Error(), "canonical secret://") {
		t.Fatalf("relay reference list did not fail at format validation: %v", err)
	}
}

func TestProtocolSecretReferencesCheckFormatBeforeCustody(t *testing.T) {
	const ref = "secret://fixture/team/%74oken"
	ctx := t.Context()
	var automation servedACMEDNS01Automation
	var srv Server
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"DNS-01", func() error {
			_, err := automation.secretRef(ctx, "fixture-tenant", json.RawMessage(`{"token_ref":"`+ref+`"}`), "token_ref")
			return err
		}},
		{"MDM challenge", func() error {
			_, err := srv.openMDMSCEPSecretRef(ctx, "fixture-tenant", "challenge", ref, nil)
			return err
		}},
		{"MDM trust anchor", func() error {
			_, err := srv.loadMDMSCEPTrustAnchorRef(ctx, "fixture-tenant", "anchor", ref, nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err == nil || !strings.Contains(err.Error(), "canonical secret://") {
				t.Errorf("reference did not fail before custody lookup: %v", err)
			}
		})
	}
}

func TestServedStoredReferenceSelectsOneHistoricalVersionAcrossReaders(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DeletedSecretRetention = time.Hour
	})
	ctx := t.Context()
	const name = "fixture/team/edge token"
	const ref = "secret://fixture/team/edge%20token?version=1"
	const previous = "fixture-version-one"
	token := seedScopedTokenSubject(t, h.store, h.tenant, "stored-version-connector-author", "secrets:read", "secrets:write", "connectors:read", "connectors:write")
	if status, _ := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token, map[string]string{"name": name, "value": previous}); status != http.StatusCreated {
		t.Fatalf("create fixture secret returned HTTP %d", status)
	}
	if status, _ := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/fixture/team/edge%20token", token,
		map[string]string{"value": "fixture-version-two"}); status != http.StatusOK {
		t.Fatalf("rotate fixture secret returned HTTP %d", status)
	}
	targetConfig := json.RawMessage(`{"endpoint":"https://kemp.example.test","token_ref":"` + ref + `"}`)
	status, saved := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", token,
		map[string]any{"name": "stored-version-kemp", "connector": "kemp", "config": targetConfig})
	if status != http.StatusCreated {
		t.Fatalf("save version-pinned connector target: HTTP %d %s", status, saved)
	}
	var targetID struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(saved, &targetID); err != nil || targetID.ID == "" {
		t.Fatalf("decode version-pinned connector target: %v", err)
	}
	target, err := h.store.GetDeploymentTarget(ctx, h.tenant, targetID.ID)
	if err != nil {
		t.Fatal(err)
	}
	lease := &connectorCredentialLease{store: h.store, kek: h.kek, crypto: h.srv.tenantCrypto, tenantID: h.tenant,
		targetID: target.ID, targetRevision: target.RevisionID, targetConfig: target.Config, connectorName: target.Type}
	defer lease.Close()
	if value, err := lease.require(ctx, ref); err != nil || !bytes.Equal(value, []byte(previous)) {
		t.Errorf("connector did not resolve the pinned fixture version: %v", err)
	}
	integration := integrationCredentialResolver{store: h.store, kek: h.kek, crypto: h.srv.tenantCrypto}
	value, err := integration.resolve(ctx, h.tenant, ref)
	if err != nil {
		t.Errorf("integration did not resolve the pinned fixture version: %v", err)
	} else {
		defer value.Destroy()
		if !bytes.Equal(value.Bytes(), []byte(previous)) {
			t.Error("integration selected the wrong fixture version")
		}
	}
	relay := relayCredentialResolver{store: h.store, kek: h.kek, tenantCrypto: h.srv.tenantCrypto}
	material, err := relay.resolveReferenceNames(ctx, h.tenant, []string{ref})
	if err != nil {
		t.Fatal(err)
	}
	defer material.wipe()
	if len(material.items) != 1 || material.items[0].Name != ref || !bytes.Equal(material.items[0].Value, []byte(previous)) {
		t.Error("relay did not preserve the reference and pinned fixture version")
	}
	const unversioned = "secret://fixture/team/edge%20token"
	current, err := integration.resolve(ctx, h.tenant, unversioned)
	if err != nil {
		t.Fatalf("integration did not resolve the current fixture version: %v", err)
	}
	if !bytes.Equal(current.Bytes(), []byte("fixture-version-two")) {
		t.Error("integration selected the wrong current fixture version")
	}
	current.Destroy()
	if status, _ := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]string{"name": strings.TrimPrefix(unversioned, "secret://"), "value": "fixture-retired-literal"}); status != http.StatusCreated {
		t.Fatalf("create unpinned literal fixture returned HTTP %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/fixture/team/edge%2520token",
		token, "fixture-delete-retired-literal", nil); status != http.StatusNoContent {
		t.Fatalf("delete literal fixture returned HTTP %d", status)
	}
	retired, err := integration.resolve(ctx, h.tenant, unversioned)
	if retired != nil {
		retired.Destroy()
	}
	if err == nil || !strings.Contains(err.Error(), "legacy literal name") {
		t.Errorf("a retained deleted name allowed the reader to change identity: %v", err)
	}
	if purged, err := h.store.PurgeDeletedSecret(ctx, h.tenant, strings.TrimPrefix(unversioned, "secret://")); err != nil || !purged {
		t.Fatalf("purge deleted fixture credential: purged=%t err=%v", purged, err)
	}
	purged, err := integration.resolve(ctx, h.tenant, unversioned)
	if purged != nil {
		purged.Destroy()
	}
	if err == nil || !strings.Contains(err.Error(), "legacy literal name") {
		t.Errorf("purging the value allowed a retained reference to change identity: %v", err)
	}

	// Older integrations and protocol readers used the complete suffix as a
	// literal name. An existing literal credential blocks a change of identity.
	literalName := strings.TrimPrefix(ref, "secret://")
	if status, _ := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]string{"name": literalName, "value": "fixture-old-literal"}); status != http.StatusCreated {
		t.Fatalf("create retained literal fixture returned HTTP %d", status)
	}
	automation := servedACMEDNS01Automation{store: h.store, kek: h.kek, crypto: h.srv.tenantCrypto}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"integration", func() error {
			buf, err := integration.resolve(ctx, h.tenant, ref)
			if buf != nil {
				buf.Destroy()
			}
			return err
		}},
		{"DNS-01", func() error {
			value, err := automation.secretRef(ctx, h.tenant, json.RawMessage(`{"token_ref":"`+ref+`"}`), "token_ref")
			secret.Wipe(value)
			return err
		}},
		{"MDM challenge", func() error {
			value, err := h.srv.openMDMSCEPSecretRef(ctx, h.tenant, "challenge", ref, h.kek)
			secret.Wipe(value)
			return err
		}},
		{"MDM trust anchor", func() error {
			values, err := h.srv.loadMDMSCEPTrustAnchorRef(ctx, h.tenant, "anchor", ref, h.kek)
			for _, value := range values {
				secret.Wipe(value)
			}
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil || !strings.Contains(err.Error(), "legacy literal name") {
				t.Errorf("reader did not refuse the two possible stored identities: %v", err)
			}
		})
	}
	if value, err := lease.require(ctx, ref); err != nil || !bytes.Equal(value, []byte(previous)) {
		t.Errorf("a connector whose original syntax used the version stopped resolving it: %v", err)
	}
}
