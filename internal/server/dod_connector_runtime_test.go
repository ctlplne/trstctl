//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const dodConnectorTenant = "d0d00000-0000-4000-8000-000000000001"

type dodConnectorTarget struct {
	entryID      string
	connector    string
	external     *proof.ExternalSubstrate
	config       json.RawMessage
	target       string
	readbackPath string
}

// TestDODNativeConnectorsProductionAssembly is shared by the 25 granular
// connector census rows. Every literal entry starts its own nonce/entry/PID-bound
// external process, while one production buildRunDeps -> Build composition routes
// all deliveries through the real outbox and user-visible receipt API.
func TestDODNativeConnectorsProductionAssembly(t *testing.T) {
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
		"mysql":         {mysqlExternal, []string{"mysqladmin"}},
		"rabbitmq":      {rabbitExternal, []string{"rabbitmqctl"}},
		"elasticsearch": {elasticExternal, nil},
		"tomcat":        {tomcatExternal, []string{"catalina.sh"}},
	}

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
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
	dodRunConnector(t, "connector.traefik", "traefik", traefikExternal, srv, token, ownerID, dodPairConfig(t, "traefik", roots["traefik"]), "dod-target", filepath.Join(roots["traefik"], "server.crt"))
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
		if _, err := st.PutSecret(context.Background(), dodConnectorTenant, name, sealed); err != nil {
			t.Fatal(err)
		}
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
	}, http.StatusCreated)
	var owner struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &owner) != nil || owner.ID == "" {
		t.Fatalf("decode connector proof owner: %s", body)
	}
	return owner.ID
}

func dodRunConnector(t *testing.T, entryID, connectorName string, external *proof.ExternalSubstrate, srv *Server, token, ownerID string, targetConfig json.RawMessage, target, readbackPath string) {
	t.Helper()
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
	if err := srv.Drain(context.Background()); err != nil {
		t.Fatalf("drain %s deployment: %v", entryID, err)
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
	request, err := http.NewRequest(http.MethodGet, "/api/v1/connectors/deliveries?limit=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	session := proof.Start(t, entryID, srv.Handler(), request)
	if !bytes.Contains(session.ResponseBody(), []byte(`"status":"delivered"`)) || !bytes.Contains(session.ResponseBody(), []byte(`"connector":"`+connectorName+`"`)) {
		t.Fatalf("%s delivery receipt is not user-visible delivered evidence: %s", entryID, session.ResponseBody())
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{
		Destination: []byte("native-connector://" + entryID + "/" + target),
		Written:     written, ReadBack: readback, ExecutionReceipt: executionReceipt,
	}))
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
