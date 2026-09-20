// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/apache"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/caddy"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/elasticsearch"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/haproxy"
	"trstctl.com/trstctl/internal/connector/iis"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/mysql"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/connector/postfix"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
	"trstctl.com/trstctl/internal/connector/tomcat"
	"trstctl.com/trstctl/internal/connector/traefik"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type nativeConnectorRuntime struct {
	cfg        config.Connectors
	store      *store.Store
	kek        seal.KeyWrapper
	crypto     tenantseal.Access
	httpClient *http.Client
	guard      *egress.Guard
}

// connectorRegistryFromConfig is the only production constructor registry for
// native connectors. It registers stateless one-shot factories; target URLs,
// paths, and secret references come from the immutable sealed outbox payload.
func connectorRegistryFromConfig(cfg config.Connectors, st *store.Store, kek seal.KeyWrapper, guard *egress.Guard, tenantCrypto ...tenantseal.Access) (*connector.Registry, error) {
	client, err := connectorHTTPClientFromConfig(cfg, guard)
	if err != nil {
		return nil, err
	}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	runtime := nativeConnectorRuntime{cfg: cfg, store: st, kek: kek, crypto: access, httpClient: client, guard: guard}
	registry := connector.NewRegistry()
	for _, raw := range cfg.Enabled {
		name := strings.TrimSpace(raw)
		factory, err := nativeConnectorFactory(runtime, name)
		if err != nil {
			return nil, err
		}
		if err := registry.RegisterFactoryWithReplaySafety(name, factory, nativeConnectorReplaySafety(name)); err != nil {
			return nil, err
		}
		if nativeConnectorSupportsTLSPosture(name) {
			if err := registry.MarkTLSPostureCapable(name); err != nil {
				return nil, err
			}
		}
		if err := registry.DeclareTargetVantage(name, nativeConnectorVantage(name)); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// nativeConnectorSupportsTLSPosture is the closed production wiring census for
// receiver APIs that implement protocol/cipher/group mutation plus read-back.
// Envoy is the first high-fidelity native target; every other connector fails
// binding preflight until it implements the same contract.
func nativeConnectorSupportsTLSPosture(name string) bool { return name == "envoy" }

// nativeConnectorReplaySafety is a closed audit of the shipped receivers. A
// connector is replay-safe only when the same credential converges on the same
// named object (or reconciles by fingerprint). Import/create APIs that can mint
// another receiver object after an ambiguous response stay at-most-once.
func nativeConnectorReplaySafety(name string) connector.ReplaySafety {
	switch name {
	// caddy/traefik/postfix read current files and return before reload when
	// fingerprint + key already match. java-keystore rewrites a deterministic
	// encoding to one fixed path. Their package-level repeated-deploy tests are
	// linked to these exact names by run_connectors_test.go.
	case "caddy", "postfix", "traefik", "java-keystore":
		return connector.ReplaySafetyReconciled
	// envoy reads the named SDS resource and compares its credential fingerprint;
	// Kemp uses PUT/PATCH against target-derived object names and FortiGate PUTs one
	// named object. Executable receiver proofs replay the same credential through
	// these exact implementations in run_connectors_test.go.
	case "envoy", "kemp", "fortigate":
		return connector.ReplaySafetyReconciled
	// These connectors use import/create or un-reconciled exec paths. In
	// particular, ACM permits an empty CertificateArn and then creates a new
	// certificate. GCP Certificate Manager PATCH creates a fresh long-running
	// operation and does not read back the named resource before retrying. Neither
	// can receive a name-wide durable-safe classification.
	case "nginx", "apache", "iis", "haproxy", "postgresql", "mysql", "rabbitmq",
		"elasticsearch", "tomcat", "f5", "netscaler", "a10", "cisco", "paloalto",
		"azure-keyvault", "aws-acm", "gcp-certificate-manager":
		return connector.ReplaySafetyAtMostOnce
	default:
		return connector.ReplaySafetyAtMostOnce
	}
}

// nativeConnectorVantage is the closed census of where each shipped connector's
// work must execute (epic A3). It is written BY HAND, not derived from the
// local-vs-HTTP factory split below: that split is a transport decision, and
// transport does not decide vantage — envoy is driven over HTTP yet its xDS/SDS
// admin socket is commonly co-resident with the workload, which is exactly the
// kind of judgement a derivation would get wrong.
//
// The census answers one question per connector: what IS the target?
//
//   - A service on a host that could run an agent — nginx, apache, a JVM
//     keystore, a database — is host-agent work: the connector mutates that
//     machine's files and reloads that machine's services, and doing it from
//     anywhere else is what doctrine D1 exists to end.
//   - An appliance that cannot run an agent — an F5, a NetScaler, a FortiGate —
//     is network-relay work: driven over its API from inside its segment, by a
//     relay holding the credentials that drive it (A2's network role).
//   - A cloud certificate store — ACM, Azure Key Vault, GCP Certificate
//     Manager — is neither a host nor an appliance. The currently shipped path
//     is the control plane's egress-guarded client. E1 still names all three for
//     network-relay migration, so this is current runtime truth, not permission
//     to call that migration complete; ParityProgram reports them unimplemented.
//
// envoy is declared host-agent deliberately: its admin/SDS surface binds
// loopback in the deployments we ship for, so the executor must be on the box
// even though the bytes travel over HTTP.
func nativeConnectorVantage(name string) connector.TargetVantage {
	if vantage, shipped := connector.ShippedTargetVantage(name); shipped {
		return vantage
	}
	// Fail closed: an unlisted connector stays where it always ran until
	// someone audits it for agent execution and adds it to the shared census.
	return connector.VantageControlPlane
}

func connectorHTTPClientFromConfig(cfg config.Connectors, guard *egress.Guard) (*http.Client, error) {
	timeout, err := cfg.HTTPTimeoutDuration()
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowPrivateCIDRs))
	for _, raw := range cfg.AllowPrivateCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("connectors private CIDR %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}
	transport := http.RoundTripper(netsec.SafeTransportWithOptions(netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes}))
	if guard != nil {
		transport = guard.WrapTransport(transport)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func nativeConnectorFactory(r nativeConnectorRuntime, name string) (connector.Factory, error) {
	switch name {
	case "nginx", "apache", "caddy", "iis", "haproxy", "postfix", "traefik",
		"java-keystore", "postgresql", "mysql", "rabbitmq", "elasticsearch", "tomcat":
		return func(ctx context.Context, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
			return buildLocalConnector(r, ctx, name, payload)
		}, nil
	case "envoy", "f5", "netscaler", "a10", "kemp", "cisco", "fortigate",
		"paloalto", "aws-acm", "azure-keyvault", "gcp-certificate-manager":
		return func(ctx context.Context, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
			return buildHTTPConnector(r, ctx, name, payload)
		}, nil
	default:
		return nil, fmt.Errorf("connector: unsupported production connector %q", name)
	}
}

type nativeTargetConfig struct {
	Profile string `json:"profile,omitempty"`

	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	CRTPath    string `json:"crt_path,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`

	PostfixCertPath string `json:"postfix_cert_path,omitempty"`
	PostfixKeyPath  string `json:"postfix_key_path,omitempty"`
	DovecotCertPath string `json:"dovecot_cert_path,omitempty"`
	DovecotKeyPath  string `json:"dovecot_key_path,omitempty"`

	Binding   string `json:"binding,omitempty"`
	Store     string `json:"store,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	ImportDir string `json:"import_dir,omitempty"`

	KeystorePath        string `json:"keystore_path,omitempty"`
	KeystorePasswordRef string `json:"keystore_password_ref,omitempty"`
	Alias               string `json:"alias,omitempty"`
	Format              string `json:"format,omitempty"`
	ReloadAction        string `json:"reload_action,omitempty"`

	Endpoint         string `json:"endpoint,omitempty"`
	SecretName       string `json:"secret_name,omitempty"`
	Username         string `json:"username,omitempty"`
	PasswordRef      string `json:"password_ref,omitempty"`
	TokenRef         string `json:"token_ref,omitempty"`
	APIKeyRef        string `json:"api_key_ref,omitempty"`
	ObjectName       string `json:"object_name,omitempty"`
	ClientSSLProfile string `json:"client_ssl_profile,omitempty"`
	FileLocation     string `json:"file_location,omitempty"`

	Region             string `json:"region,omitempty"`
	AccessKeyID        string `json:"access_key_id,omitempty"`
	SecretAccessKeyRef string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef    string `json:"session_token_ref,omitempty"`
	Project            string `json:"project,omitempty"`
	Location           string `json:"location,omitempty"`
	BearerTokenRef     string `json:"bearer_token_ref,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	PollInterval       string `json:"poll_interval,omitempty"`
}

func buildLocalConnector(r nativeConnectorRuntime, ctx context.Context, name string, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
	target, err := decodeNativeTarget(name, payload.TargetConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	profile, ok := r.cfg.LocalProfiles[target.Profile]
	if !ok || target.Profile == "" {
		return nil, nil, nil, fmt.Errorf("connector: %s target requires an operator-owned local profile", name)
	}
	actions := make([]connector.LocalAction, 0, len(profile.Actions))
	for _, action := range profile.Actions {
		timeout, err := action.TimeoutDuration()
		if err != nil {
			return nil, nil, nil, err
		}
		actions = append(actions, connector.LocalAction{
			LogicalName: action.LogicalName, LogicalArgs: action.LogicalArgs,
			Command: action.Command, Args: action.Args, PassArgs: action.PassArgs, Timeout: timeout,
		})
	}
	ops, err := connector.NewLocalOps(connector.LocalOpsConfig{AllowedRoots: profile.AllowedRoots, Actions: actions})
	if err != nil {
		return nil, nil, nil, err
	}
	lease := &connectorCredentialLease{store: r.store, kek: r.kek, crypto: r.crypto, tenantID: payload.TenantID}
	var built connector.Connector
	switch name {
	case "nginx":
		built = nginx.New(target.CertPath, target.KeyPath)
	case "apache":
		built = apache.New(target.CertPath, target.KeyPath)
	case "caddy":
		built = caddy.New(target.CertPath, target.KeyPath)
	case "iis":
		options := []iis.Option{}
		if target.Store != "" {
			options = append(options, iis.WithStore(target.Store))
		}
		if target.AppID != "" {
			options = append(options, iis.WithAppID(target.AppID))
		}
		if target.ImportDir != "" {
			options = append(options, iis.WithImportDir(target.ImportDir))
		}
		built = iis.New(target.Binding, options...)
	case "haproxy":
		built = haproxy.New(target.CRTPath, target.ConfigPath)
	case "postfix":
		built = postfix.New(postfix.Config{
			Postfix: postfix.ServiceConfig{CertPath: target.PostfixCertPath, KeyPath: target.PostfixKeyPath},
			Dovecot: postfix.ServiceConfig{CertPath: target.DovecotCertPath, KeyPath: target.DovecotKeyPath},
		})
	case "traefik":
		built = traefik.New(target.CertPath, target.KeyPath)
	case "java-keystore":
		password, err := lease.require(ctx, target.KeystorePasswordRef)
		if err != nil {
			lease.Close()
			return nil, nil, nil, fmt.Errorf("connector: java keystore password: %w", err)
		}
		options := []javakeystore.Option{}
		if target.Format != "" {
			options = append(options, javakeystore.WithFormat(javakeystore.Format(target.Format)))
		}
		options = append(options, javakeystore.WithReloadAction(target.ReloadAction))
		java := javakeystore.New(target.KeystorePath, password, target.Alias, options...)
		if err := java.Validate(); err != nil {
			java.Close()
			lease.Close()
			return nil, nil, nil, err
		}
		built = java
	case "postgresql":
		built = postgresql.New(target.CertPath, target.KeyPath)
	case "mysql":
		built = mysql.New(target.CertPath, target.KeyPath)
	case "rabbitmq":
		built = rabbitmq.New(target.CertPath, target.KeyPath)
	case "elasticsearch":
		built = elasticsearch.New(target.CertPath, target.KeyPath)
	case "tomcat":
		built = tomcat.New(target.CertPath, target.KeyPath)
	}
	if built == nil {
		lease.Close()
		return nil, nil, nil, fmt.Errorf("connector: no local constructor for %q", name)
	}
	return built, ops, connectorAttemptCleanup(built, lease), nil
}

func buildHTTPConnector(r nativeConnectorRuntime, ctx context.Context, name string, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
	target, err := validatedHTTPConnectorTarget(r.cfg, name, payload.TargetConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	lease := &connectorCredentialLease{store: r.store, kek: r.kek, crypto: r.crypto, tenantID: payload.TenantID}
	var (
		built   connector.Connector
		destroy []interface{ Destroy() }
	)
	require := func(ref, label string) ([]byte, error) {
		value, err := lease.require(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		return value, nil
	}
	switch name {
	case "envoy":
		built = envoy.New(target.Endpoint, target.SecretName)
	case "a10":
		password, err := require(target.PasswordRef, "a10 password")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		built = a10.New(target.Endpoint, target.Username, password)
	case "f5":
		password, err := require(target.PasswordRef, "f5 password")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		options := []f5.Option{f5.WithBasicAuthBytes(target.Username, password)}
		if target.ObjectName != "" {
			options = append(options, f5.WithName(target.ObjectName))
		}
		built = f5.New(target.Endpoint, target.ClientSSLProfile, options...)
	case "netscaler":
		password, err := require(target.PasswordRef, "netscaler password")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		options := []netscaler.Option{}
		if target.FileLocation != "" {
			options = append(options, netscaler.WithFileLocation(target.FileLocation))
		}
		built = netscaler.New(target.Endpoint, target.Username, password, options...)
	case "kemp":
		token, err := require(target.TokenRef, "kemp token")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		built = kemp.New(target.Endpoint, token)
	case "cisco":
		password, err := require(target.PasswordRef, "cisco password")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		built = cisco.New(target.Endpoint, target.Username, password)
	case "fortigate":
		token, err := require(target.TokenRef, "fortigate token")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		built = fortigate.New(target.Endpoint, token)
	case "paloalto":
		apiKey, err := require(target.APIKeyRef, "palo alto API key")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		built = paloalto.New(target.Endpoint, apiKey)
	case "aws-acm":
		accessSecret, err := require(target.SecretAccessKeyRef, "AWS secret access key")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		var session []byte
		if target.SessionTokenRef != "" {
			session, err = require(target.SessionTokenRef, "AWS session token")
			if err != nil {
				lease.Close()
				return nil, nil, nil, err
			}
		}
		built = acm.New(target.Region, acm.Credentials{
			AccessKeyID: target.AccessKeyID, SecretAccessKey: accessSecret, SessionToken: session,
		}, acm.WithEndpoint(target.Endpoint))
	case "azure-keyvault":
		token, err := require(target.BearerTokenRef, "Azure bearer token")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		provider := azurekv.StaticToken(token)
		if d, ok := provider.(interface{ Destroy() }); ok {
			destroy = append(destroy, d)
		}
		options := []azurekv.Option{}
		if target.APIVersion != "" {
			options = append(options, azurekv.WithAPIVersion(target.APIVersion))
		}
		built = azurekv.New(target.Endpoint, provider, options...)
	case "gcp-certificate-manager":
		token, err := require(target.BearerTokenRef, "GCP bearer token")
		if err != nil {
			lease.Close()
			return nil, nil, nil, err
		}
		provider := gcpcm.StaticToken(token)
		if d, ok := provider.(interface{ Destroy() }); ok {
			destroy = append(destroy, d)
		}
		options := []gcpcm.Option{gcpcm.WithEndpoint(target.Endpoint)}
		if target.PollInterval != "" {
			interval, err := time.ParseDuration(target.PollInterval)
			if err != nil || interval <= 0 {
				lease.Close()
				return nil, nil, nil, fmt.Errorf("connector: invalid GCP poll_interval")
			}
			options = append(options, gcpcm.WithPollInterval(interval))
		}
		built = gcpcm.New(target.Project, target.Location, provider, options...)
	}
	if built == nil {
		lease.Close()
		return nil, nil, nil, fmt.Errorf("connector: no HTTP constructor for %q", name)
	}
	cleanup := connectorAttemptCleanup(built, lease, destroy...)
	return built, connector.NewHTTPOps(httpConnectorClient(r, target.Endpoint)), cleanup, nil
}

func validatedHTTPConnectorTarget(cfg config.Connectors, name string, raw json.RawMessage) (nativeTargetConfig, error) {
	target, err := decodeNativeTarget(name, raw)
	if err != nil {
		return nativeTargetConfig{}, err
	}
	if err := validateConnectorEndpoint(target.Endpoint, cfg); err != nil {
		return nativeTargetConfig{}, err
	}
	return target, nil
}

func httpConnectorClient(r nativeConnectorRuntime, endpoint string) *http.Client {
	if !netsec.IsInsecureLoopbackHTTPURL(endpoint) {
		return r.httpClient
	}
	client := netsec.InsecureLoopbackClient(r.httpClient.Timeout)
	if r.guard != nil {
		client.Transport = r.guard.WrapTransport(client.Transport)
	}
	return client
}

func validateConnectorEndpoint(raw string, cfg config.Connectors) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("connector: endpoint must be an absolute URL without userinfo")
	}
	if parsed.Scheme != "https" && (!cfg.AllowInsecureHTTP || parsed.Scheme != "http" || !connectorLoopbackHost(parsed.Hostname())) {
		return fmt.Errorf("connector: endpoint must use https (explicit insecure HTTP is allowed only for a loopback emulator)")
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowPrivateCIDRs))
	for _, value := range cfg.AllowPrivateCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(value)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, prefix)
	}
	check := *parsed
	check.Scheme = "https"
	return netsec.ValidatePublicHTTPSURLWithOptions(check.String(), netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes})
}

func connectorLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type connectorCredentialLease struct {
	store    *store.Store
	kek      seal.KeyWrapper
	crypto   tenantseal.Access
	tenantID string
	buffers  []*secret.Buffer
}

func (l *connectorCredentialLease) require(ctx context.Context, ref string) ([]byte, error) {
	if l.store == nil || l.kek == nil || strings.TrimSpace(l.tenantID) == "" {
		return nil, errors.New("tenant secret-store runtime is unavailable")
	}
	name, version, err := parseConnectorSecretRef(ref)
	if err != nil {
		return nil, err
	}
	var sealed []byte
	if version == nil {
		record, err := l.store.GetSecret(ctx, l.tenantID, name)
		if err != nil {
			return nil, err
		}
		sealed = record.Sealed
	} else {
		record, err := l.store.GetSecretVersion(ctx, l.tenantID, name, *version)
		if err != nil {
			return nil, err
		}
		sealed = record.Sealed
	}
	plain, err := openTenantValue(ctx, l.crypto, l.kek, l.tenantID, sealed, []byte(l.tenantID+"/secret-store/"+name))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plain)
	buffer, err := secret.NewFrom(bytes.TrimSpace(plain))
	if err != nil {
		return nil, err
	}
	l.buffers = append(l.buffers, buffer)
	return buffer.Bytes(), nil
}

func (l *connectorCredentialLease) Close() {
	if l == nil {
		return
	}
	for _, buffer := range l.buffers {
		buffer.Destroy()
	}
	l.buffers = nil
}

func parseConnectorSecretRef(raw string) (string, *int, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "secret" || parsed.User != nil || parsed.Fragment != "" {
		return "", nil, fmt.Errorf("credential reference must use secret://")
	}
	name := strings.Trim(strings.TrimSpace(parsed.Host+parsed.EscapedPath()), "/")
	name, err = url.PathUnescape(name)
	if err != nil || name == "" || strings.Contains(name, "..") {
		return "", nil, fmt.Errorf("credential reference has an invalid secret name")
	}
	query := parsed.Query()
	for key := range query {
		if key != "version" {
			return "", nil, fmt.Errorf("credential reference query %q is not supported", key)
		}
	}
	if query.Get("version") == "" {
		return name, nil, nil
	}
	version, err := strconv.Atoi(query.Get("version"))
	if err != nil || version <= 0 {
		return "", nil, fmt.Errorf("credential reference version must be positive")
	}
	return name, &version, nil
}

func connectorAttemptCleanup(built connector.Connector, lease *connectorCredentialLease, destroyers ...interface{ Destroy() }) func() {
	return func() {
		for _, destroyer := range destroyers {
			if destroyer != nil {
				destroyer.Destroy()
			}
		}
		if closer, ok := built.(interface{ Close() }); ok {
			closer.Close()
		}
		lease.Close()
	}
}

func decodeNativeTarget(name string, raw json.RawMessage) (nativeTargetConfig, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return nativeTargetConfig{}, fmt.Errorf("connector: %s target_config must be a JSON object", name)
	}
	allowed := nativeTargetFields[name]
	for field := range object {
		if !allowed[field] {
			return nativeTargetConfig{}, fmt.Errorf("connector: %s target_config field %q is not allowed", name, field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var target nativeTargetConfig
	if err := decoder.Decode(&target); err != nil {
		return nativeTargetConfig{}, fmt.Errorf("connector: decode %s target_config: %w", name, err)
	}
	if err := validateNativeTarget(name, target); err != nil {
		return nativeTargetConfig{}, err
	}
	return target, nil
}

func fields(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

var nativeTargetFields = map[string]map[string]bool{
	"nginx":                   fields("profile", "cert_path", "key_path"),
	"apache":                  fields("profile", "cert_path", "key_path"),
	"caddy":                   fields("profile", "cert_path", "key_path"),
	"iis":                     fields("profile", "binding", "store", "app_id", "import_dir"),
	"haproxy":                 fields("profile", "crt_path", "config_path"),
	"postfix":                 fields("profile", "postfix_cert_path", "postfix_key_path", "dovecot_cert_path", "dovecot_key_path"),
	"traefik":                 fields("profile", "cert_path", "key_path"),
	"java-keystore":           fields("profile", "keystore_path", "keystore_password_ref", "alias", "format", "reload_action"),
	"postgresql":              fields("profile", "cert_path", "key_path"),
	"mysql":                   fields("profile", "cert_path", "key_path"),
	"rabbitmq":                fields("profile", "cert_path", "key_path"),
	"elasticsearch":           fields("profile", "cert_path", "key_path"),
	"tomcat":                  fields("profile", "cert_path", "key_path"),
	"envoy":                   fields("endpoint", "secret_name"),
	"a10":                     fields("endpoint", "username", "password_ref"),
	"f5":                      fields("endpoint", "client_ssl_profile", "object_name", "username", "password_ref"),
	"netscaler":               fields("endpoint", "username", "password_ref", "file_location"),
	"kemp":                    fields("endpoint", "token_ref"),
	"cisco":                   fields("endpoint", "username", "password_ref"),
	"fortigate":               fields("endpoint", "token_ref"),
	"paloalto":                fields("endpoint", "api_key_ref"),
	"aws-acm":                 fields("endpoint", "region", "access_key_id", "secret_access_key_ref", "session_token_ref"),
	"azure-keyvault":          fields("endpoint", "bearer_token_ref", "api_version"),
	"gcp-certificate-manager": fields("endpoint", "project", "location", "bearer_token_ref", "poll_interval"),
}

func validateNativeTarget(name string, target nativeTargetConfig) error {
	require := func(values ...string) bool {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return false
			}
		}
		return true
	}
	switch name {
	case "nginx", "apache", "caddy", "traefik", "postgresql", "mysql", "rabbitmq", "elasticsearch", "tomcat":
		if !require(target.Profile, target.CertPath, target.KeyPath) {
			return fmt.Errorf("connector: %s requires profile, cert_path, and key_path", name)
		}
	case "iis":
		if !require(target.Profile, target.Binding, target.ImportDir) {
			return fmt.Errorf("connector: iis requires profile, binding, and import_dir")
		}
	case "haproxy":
		if !require(target.Profile, target.CRTPath, target.ConfigPath) {
			return fmt.Errorf("connector: haproxy requires profile, crt_path, and config_path")
		}
	case "postfix":
		if !require(target.Profile, target.PostfixCertPath, target.PostfixKeyPath, target.DovecotCertPath, target.DovecotKeyPath) {
			return fmt.Errorf("connector: postfix requires profile and both services' cert/key paths")
		}
	case "java-keystore":
		if !require(target.Profile, target.KeystorePath, target.KeystorePasswordRef, target.Alias) || (target.Format != "" && target.Format != "jks" && target.Format != "pkcs12") {
			return fmt.Errorf("connector: java-keystore requires profile/path/password_ref/alias and a valid format")
		}
		if err := javakeystore.ValidateReloadAction(target.ReloadAction); err != nil {
			return err
		}
	case "envoy":
		if !require(target.Endpoint, target.SecretName) {
			return fmt.Errorf("connector: envoy requires endpoint and secret_name")
		}
	case "a10", "cisco", "netscaler":
		if !require(target.Endpoint, target.Username, target.PasswordRef) {
			return fmt.Errorf("connector: %s requires endpoint, username, and password_ref", name)
		}
	case "f5":
		if !require(target.Endpoint, target.ClientSSLProfile, target.Username, target.PasswordRef) {
			return fmt.Errorf("connector: f5 requires endpoint, client_ssl_profile, username, and password_ref")
		}
	case "kemp", "fortigate":
		if !require(target.Endpoint, target.TokenRef) {
			return fmt.Errorf("connector: %s requires endpoint and token_ref", name)
		}
	case "paloalto":
		if !require(target.Endpoint, target.APIKeyRef) {
			return fmt.Errorf("connector: paloalto requires endpoint and api_key_ref")
		}
	case "aws-acm":
		if !require(target.Endpoint, target.Region, target.AccessKeyID, target.SecretAccessKeyRef) {
			return fmt.Errorf("connector: aws-acm requires endpoint, region, access_key_id, and secret_access_key_ref")
		}
	case "azure-keyvault":
		if !require(target.Endpoint, target.BearerTokenRef) {
			return fmt.Errorf("connector: azure-keyvault requires endpoint and bearer_token_ref")
		}
	case "gcp-certificate-manager":
		if !require(target.Endpoint, target.Project, target.Location, target.BearerTokenRef) {
			return fmt.Errorf("connector: gcp-certificate-manager requires endpoint/project/location/bearer_token_ref")
		}
	default:
		return fmt.Errorf("connector: unknown target schema %q", name)
	}
	return nil
}
