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

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	connectorwasm "trstctl.com/trstctl/internal/connector/wasm/host"
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
	// sandbox returns the WASM runtime the connector families run in; nil when
	// connectors.isolation is in_process.
	sandbox func() (*connectorwasm.Runtime, error)
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
	isolation := connector.IsolationInProcess
	if cfg.SandboxedConnectors() {
		runtime.sandbox = connectorwasm.Builtin
		isolation = connector.IsolationWASMSandbox
		// Compile the embedded module now, off the startup path, so the first
		// delivery does not pay for it.
		go func() { _, _ = connectorwasm.Builtin() }()
	}
	if err := registry.DeclareIsolation(isolation); err != nil {
		return nil, err
	}
	for _, raw := range cfg.Enabled {
		name := strings.TrimSpace(raw)
		factory, err := nativeConnectorFactory(runtime, name)
		if err != nil {
			return nil, err
		}
		if err := registry.RegisterFactoryWithReplaySafety(name, factory, nativeConnectorReplaySafety(name)); err != nil {
			return nil, err
		}
		if grant, ok := NativeConnectorGrant(name); ok {
			if err := registry.DeclareCapabilities(name, grant); err != nil {
				return nil, err
			}
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
// kind of judgment a derivation would get wrong.
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
//     Manager — is reached over its management API like an appliance, from
//     inside the VPC or private-endpoint segment a relay sits in, so it is
//     network-relay work (A59). ControlPlaneCarriesNatively keeps the control
//     plane's egress-guarded client as the executor where a tenant runs no
//     relay; ParityProgram records GCP as migrated and ACM/Key Vault as
//     retained exceptions whose APIs cannot express a re-bind.
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
	return netsec.ClientFor(transport, timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}), nil
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
	case "k8s_secret":
		// Agent-only: the in-cluster agent generates the key and writes the
		// Secret. Host-vantage deploys are refused before registry lookup, so the
		// control plane never builds one; enabling it admits the targets.
		return func(context.Context, connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
			return nil, nil, nil, errors.New("connector: k8s_secret executes only on the in-cluster agent")
		}, nil
	default:
		return nil, fmt.Errorf("connector: unsupported production connector %q", name)
	}
}

func buildLocalConnector(r nativeConnectorRuntime, ctx context.Context, name string, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
	target, err := native.DecodeTarget(name, payload.TargetConfig)
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
	credentials := map[string][]byte{}
	built, destroy, err := native.Build(name, target, lease.requirer(ctx, credentials))
	if err != nil {
		lease.Close()
		return nil, nil, nil, err
	}
	cleanup := connectorAttemptCleanup(built, lease, destroy...)
	bound, err := r.bind(built, name, target, credentials)
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	return bound, ops, cleanup, nil
}

func buildHTTPConnector(r nativeConnectorRuntime, ctx context.Context, name string, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
	target, err := validatedHTTPConnectorTarget(r.cfg, name, payload.TargetConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	lease := &connectorCredentialLease{store: r.store, kek: r.kek, crypto: r.crypto, tenantID: payload.TenantID}
	credentials := map[string][]byte{}
	built, destroy, err := native.Build(name, target, lease.requirer(ctx, credentials))
	if err != nil {
		lease.Close()
		return nil, nil, nil, err
	}
	cleanup := connectorAttemptCleanup(built, lease, destroy...)
	bound, err := r.bind(built, name, target, credentials)
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	return bound, connector.NewHTTPOps(httpConnectorClient(r, target.Endpoint)), cleanup, nil
}

// bind runs built's family in the WASM sandbox when connectors are isolated
// (the default): every operation executes in a fresh module instance whose only
// effects are the Sandbox operations it asks for, gated here by the family's
// grant over this attempt's Ops. in_process keeps the host-built connector.
func (r nativeConnectorRuntime) bind(built connector.Connector, name string, target native.Target, credentials map[string][]byte) (connector.Connector, error) {
	if r.sandbox == nil {
		return built, nil
	}
	rt, err := r.sandbox()
	if err != nil {
		return nil, fmt.Errorf("connector: the connector sandbox is unavailable (set connectors.isolation to %q to run connectors in process): %w", config.ConnectorIsolationInProcess, err)
	}
	return rt.Bind(built, name, target, credentials)
}

func validatedHTTPConnectorTarget(cfg config.Connectors, name string, raw json.RawMessage) (native.Target, error) {
	target, err := native.DecodeTarget(name, raw)
	if err != nil {
		return native.Target{}, err
	}
	if err := validateConnectorEndpoint(target.Endpoint, cfg); err != nil {
		return native.Target{}, err
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

// requirer adapts the lease to native.Require: each reference is resolved from
// the tenant's secret store and owned by the lease until Close. Each resolved
// value is also recorded by reference, so a sandboxed connector receives
// exactly the credentials its family asked for.
func (l *connectorCredentialLease) requirer(ctx context.Context, record map[string][]byte) native.Require {
	return func(ref, _ string) ([]byte, error) {
		value, err := l.require(ctx, ref)
		if err == nil {
			record[ref] = value
		}
		return value, err
	}
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
