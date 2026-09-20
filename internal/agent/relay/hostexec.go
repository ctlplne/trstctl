// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/apache"
	"trstctl.com/trstctl/internal/connector/caddy"
	"trstctl.com/trstctl/internal/connector/elasticsearch"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/haproxy"
	"trstctl.com/trstctl/internal/connector/iis"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/connector/mysql"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/postfix"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
	"trstctl.com/trstctl/internal/connector/tomcat"
	"trstctl.com/trstctl/internal/connector/traefik"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// Host-executed connector deploys (epic D1).
//
// Thirteen connectors write files and run reload commands. Envoy is the
// fourteenth host-vantage connector: its co-resident SDS endpoint is HTTP, but
// it is still reachable only from the serving host. Until now they did
// that against the CONTROL PLANE's filesystem — which is doctrine D1's founding
// defect stated as plainly as it can be: the machine that decided the deploy is
// not the machine the certificate belongs on, and a product that writes
// /etc/nginx/ on its own host has not deployed anything to a customer's estate.
//
// The connector implementations move here unchanged. They were always
// host-neutral: NewLocalOps canonicalizes its allowed roots, Lstats every
// command, bans shell interpreters, and refuses any argv that is not an exact
// match — none of which cared which machine it ran on. What changes is which
// filesystem it resolves against, and therefore which machine's paths and
// binaries the operator profile has to describe.
//
// That is why the profile moves with it. An exec allowlist that names
// /usr/sbin/nginx is a statement about a host; keeping it on the control plane
// while the exec happens on an agent would mean an operator authorizing a
// binary on one machine and a different binary running on another.

// HostConnectorKinds is the closed set a host agent can execute. It is exactly
// the connectors whose deploys write files and run reloads on the machine they
// serve; anything else reaching a host agent is refused here rather than
// trusted, the same way the relay refuses appliance work it does not carry.
func HostConnectorKinds() []string {
	return []string{
		"apache", "caddy", "elasticsearch", "envoy", "haproxy", "iis", "java-keystore",
		"mysql", "nginx", "postfix", "postgresql", "rabbitmq", "tomcat", "traefik",
	}
}

// RequiresHostExecProfile reports whether this connector writes local files or
// runs allowlisted commands. Envoy is host-vantage too, but uses only the
// co-resident HTTP SDS endpoint and needs no filesystem/exec grant.
func RequiresHostExecProfile(name string) bool {
	return ExecutesOnHost(name) && name != "envoy"
}

// ExecutesOnHost reports whether this build can execute the named connector on
// the host it runs on.
func ExecutesOnHost(name string) bool {
	for _, kind := range HostConnectorKinds() {
		if kind == name {
			return true
		}
	}
	return false
}

// HostProfile is the operator-owned exec allowlist, read from a file ON THE
// HOST that will run the commands.
//
// A file rather than flags, deliberately. This is estate topology — which
// directories may be written, which binaries may run, with exactly which
// arguments — and it is the security boundary that keeps a compromised control
// plane from running arbitrary commands on a customer's machine. Putting it in
// argv would expose it in the process table and make it something a deployment
// system rewrites; putting it in a file makes it something an operator owns.
type HostProfile struct {
	// AllowedRoots are the only directories a connector may write into. Every
	// path is canonicalized and symlinked parents fail closed.
	AllowedRoots []string `json:"allowed_roots"`
	// Actions bind a connector's logical command ("reload") to one exact
	// executable and argv on this host. A connector cannot add to this, and
	// neither can a tenant's target configuration.
	Actions []HostAction `json:"actions"`
}

// HostAction is one permitted command.
type HostAction struct {
	LogicalName string   `json:"logical_name"`
	LogicalArgs []string `json:"logical_args,omitempty"`
	Command     string   `json:"command"`
	Args        []string `json:"args,omitempty"`
	PassArgs    bool     `json:"pass_args,omitempty"`
	TimeoutSecs int      `json:"timeout_seconds,omitempty"`
}

// LoadHostProfile reads and validates the operator's profile.
//
// An unreadable or empty profile is an error, never a permissive default: a
// host executor that fell back to "any command" on a missing file would be the
// most dangerous possible failure mode, and one an operator would never see
// until it mattered.
func LoadHostProfile(path string) (connector.LocalOpsConfig, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied profile path, read at their instruction (CWE-22)
	if err != nil {
		return connector.LocalOpsConfig{}, fmt.Errorf("relay: read host profile: %w", err)
	}
	var profile HostProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return connector.LocalOpsConfig{}, fmt.Errorf("relay: decode host profile: %w", err)
	}
	if len(profile.AllowedRoots) == 0 {
		return connector.LocalOpsConfig{}, errors.New("relay: host profile names no allowed roots; a profile that permits nothing is safer than one that permits everything, so this is refused rather than defaulted")
	}
	actions := make([]connector.LocalAction, 0, len(profile.Actions))
	for _, action := range profile.Actions {
		if strings.TrimSpace(action.LogicalName) == "" || strings.TrimSpace(action.Command) == "" {
			return connector.LocalOpsConfig{}, errors.New("relay: every host profile action needs a logical name and a command")
		}
		timeout := time.Duration(action.TimeoutSecs) * time.Second
		actions = append(actions, connector.LocalAction{
			LogicalName: action.LogicalName,
			LogicalArgs: action.LogicalArgs,
			Command:     action.Command,
			Args:        action.Args,
			PassArgs:    action.PassArgs,
			Timeout:     timeout,
		})
	}
	return connector.LocalOpsConfig{AllowedRoots: profile.AllowedRoots, Actions: actions}, nil
}

// HostTargetConfig is the host-side view of a deployment target: the paths and
// options the 13 file/exec connectors and co-resident Envoy need. It covers host-vantage
// connectors only, for the same reason TargetConfig covers relay ones — a host
// agent has no business decoding an appliance's endpoint schema.
type HostTargetConfig struct {
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	CRTPath    string `json:"crt_path,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	SecretName string `json:"secret_name,omitempty"`

	// IIS.
	Binding   string `json:"binding,omitempty"`
	Store     string `json:"store,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	ImportDir string `json:"import_dir,omitempty"`

	// Postfix/Dovecot pair.
	PostfixCertPath string `json:"postfix_cert_path,omitempty"`
	PostfixKeyPath  string `json:"postfix_key_path,omitempty"`
	DovecotCertPath string `json:"dovecot_cert_path,omitempty"`
	DovecotKeyPath  string `json:"dovecot_key_path,omitempty"`

	// Java keystore.
	KeystorePath        string `json:"keystore_path,omitempty"`
	KeystorePasswordRef string `json:"keystore_password_ref,omitempty"`
	Alias               string `json:"alias,omitempty"`
	Format              string `json:"format,omitempty"`
	ReloadAction        string `json:"reload_action,omitempty"`
}

// ExecuteOnHost deploys a credential to a service on the machine this agent runs
// on, through the operator's profile.
//
// It is the host counterpart of Execute, and it is deliberately the same shape:
// same intent, same redeemed material, same connector.Run with the same sandbox.
// The difference is which Ops the connector gets — a filesystem and process
// executor bound to this host's profile, rather than an HTTP client.
func ExecuteOnHost(
	ctx context.Context,
	profile connector.LocalOpsConfig,
	intent DeployIntent,
	material Material,
	clients ...*http.Client,
) (connector.Stats, error) {
	if !ExecutesOnHost(intent.Connector) {
		return connector.Stats{}, fmt.Errorf("relay: connector %q is not host-executable", intent.Connector)
	}
	servingCertPEM, err := servingCertificatePEM(material)
	if err != nil {
		return connector.Stats{}, err
	}
	keyPEM, ok := material["credential.key_pem"]
	if !ok || len(keyPEM) == 0 {
		return connector.Stats{}, errors.New("relay: redeemed material carries no private key")
	}

	var target HostTargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return connector.Stats{}, fmt.Errorf("relay: decode host target config: %w", err)
		}
	}

	built, err := buildHostConnector(intent.Connector, target, material)
	if err != nil {
		return connector.Stats{}, err
	}
	if closer, ok := built.(interface{ Close() }); ok {
		defer closer.Close()
	}
	var ops connector.Ops
	if intent.Connector == "envoy" {
		var client *http.Client
		if len(clients) > 0 {
			client = clients[0]
		}
		ops = connector.NewHTTPOps(client)
	} else {
		// NewLocalOps re-canonicalizes roots and re-Lstats every command HERE,
		// so the authorization and effect bind to the same machine.
		local, localErr := connector.NewLocalOps(profile)
		if localErr != nil {
			return connector.Stats{}, fmt.Errorf("relay: host exec profile is not usable: %w", localErr)
		}
		ops = local
	}
	return connector.Run(ctx, built, ops, connector.Deployment{
		Target:      intent.Target,
		CertPEM:     servingCertPEM,
		KeyPEM:      keyPEM,
		Fingerprint: intent.Fingerprint,
	})
}

// servingCertificatePEM turns the wire representation into the bytes a TLS
// service must install and the rollback ledger must retain. Keeping this in one
// function prevents a subtle split-brain failure where the live deploy receives
// leaf+issuers but recovery remembers only the leaf and restores a listener that
// reloads successfully while standards-compliant clients reject its chain.
func servingCertificatePEM(material Material) ([]byte, error) {
	leafPEM, ok := material["credential.cert_pem"]
	if !ok || len(leafPEM) == 0 {
		return nil, errors.New("relay: redeemed material carries no certificate")
	}
	servingPEM := append([]byte(nil), leafPEM...)
	if chainPEM := material["credential.chain_pem"]; len(chainPEM) > 0 {
		if servingPEM[len(servingPEM)-1] != '\n' {
			servingPEM = append(servingPEM, '\n')
		}
		servingPEM = append(servingPEM, chainPEM...)
	}
	return servingPEM, nil
}

// DryRunOnHost validates a host connector on the machine that would execute it
// and, when configured, handshakes the listener it would later update. It
// performs no deployment: PreflightLocalOps only canonicalizes/Lstats roots and
// commands, and the optional listener check is a read-only TLS handshake.
// Certificate/key material is not required because connector.test proves the
// target path, not a credential that has not been selected for deployment yet.
func DryRunOnHost(
	ctx context.Context,
	client *http.Client,
	profile connector.LocalOpsConfig,
	intent DeployIntent,
	material Material,
) (Plan, error) {
	plan := Plan{Connector: intent.Connector, Target: intent.Target}
	if !ExecutesOnHost(intent.Connector) {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "connector", Status: StepFailed,
			Detail: fmt.Sprintf("connector %q is not executable by a host agent", intent.Connector),
		})
		return plan, nil
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "connector", Status: StepOK,
		Detail: "this host agent carries an executor for " + intent.Connector,
	})

	var target HostTargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			plan.Steps = append(plan.Steps, PlanStep{
				Name: "target-config", Status: StepFailed,
				Detail: "host target configuration did not decode: " + err.Error(),
			})
			return plan, nil
		}
	}
	actions, err := hostPreflightActions(intent.Connector, target)
	if err != nil {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "target-config", Status: StepFailed, Detail: err.Error(),
		})
		return plan, nil
	}
	for _, ref := range intent.CredentialRefs {
		if len(material[strings.TrimSpace(ref)]) == 0 {
			plan.Steps = append(plan.Steps, PlanStep{
				Name: "credentials", Status: StepFailed,
				Detail: "required credential reference " + strings.TrimSpace(ref) + " was not redeemed for this test",
			})
			return plan, nil
		}
	}
	if len(intent.CredentialRefs) == 0 {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "credentials", Status: StepSkipped,
			Detail: "this host target needs no management credential; certificate material is supplied only when a deploy is authorized",
		})
	} else {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "credentials", Status: StepOK,
			Detail: "every host-target credential reference was redeemed for this one test attempt",
		})
	}

	built, err := buildHostConnector(intent.Connector, target, material)
	if err != nil {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "target-config", Status: StepFailed, Detail: err.Error(),
		})
		return plan, nil
	}
	if closer, ok := built.(interface{ Close() }); ok {
		defer closer.Close()
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "target-config", Status: StepOK,
		Detail: "the host target configuration resolves to the shipped " + intent.Connector + " connector",
	})

	if RequiresHostExecProfile(intent.Connector) {
		if len(profile.AllowedRoots) == 0 {
			plan.Steps = append(plan.Steps, PlanStep{
				Name: "host-authority", Status: StepFailed,
				Detail: "this agent has no host exec profile configured for file and reload operations",
			})
			return plan, nil
		}
		if err := connector.PreflightLocalOps(profile, built.Capabilities(), actions); err != nil {
			plan.Steps = append(plan.Steps, PlanStep{
				Name: "host-authority", Status: StepFailed,
				Detail: "operator host authority does not permit this target plan: " + err.Error(),
			})
			return plan, nil
		}
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "host-authority", Status: StepOK,
			Detail: "target directories and logical commands fit inside the operator-owned host exec profile",
		})
	} else {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "host-authority", Status: StepSkipped,
			Detail: "this co-resident connector uses no filesystem or process authority",
		})
	}

	var reachability PlanStep
	if intent.Connector == "envoy" {
		plan.Endpoint = strings.TrimSpace(target.Endpoint)
		reachability = probeEndpoint(ctx, client, plan.Endpoint)
	} else {
		plan.Endpoint = strings.TrimSpace(intent.VerifyAddress)
		reachability = probeHostListener(ctx, plan.Endpoint, strings.TrimSpace(intent.VerifyServerName), connectorTLSNegotiation(intent.Connector))
	}
	plan.Steps = append(plan.Steps, reachability)
	if reachability.Status == StepFailed {
		return plan, nil
	}

	plan.Ready = true
	plan.WouldMutate = wouldMutateOnHost(intent.Connector, target, actions, plan.Endpoint)
	return plan, nil
}

func hostPreflightActions(name string, target HostTargetConfig) ([]connector.LocalActionInvocation, error) {
	require := func(fields ...struct{ label, value string }) error {
		for _, field := range fields {
			if strings.TrimSpace(field.value) == "" {
				return fmt.Errorf("host target configuration requires %s", field.label)
			}
		}
		return nil
	}
	field := func(label, value string) struct{ label, value string } {
		return struct{ label, value string }{label, value}
	}
	action := func(name string, args ...string) connector.LocalActionInvocation {
		return connector.LocalActionInvocation{LogicalName: name, LogicalArgs: args, ArgsKnown: true}
	}

	switch name {
	case "apache":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("apachectl", "configtest"), action("apachectl", "graceful")}, nil
	case "nginx":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("nginx", "-t"), action("nginx", "-s", "reload")}, nil
	case "caddy":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("caddy", "reload")}, nil
	case "haproxy":
		if err := require(field("crt_path", target.CRTPath), field("config_path", target.ConfigPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("haproxy", "-c", "-f", target.ConfigPath), action("systemctl", "reload", "haproxy")}, nil
	case "mysql":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action(mysql.TLSReloadAction)}, nil
	case "postgresql":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("pg_ctl", "reload")}, nil
	case "rabbitmq":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action("rabbitmqctl", "rotate_certs")}, nil
	case "tomcat":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{action(tomcat.TLSReloadAction)}, nil
	case "postfix":
		if err := require(
			field("postfix_cert_path", target.PostfixCertPath), field("postfix_key_path", target.PostfixKeyPath),
			field("dovecot_cert_path", target.DovecotCertPath), field("dovecot_key_path", target.DovecotKeyPath)); err != nil {
			return nil, err
		}
		return []connector.LocalActionInvocation{
			action("postfix", "check"), action("doveconf", "-n"),
			action("postfix", "reload"), action("doveadm", "reload"),
		}, nil
	case "iis":
		if err := require(field("binding", target.Binding), field("import_dir", target.ImportDir)); err != nil {
			return nil, err
		}
		// The complete argv includes the certificate thumbprint and staged PFX
		// filename selected only at deploy time. The profile's action names and
		// executable safety are still checked now; exact argv is enforced again
		// by LocalOps when the real deploy supplies it.
		return []connector.LocalActionInvocation{
			{LogicalName: "powershell", ArgsKnown: false},
			{LogicalName: "netsh", ArgsKnown: false},
		}, nil
	case "java-keystore":
		if err := require(field("keystore_path", target.KeystorePath), field("keystore_password_ref", target.KeystorePasswordRef)); err != nil {
			return nil, err
		}
		if err := javakeystore.ValidateReloadAction(target.ReloadAction); err != nil {
			return nil, err
		}
		if target.ReloadAction != "" {
			return []connector.LocalActionInvocation{action(target.ReloadAction)}, nil
		}
		return nil, nil
	case "elasticsearch":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath)); err != nil {
			return nil, err
		}
		return nil, nil
	case "traefik":
		if err := require(field("cert_path", target.CertPath), field("key_path", target.KeyPath), field("config_path", target.ConfigPath)); err != nil {
			return nil, err
		}
		return nil, nil
	case "envoy":
		if err := require(field("endpoint", target.Endpoint), field("secret_name", target.SecretName)); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("connector %q has no host preflight plan", name)
	}
}

func probeHostListener(ctx context.Context, address, serverName string, negotiate tlsprobe.PreHandshake) PlanStep {
	if strings.TrimSpace(address) == "" {
		return PlanStep{Name: "reachability", Status: StepSkipped,
			Detail: "no verify_address is configured; this deploy can proceed, but trstctl will not claim the certificate is live until a listener address is added and verified"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, dryRunProbeTimeout)
	defer cancel()
	observed, err := tlsprobe.Probe(probeCtx, address,
		tlsprobe.WithTimeout(dryRunProbeTimeout), tlsprobe.WithServerName(serverName), tlsprobe.WithPreHandshake(negotiate))
	if err != nil {
		return PlanStep{Name: "reachability", Status: StepFailed,
			Detail: "could not handshake the configured listener: " + transport.SanitizeProbeError(err)}
	}
	if len(observed.PeerCertificates) == 0 {
		return PlanStep{Name: "reachability", Status: StepFailed,
			Detail: "the configured listener completed TLS but presented no certificate"}
	}
	leaf, err := certinfo.Inspect(observed.PeerCertificates[0])
	if err != nil {
		return PlanStep{Name: "reachability", Status: StepFailed,
			Detail: "the configured listener presented an unreadable certificate"}
	}
	if serverName != "" && certinfo.VerifyHostname(observed.PeerCertificates[0], serverName) != nil {
		return PlanStep{Name: "reachability", Status: StepFailed,
			Detail: "the listener is reachable but its current certificate is not valid for verify_server_name " + serverName}
	}
	fingerprint := strings.ToLower(strings.ReplaceAll(leaf.SHA256Fingerprint, ":", ""))
	if len(fingerprint) > 12 {
		fingerprint = fingerprint[:12]
	}
	return PlanStep{Name: "reachability", Status: StepOK,
		Detail: "TLS handshake reached " + address + " and observed current public leaf " + fingerprint + "; CA trust was not assumed or changed"}
}

func wouldMutateOnHost(name string, target HostTargetConfig, actions []connector.LocalActionInvocation, endpoint string) []string {
	var changes []string
	appendPath := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			changes = append(changes, "replace "+label+" at "+value)
		}
	}
	switch name {
	case "haproxy":
		appendPath("certificate/key bundle", target.CRTPath)
	case "java-keystore":
		appendPath("Java keystore", target.KeystorePath)
	case "iis":
		changes = append(changes, "import the certificate into the Windows "+nonemptyHost(target.Store, "MY")+" store")
		changes = append(changes, "bind it to IIS listener "+target.Binding)
	case "postfix":
		appendPath("Postfix certificate", target.PostfixCertPath)
		appendPath("Postfix private key", target.PostfixKeyPath)
		appendPath("Dovecot certificate", target.DovecotCertPath)
		appendPath("Dovecot private key", target.DovecotKeyPath)
	case "envoy":
		changes = append(changes, "replace co-resident Envoy SDS secret "+target.SecretName)
	default:
		appendPath("certificate", target.CertPath)
		appendPath("private key", target.KeyPath)
	}
	for _, invocation := range actions {
		if invocation.ArgsKnown {
			changes = append(changes, "run operator-approved "+strings.TrimSpace(invocation.LogicalName+" "+strings.Join(invocation.LogicalArgs, " ")))
		} else {
			changes = append(changes, "run operator-approved "+invocation.LogicalName+" action with deploy-bound arguments")
		}
	}
	if endpoint != "" && name != "envoy" {
		changes = append(changes, "handshake "+endpoint+" and require the newly deployed certificate before reporting verified")
	}
	return changes
}

func nonemptyHost(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// buildHostConnector constructs the named file/exec connector. It mirrors the
// control plane's factory for the same thirteen kinds — same constructors, same
// options — because they are the same implementations.
func buildHostConnector(name string, target HostTargetConfig, material Material) (connector.Connector, error) {
	switch name {
	case "nginx":
		return nginx.New(target.CertPath, target.KeyPath), nil
	case "apache":
		return apache.New(target.CertPath, target.KeyPath), nil
	case "caddy":
		return caddy.New(target.CertPath, target.KeyPath), nil
	case "traefik":
		if strings.TrimSpace(target.ConfigPath) == "" {
			return nil, errors.New("relay: traefik target needs config_path so its file provider can be notified after credential changes")
		}
		return traefik.New(target.CertPath, target.KeyPath,
			traefik.WithDynamicConfigPath(target.ConfigPath)), nil
	case "postgresql":
		return postgresql.New(target.CertPath, target.KeyPath), nil
	case "mysql":
		return mysql.New(target.CertPath, target.KeyPath), nil
	case "rabbitmq":
		return rabbitmq.New(target.CertPath, target.KeyPath), nil
	case "elasticsearch":
		return elasticsearch.New(target.CertPath, target.KeyPath), nil
	case "envoy":
		if err := validateCoResidentEnvoyEndpoint(target.Endpoint); err != nil {
			return nil, err
		}
		return envoy.New(target.Endpoint, target.SecretName), nil
	case "tomcat":
		return tomcat.New(target.CertPath, target.KeyPath), nil
	case "haproxy":
		return haproxy.New(target.CRTPath, target.ConfigPath), nil
	case "postfix":
		return postfix.New(postfix.Config{
			Postfix: postfix.ServiceConfig{CertPath: target.PostfixCertPath, KeyPath: target.PostfixKeyPath},
			Dovecot: postfix.ServiceConfig{CertPath: target.DovecotCertPath, KeyPath: target.DovecotKeyPath},
		}), nil
	case "iis":
		var options []iis.Option
		if target.Store != "" {
			options = append(options, iis.WithStore(target.Store))
		}
		if target.AppID != "" {
			options = append(options, iis.WithAppID(target.AppID))
		}
		if target.ImportDir != "" {
			options = append(options, iis.WithImportDir(target.ImportDir))
		}
		return iis.New(target.Binding, options...), nil
	case "java-keystore":
		ref := strings.TrimSpace(target.KeystorePasswordRef)
		if ref == "" {
			return nil, errors.New("relay: java-keystore target needs a keystore password reference")
		}
		password, ok := material[ref]
		if !ok || len(password) == 0 {
			return nil, errors.New("relay: the java keystore password was not redeemed for this attempt")
		}
		var options []javakeystore.Option
		if target.Format != "" {
			options = append(options, javakeystore.WithFormat(javakeystore.Format(target.Format)))
		}
		options = append(options, javakeystore.WithReloadAction(target.ReloadAction))
		built := javakeystore.New(target.KeystorePath, password, target.Alias, options...)
		if err := built.Validate(); err != nil {
			built.Close()
			return nil, err
		}
		return built, nil
	default:
		return nil, fmt.Errorf("relay: connector %q is not host-executable", name)
	}
}

func validateCoResidentEnvoyEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("relay: host Envoy endpoint must be an absolute HTTP(S) loopback URL without user info")
	}
	host := strings.TrimSpace(u.Hostname())
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("relay: host Envoy endpoint must name localhost or a literal loopback address")
	}
	return nil
}

func preflightJavaRenewal(profile connector.LocalOpsConfig, intent DeployIntent, material Material) error {
	var target HostTargetConfig
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
		return errors.New("java target configuration did not decode")
	}
	actions, err := hostPreflightActions("java-keystore", target)
	if err != nil {
		return err
	}
	built, err := buildHostConnector("java-keystore", target, material)
	if err != nil {
		return err
	}
	defer built.(interface{ Close() }).Close()
	return connector.PreflightLocalOps(profile, built.Capabilities(), actions)
}
