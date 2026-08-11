// SPDX-License-Identifier: MPL-2.0

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
	certPEM, ok := material["credential.cert_pem"]
	if !ok || len(certPEM) == 0 {
		return connector.Stats{}, errors.New("relay: redeemed material carries no certificate")
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
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: intent.Fingerprint,
	})
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
		return traefik.New(target.CertPath, target.KeyPath), nil
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
		return javakeystore.New(target.KeystorePath, password, target.Alias, options...), nil
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
