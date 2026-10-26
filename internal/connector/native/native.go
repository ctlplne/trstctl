// SPDX-License-Identifier: BUSL-1.1

// Package native is the constructor census for the shipped connector families:
// it decodes a deployment target's closed configuration schema and builds the
// connector that target describes. The control plane and the WASM connector
// guest both build through it, so a connector constructed inside the sandbox is
// exactly the one the host would have constructed. It is host-neutral:
// credentials arrive through a Require function, never from a store.
package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
)

// Target is the closed configuration schema of one deployment target. Each
// family accepts only its own fields (DecodeTarget); credentials are secret://
// references, resolved just in time by the host.
type Target struct {
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
	BindTo           string `json:"bind_to,omitempty"`
	SSLTLSProfile    string `json:"ssl_tls_profile,omitempty"`
	CommitAdmin      string `json:"commit_admin,omitempty"`
	// NodeHostname and CertificateRoles select the cisco connector's ISE mode
	// (A122): role-bound, fingerprint-named system certificates.
	NodeHostname     string   `json:"node_hostname,omitempty"`
	CertificateRoles []string `json:"certificate_roles,omitempty"`

	Region             string `json:"region,omitempty"`
	AccessKeyID        string `json:"access_key_id,omitempty"`
	SecretAccessKeyRef string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef    string `json:"session_token_ref,omitempty"`
	Project            string `json:"project,omitempty"`
	Location           string `json:"location,omitempty"`
	BearerTokenRef     string `json:"bearer_token_ref,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	PollInterval       string `json:"poll_interval,omitempty"`
	// CertificateMapEntry ("map/entry") makes gcp-certificate-manager deploys
	// fingerprint-named and bound, which is what makes the target
	// rollback-capable (A58).
	CertificateMapEntry string `json:"certificate_map_entry,omitempty"`
	// Vantage lets an envoy target declare "network" so a relay drives a
	// remote SDS endpoint instead of the co-resident host agent (A61).
	Vantage string `json:"vantage,omitempty"`

	// PeerEndpoint names the standby BIG-IP of an F5 HA pair a network relay
	// drives (epic E1); PeerObjectName overrides the crypto object base name
	// on the peer. The control plane's closed schema does not accept them.
	PeerEndpoint   string `json:"peer_endpoint,omitempty"`
	PeerObjectName string `json:"peer_object_name,omitempty"`
}

func fields(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

// targetFields is each family's closed schema.
var targetFields = map[string]map[string]bool{
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
	"envoy":                   fields("endpoint", "secret_name", "vantage"),
	"a10":                     fields("endpoint", "username", "password_ref"),
	"f5":                      fields("endpoint", "client_ssl_profile", "object_name", "username", "password_ref"),
	"netscaler":               fields("endpoint", "username", "password_ref", "file_location"),
	"kemp":                    fields("endpoint", "token_ref"),
	"cisco":                   fields("endpoint", "username", "password_ref", "node_hostname", "certificate_roles"),
	"fortigate":               fields("endpoint", "token_ref"),
	"paloalto":                fields("endpoint", "api_key_ref"),
	"aws-acm":                 fields("endpoint", "region", "access_key_id", "secret_access_key_ref", "session_token_ref"),
	"azure-keyvault":          fields("endpoint", "bearer_token_ref", "api_version"),
	"gcp-certificate-manager": fields("endpoint", "project", "location", "bearer_token_ref", "poll_interval", "certificate_map_entry"),
}

// DecodeTarget decodes and validates family's closed target schema: a field
// another family uses, or an unknown field, is refused.
func DecodeTarget(family string, raw json.RawMessage) (Target, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return Target{}, fmt.Errorf("connector: %s target_config must be a JSON object", family)
	}
	allowed := targetFields[family]
	for field := range object {
		if !allowed[field] {
			return Target{}, fmt.Errorf("connector: %s target_config field %q is not allowed", family, field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var target Target
	if err := decoder.Decode(&target); err != nil {
		return Target{}, fmt.Errorf("connector: decode %s target_config: %w", family, err)
	}
	if err := validateTarget(family, target); err != nil {
		return Target{}, err
	}
	return target, nil
}

func validateTarget(name string, target Target) error {
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
		if v := strings.ToLower(strings.TrimSpace(target.Vantage)); v != "" && v != connector.VantageNetworkDeclaration {
			return fmt.Errorf("connector: envoy vantage must be empty (co-resident host agent) or %q", connector.VantageNetworkDeclaration)
		}
	case "a10", "cisco", "netscaler":
		if !require(target.Endpoint, target.Username, target.PasswordRef) {
			return fmt.Errorf("connector: %s requires endpoint, username, and password_ref", name)
		}
		if name == "cisco" {
			if err := cisco.ValidateISETarget(target.NodeHostname, target.CertificateRoles); err != nil {
				return err
			}
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
		if _, err := gcpcm.ParseCertificateMapEntry(target.CertificateMapEntry); err != nil {
			return err
		}
	default:
		return fmt.Errorf("connector: unknown target schema %q", name)
	}
	return nil
}

// Require resolves one credential reference to its bytes. The control plane
// leases it from the tenant's secret store; the WASM guest reads it from the
// set the host resolved for that one call. label names the credential in errors.
type Require func(ref, label string) ([]byte, error)

// Build constructs family's connector for target. The returned destroyers wipe
// credential material the connector owns; the caller runs them, with the
// connector's own Close if it has one, when the attempt ends.
func Build(family string, target Target, require Require) (connector.Connector, []interface{ Destroy() }, error) {
	if built, ok := buildLocal(family, target); ok {
		return built, nil, nil
	}
	switch family {
	case "java-keystore":
		password, err := credential(require, target.KeystorePasswordRef, "java keystore password")
		if err != nil {
			return nil, nil, fmt.Errorf("connector: %w", err)
		}
		options := []javakeystore.Option{}
		if target.Format != "" {
			options = append(options, javakeystore.WithFormat(javakeystore.Format(target.Format)))
		}
		options = append(options, javakeystore.WithReloadAction(target.ReloadAction))
		java := javakeystore.New(target.KeystorePath, password, target.Alias, options...)
		if err := java.Validate(); err != nil {
			java.Close()
			return nil, nil, err
		}
		return java, nil, nil
	case "aws-acm", "azure-keyvault", "gcp-certificate-manager":
		return buildCloud(family, target, require)
	}
	built, err := buildAppliance(family, target, require)
	if err != nil {
		return nil, nil, err
	}
	return built, nil, nil
}

// buildLocal constructs the file-mode families, which take no credentials.
func buildLocal(family string, target Target) (connector.Connector, bool) {
	switch family {
	case "nginx":
		return nginx.New(target.CertPath, target.KeyPath), true
	case "apache":
		return apache.New(target.CertPath, target.KeyPath), true
	case "caddy":
		return caddy.New(target.CertPath, target.KeyPath), true
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
		return iis.New(target.Binding, options...), true
	case "haproxy":
		return haproxy.New(target.CRTPath, target.ConfigPath), true
	case "postfix":
		return postfix.New(postfix.Config{
			Postfix: postfix.ServiceConfig{CertPath: target.PostfixCertPath, KeyPath: target.PostfixKeyPath},
			Dovecot: postfix.ServiceConfig{CertPath: target.DovecotCertPath, KeyPath: target.DovecotKeyPath},
		}), true
	case "traefik":
		// A host agent's traefik target names the file provider's dynamic
		// configuration so traefik is notified after a credential change.
		if strings.TrimSpace(target.ConfigPath) != "" {
			return traefik.New(target.CertPath, target.KeyPath, traefik.WithDynamicConfigPath(target.ConfigPath)), true
		}
		return traefik.New(target.CertPath, target.KeyPath), true
	case "postgresql":
		return postgresql.New(target.CertPath, target.KeyPath), true
	case "mysql":
		return mysql.New(target.CertPath, target.KeyPath), true
	case "rabbitmq":
		return rabbitmq.New(target.CertPath, target.KeyPath), true
	case "elasticsearch":
		return elasticsearch.New(target.CertPath, target.KeyPath), true
	case "tomcat":
		return tomcat.New(target.CertPath, target.KeyPath), true
	}
	return nil, false
}

// credential resolves one reference, naming the credential in its error.
func credential(require Require, ref, label string) ([]byte, error) {
	value, err := require(ref, label)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return value, nil
}

// buildAppliance constructs the network-appliance families.
func buildAppliance(family string, target Target, require Require) (connector.Connector, error) {
	switch family {
	case "envoy":
		return envoy.New(target.Endpoint, target.SecretName), nil
	case "a10":
		password, err := credential(require, target.PasswordRef, "a10 password")
		if err != nil {
			return nil, err
		}
		return a10.New(target.Endpoint, target.Username, password), nil
	case "f5":
		password, err := credential(require, target.PasswordRef, "f5 password")
		if err != nil {
			return nil, err
		}
		options := []f5.Option{f5.WithBasicAuthBytes(target.Username, password)}
		if target.ObjectName != "" {
			options = append(options, f5.WithName(target.ObjectName))
		}
		active := f5.New(target.Endpoint, target.ClientSSLProfile, options...)
		if strings.TrimSpace(target.PeerEndpoint) == "" {
			return active, nil
		}
		// HA pair: the standby shares the synced admin credential (E1), and
		// both peers must converge.
		peerOptions := []f5.Option{f5.WithBasicAuthBytes(target.Username, password)}
		peerName := target.ObjectName
		if target.PeerObjectName != "" {
			peerName = target.PeerObjectName
		}
		if peerName != "" {
			peerOptions = append(peerOptions, f5.WithName(peerName))
		}
		return f5.NewHAPair(active, f5.New(target.PeerEndpoint, target.ClientSSLProfile, peerOptions...)), nil
	case "netscaler":
		password, err := credential(require, target.PasswordRef, "netscaler password")
		if err != nil {
			return nil, err
		}
		options := []netscaler.Option{}
		if target.FileLocation != "" {
			options = append(options, netscaler.WithFileLocation(target.FileLocation))
		}
		return netscaler.New(target.Endpoint, target.Username, password, options...), nil
	case "kemp":
		token, err := credential(require, target.TokenRef, "kemp token")
		if err != nil {
			return nil, err
		}
		return kemp.New(target.Endpoint, token), nil
	case "cisco":
		password, err := credential(require, target.PasswordRef, "cisco password")
		if err != nil {
			return nil, err
		}
		if err := cisco.ValidateISETarget(target.NodeHostname, target.CertificateRoles); err != nil {
			return nil, err
		}
		var options []cisco.Option
		if strings.TrimSpace(target.NodeHostname) != "" {
			options = append(options, cisco.WithISENode(target.NodeHostname, target.CertificateRoles))
		}
		return cisco.New(target.Endpoint, target.Username, password, options...), nil
	case "fortigate":
		token, err := credential(require, target.TokenRef, "fortigate token")
		if err != nil {
			return nil, err
		}
		bind, err := fortigate.ParseBindTo(target.BindTo)
		if err != nil {
			return nil, err
		}
		return fortigate.New(target.Endpoint, token, fortigate.WithBindTo(bind)), nil
	case "paloalto":
		apiKey, err := credential(require, target.APIKeyRef, "palo alto API key")
		if err != nil {
			return nil, err
		}
		return paloalto.New(target.Endpoint, apiKey, paloalto.WithSSLTLSProfile(target.SSLTLSProfile, target.CommitAdmin)), nil
	}
	return nil, fmt.Errorf("connector: no constructor for %q", family)
}

// buildCloud constructs the cloud certificate-store families.
func buildCloud(name string, target Target, require Require) (connector.Connector, []interface{ Destroy() }, error) {
	var destroy []interface{ Destroy() }
	switch name {
	case "aws-acm":
		accessSecret, err := credential(require, target.SecretAccessKeyRef, "AWS secret access key")
		if err != nil {
			return nil, nil, err
		}
		var session []byte
		if target.SessionTokenRef != "" {
			session, err = credential(require, target.SessionTokenRef, "AWS session token")
			if err != nil {
				return nil, nil, err
			}
		}
		return acm.New(target.Region, acm.Credentials{
			AccessKeyID: target.AccessKeyID, SecretAccessKey: accessSecret, SessionToken: session,
		}, acm.WithEndpoint(target.Endpoint)), nil, nil
	case "azure-keyvault":
		token, err := credential(require, target.BearerTokenRef, "Azure bearer token")
		if err != nil {
			return nil, nil, err
		}
		provider := azurekv.StaticToken(token)
		if d, ok := provider.(interface{ Destroy() }); ok {
			destroy = append(destroy, d)
		}
		options := []azurekv.Option{}
		if target.APIVersion != "" {
			options = append(options, azurekv.WithAPIVersion(target.APIVersion))
		}
		return azurekv.New(target.Endpoint, provider, options...), destroy, nil
	case "gcp-certificate-manager":
		token, err := credential(require, target.BearerTokenRef, "GCP bearer token")
		if err != nil {
			return nil, nil, err
		}
		provider := gcpcm.StaticToken(token)
		if d, ok := provider.(interface{ Destroy() }); ok {
			destroy = append(destroy, d)
		}
		options := []gcpcm.Option{gcpcm.WithEndpoint(target.Endpoint)}
		if entry, err := gcpcm.ParseCertificateMapEntry(target.CertificateMapEntry); err != nil {
			destroyAll(destroy)
			return nil, nil, err
		} else if entry.Map != "" {
			options = append(options, gcpcm.WithCertificateMapEntry(entry))
		}
		if target.PollInterval != "" {
			interval, err := time.ParseDuration(target.PollInterval)
			if err != nil || interval <= 0 {
				destroyAll(destroy)
				return nil, nil, fmt.Errorf("connector: invalid GCP poll_interval")
			}
			options = append(options, gcpcm.WithPollInterval(interval))
		}
		return gcpcm.New(target.Project, target.Location, provider, options...), destroy, nil
	}
	return nil, nil, fmt.Errorf("connector: no cloud constructor for %q", name)
}

func destroyAll(destroyers []interface{ Destroy() }) {
	for _, d := range destroyers {
		d.Destroy()
	}
}
