// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/netsec"
)

// ExternalCATypes is the closed set of upstream certificate-authority drivers
// compiled into the shipped control-plane binary. An integration is reachable
// only when an operator creates an external_cas entry for it.
var ExternalCATypes = []string{
	"adcs", "awspca", "azurekv", "digicert", "ejbca", "entrust",
	"gcpcas", "globalsign", "letsencrypt", "sectigo", "shellca",
	"smallstep", "vaultpki", "venafi",
}

// ExternalCAConfig is one operator-owned upstream CA binding. It contains only
// non-secret routing metadata and references to secret files. Credentials are
// loaded immediately before one outbox delivery and destroyed immediately after
// that delivery; they are never retained in the process-wide registry.
//
// Fields are intentionally shared by the small, closed provider set. Validation
// below rejects a binding that is incomplete for its selected Type. Keeping this
// as ordinary JSON (rather than an opaque provider blob) lets config validation
// fail closed before the HTTP server begins accepting requests.
type ExternalCAConfig struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`

	Endpoint string `json:"endpoint,omitempty"`

	// Network is operator policy, never tenant input. Private endpoints must be
	// constrained to exact CIDRs; plaintext HTTP needs a second explicit opt-in.
	Network ExternalCANetworkConfig `json:"network,omitempty"`

	// ADCS / Microsoft Certificate Enrollment Web Service.
	CAConfig string `json:"ca_config,omitempty"`
	Template string `json:"template,omitempty"`

	// AWS Private CA.
	Region                  string `json:"region,omitempty"`
	CertificateAuthorityARN string `json:"certificate_authority_arn,omitempty"`
	SigningAlgorithm        string `json:"signing_algorithm,omitempty"`
	AccessKeyID             string `json:"access_key_id,omitempty"`
	SecretAccessKeyRef      string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef         string `json:"session_token_ref,omitempty"`

	// Azure Keys/Managed HSM CA custody / Google CAS. Azure binds an existing
	// non-exportable signing key to the matching operator CA certificate chain.
	KeyName        string `json:"key_name,omitempty"`
	KeyVersion     string `json:"key_version,omitempty"`
	ManagedKeyRef  string `json:"managed_key_ref,omitempty"`
	CACertFile     string `json:"ca_cert_file,omitempty"`
	CAPool         string `json:"ca_pool,omitempty"`
	BearerTokenRef string `json:"bearer_token_ref,omitempty"`

	// DigiCert / GlobalSign.
	APIKeyRef    string `json:"api_key_ref,omitempty"`
	APISecretRef string `json:"api_secret_ref,omitempty"`
	Product      string `json:"product,omitempty"`

	// EJBCA.
	CAName             string `json:"ca_name,omitempty"`
	CertificateProfile string `json:"certificate_profile,omitempty"`
	EndEntityProfile   string `json:"end_entity_profile,omitempty"`
	Username           string `json:"username,omitempty"`
	PasswordRef        string `json:"password_ref,omitempty"`

	// Entrust.
	CAID      string `json:"ca_id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`

	// Let's Encrypt or another ACME directory.
	DirectoryURL string `json:"directory_url,omitempty"`

	// UpstreamDNS01 enables unattended domain validation against this
	// authority: trstctl publishes the dns-01 challenge record itself, using
	// the DNS-01 provider configs that have set allow_upstream_dv (epic B7).
	//
	// Off by default. With it off this issuer can only obtain certificates for
	// identifiers the authority has already authorized out of band, which is
	// what shipped before and is still the correct posture for an operator who
	// has not decided to hand trstctl publish rights in their zones.
	UpstreamDNS01 bool `json:"upstream_dns01,omitempty"`

	// CAAIssuerDomain is THIS authority's CAA identifier ("letsencrypt.org"),
	// not trstctl's. It is required whenever UpstreamDNS01 is on: the check
	// asks whether the domain's CAA policy authorizes the CA about to issue,
	// and against an empty issuer it would authorize everyone while looking
	// like a control.
	CAAIssuerDomain string `json:"caa_issuer_domain,omitempty"`

	// Sectigo SCM.
	Login       string `json:"login,omitempty"`
	CustomerURI string `json:"customer_uri,omitempty"`
	OrgID       int    `json:"org_id,omitempty"`
	CertType    int    `json:"cert_type,omitempty"`

	// shellca. EnvRefs maps a logical credential name to a credential file
	// reference. The child receives only NAME_FD=<descriptor>; credential bytes
	// never enter its string environment.
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	EnvRefs map[string]string `json:"env_refs,omitempty"`

	// Smallstep.
	ProvisionerName   string `json:"provisioner_name,omitempty"`
	ProvisionerKeyRef string `json:"provisioner_key_ref,omitempty"`

	// Vault PKI.
	Mount      string `json:"mount,omitempty"`
	Role       string `json:"role,omitempty"`
	DefaultTTL string `json:"default_ttl,omitempty"`

	// Venafi TPP / TLS Protect.
	AccessTokenRef string `json:"access_token_ref,omitempty"`
	PolicyDN       string `json:"policy_dn,omitempty"`
	Application    string `json:"application,omitempty"`

	PollInterval string `json:"poll_interval,omitempty"`
}

// ExternalCANetworkConfig is the outbound policy shared by all HTTP-backed CA
// integrations. RootCAFile pins a private trust root. ClientCertFile/KeyFile are
// an optional mTLS identity; both must be present together.
type ExternalCANetworkConfig struct {
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	AllowInsecureHTTP    bool     `json:"allow_insecure_http,omitempty"`
	RootCAFile           string   `json:"root_ca_file,omitempty"`
	ClientCertFile       string   `json:"client_cert_file,omitempty"`
	ClientKeyFile        string   `json:"client_key_file,omitempty"`
	ServerName           string   `json:"server_name,omitempty"`
	Timeout              string   `json:"timeout,omitempty"`
}

// TimeoutDuration returns the complete per-provider HTTP deadline.
func (n ExternalCANetworkConfig) TimeoutDuration() (time.Duration, error) {
	if strings.TrimSpace(n.Timeout) == "" {
		return 15 * time.Second, nil
	}
	d, err := time.ParseDuration(n.Timeout)
	if err != nil || d <= 0 {
		return 0, errors.New("timeout must be a positive Go duration")
	}
	return d, nil
}

// PrivatePrefixes parses the already-validated private endpoint allowlist.
func (n ExternalCANetworkConfig) PrivatePrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(n.PrivateEgressCIDRs))
	for _, raw := range normalizedExternalCAStrings(n.PrivateEgressCIDRs) {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("private_egress_cidrs contains invalid CIDR %q", raw)
		}
		out = append(out, prefix)
	}
	return out, nil
}

// PollIntervalDuration returns zero when a provider should use its own default.
func (c ExternalCAConfig) PollIntervalDuration() (time.Duration, error) {
	if strings.TrimSpace(c.PollInterval) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.PollInterval)
	if err != nil || d <= 0 {
		return 0, errors.New("poll_interval must be a positive Go duration")
	}
	return d, nil
}

// DefaultTTLDuration returns zero when Vault should use its own default.
func (c ExternalCAConfig) DefaultTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(c.DefaultTTL) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.DefaultTTL)
	if err != nil || d <= 0 {
		return 0, errors.New("default_ttl must be a positive Go duration")
	}
	return d, nil
}

// ValidateExternalCAs is exported for config-focused tests and embedders.
// Config.Validate calls the package-local twin after Config grows ExternalCAs.
func ValidateExternalCAs(items []ExternalCAConfig) error {
	return errors.Join(validateExternalCAs(items)...)
}

func validateExternalCAs(items []ExternalCAConfig) []error {
	known := make(map[string]bool, len(ExternalCATypes))
	for _, typ := range ExternalCATypes {
		known[typ] = true
	}
	seen := map[string]bool{}
	var errs []error
	for i, item := range items {
		where := fmt.Sprintf("external_cas[%d]", i)
		item.ID = strings.TrimSpace(item.ID)
		item.Type = strings.ToLower(strings.TrimSpace(item.Type))
		if item.ID == "" {
			errs = append(errs, fmt.Errorf("%s.id is required", where))
		} else if seen[item.ID] {
			errs = append(errs, fmt.Errorf("%s.id %q is duplicated", where, item.ID))
		}
		seen[item.ID] = true
		if !known[item.Type] {
			errs = append(errs, fmt.Errorf("%s.type %q is not a built-in external CA", where, item.Type))
			continue
		}
		if strings.TrimSpace(item.Name) == "" {
			errs = append(errs, fmt.Errorf("%s.name is required", where))
		}
		errs = append(errs, validateExternalCANetwork(where, item)...)
		errs = append(errs, validateExternalCAProvider(where, item)...)
	}
	return errs
}

func validateExternalCANetwork(where string, item ExternalCAConfig) []error {
	var errs []error
	n := item.Network
	if _, err := n.TimeoutDuration(); err != nil {
		errs = append(errs, fmt.Errorf("%s.network.%w", where, err))
	}
	if _, err := item.PollIntervalDuration(); err != nil {
		errs = append(errs, fmt.Errorf("%s.%w", where, err))
	}
	if _, err := item.DefaultTTLDuration(); err != nil {
		errs = append(errs, fmt.Errorf("%s.%w", where, err))
	}
	if !n.AllowPrivateEndpoint && len(normalizedExternalCAStrings(n.PrivateEgressCIDRs)) != 0 {
		errs = append(errs, fmt.Errorf("%s.network.private_egress_cidrs requires allow_private_endpoint=true", where))
	}
	if n.AllowPrivateEndpoint && len(normalizedExternalCAStrings(n.PrivateEgressCIDRs)) == 0 {
		errs = append(errs, fmt.Errorf("%s.network.allow_private_endpoint requires private_egress_cidrs", where))
	}
	if _, err := n.PrivatePrefixes(); err != nil {
		errs = append(errs, fmt.Errorf("%s.network.%w", where, err))
	}
	for _, field := range []struct{ name, value string }{
		{"root_ca_file", n.RootCAFile}, {"client_cert_file", n.ClientCertFile}, {"client_key_file", n.ClientKeyFile},
	} {
		if field.value != "" && !filepath.IsAbs(strings.TrimSpace(field.value)) {
			errs = append(errs, fmt.Errorf("%s.network.%s must be an absolute path", where, field.name))
		}
	}
	if (n.ClientCertFile == "") != (n.ClientKeyFile == "") {
		errs = append(errs, fmt.Errorf("%s.network.client_cert_file and client_key_file must be set together", where))
	}
	if n.ClientCertFile != "" && n.RootCAFile == "" {
		errs = append(errs, fmt.Errorf("%s.network.root_ca_file is required with a client mTLS identity", where))
	}
	endpoint := externalCAEndpoint(item)
	if endpoint == "" && item.Type != "shellca" {
		errs = append(errs, fmt.Errorf("%s endpoint is required for %s", where, item.Type))
		return errs
	}
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, fmt.Errorf("%s endpoint must be an absolute http(s) URL", where))
		} else if u.Scheme == "http" && (!n.AllowInsecureHTTP || !netsec.IsLoopbackHost(u.Hostname())) {
			errs = append(errs, fmt.Errorf("%s endpoint must use https; explicit insecure http is allowed only for loopback development/emulators", where))
		} else if n.AllowInsecureHTTP && (u.Scheme != "http" || !netsec.IsLoopbackHost(u.Hostname())) {
			errs = append(errs, fmt.Errorf("%s network.allow_insecure_http requires an HTTP loopback endpoint", where))
		}
		if n.AllowInsecureHTTP && (n.RootCAFile != "" || n.ClientCertFile != "" || n.ClientKeyFile != "" || n.ServerName != "") {
			errs = append(errs, fmt.Errorf("%s network.allow_insecure_http cannot be combined with TLS trust or client-identity fields", where))
		}
	}
	return errs
}

func validateExternalCAProvider(where string, c ExternalCAConfig) []error {
	var errs []error
	require := func(value, field string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s.%s is required for %s", where, field, c.Type))
		}
	}
	credential := func(value, field string, optional bool) {
		if strings.TrimSpace(value) == "" && optional {
			return
		}
		if err := validateExternalCACredentialRef(value); err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", where, field, err))
		}
	}
	switch c.Type {
	case "adcs":
		require(c.CAConfig, "ca_config")
		require(c.Template, "template")
		credential(c.PasswordRef, "password_ref", true)
		if strings.TrimSpace(c.PasswordRef) != "" {
			endpoint, _ := url.Parse(strings.TrimSpace(c.Endpoint))
			if endpoint == nil || !strings.EqualFold(endpoint.Scheme, "https") {
				errs = append(errs, fmt.Errorf("%s.password_ref requires an https endpoint because AD CS Basic authentication exposes the password over plaintext HTTP", where))
			}
		}
	case "awspca":
		require(c.Region, "region")
		require(c.CertificateAuthorityARN, "certificate_authority_arn")
		require(c.AccessKeyID, "access_key_id")
		credential(c.SecretAccessKeyRef, "secret_access_key_ref", false)
		credential(c.SessionTokenRef, "session_token_ref", true)
	case "azurekv":
		if _, err := uuid.Parse(strings.TrimSpace(c.TenantID)); err != nil {
			errs = append(errs, fmt.Errorf("%s.tenant_id must be a UUID for azurekv", where))
		}
		managedRef, err := url.Parse(strings.TrimSpace(c.ManagedKeyRef))
		if err != nil || managedRef.Scheme != "https" || managedRef.Host == "" || managedRef.User != nil || managedRef.RawQuery != "" || managedRef.Fragment != "" || !strings.Contains(managedRef.EscapedPath(), "/keys/") {
			errs = append(errs, fmt.Errorf("%s.managed_key_ref must be the HTTPS key ref returned by the tenant's managed-key lifecycle", where))
		}
		if c.KeyName != "" || c.KeyVersion != "" || c.BearerTokenRef != "" {
			errs = append(errs, fmt.Errorf("%s azurekv credentials/key components belong in signer managed_keys; use managed_key_ref here", where))
		}
		if !filepath.IsAbs(strings.TrimSpace(c.CACertFile)) {
			errs = append(errs, fmt.Errorf("%s.ca_cert_file must be an absolute path for azurekv", where))
		}
	case "gcpcas":
		require(c.CAPool, "ca_pool")
		credential(c.BearerTokenRef, "bearer_token_ref", false)
	case "digicert":
		credential(c.APIKeyRef, "api_key_ref", false)
	case "ejbca":
		require(c.CAName, "ca_name")
		require(c.CertificateProfile, "certificate_profile")
		require(c.EndEntityProfile, "end_entity_profile")
		credential(c.BearerTokenRef, "bearer_token_ref", true)
		credential(c.PasswordRef, "password_ref", true)
		if c.BearerTokenRef == "" && c.Network.ClientCertFile == "" {
			errs = append(errs, fmt.Errorf("%s requires bearer_token_ref or a network mTLS identity", where))
		}
	case "entrust":
		require(c.CAID, "ca_id")
		if c.Network.ClientCertFile == "" {
			errs = append(errs, fmt.Errorf("%s requires a network mTLS identity", where))
		}
	case "globalsign":
		credential(c.APIKeyRef, "api_key_ref", false)
		credential(c.APISecretRef, "api_secret_ref", false)
	case "letsencrypt":
		// The ACME account key is generated and held by the isolated signer.
		if c.UpstreamDNS01 && strings.TrimSpace(c.CAAIssuerDomain) == "" {
			errs = append(errs, fmt.Errorf(
				"%s.caa_issuer_domain is required when upstream_dns01 is enabled: the CAA check "+
					"must name the authority that will issue, and an empty issuer authorizes every CA", where))
		}
	case "sectigo":
		require(c.Login, "login")
		credential(c.PasswordRef, "password_ref", false)
		require(c.CustomerURI, "customer_uri")
		if c.OrgID <= 0 || c.CertType <= 0 {
			errs = append(errs, fmt.Errorf("%s.org_id and cert_type must be positive for sectigo", where))
		}
	case "shellca":
		if !filepath.IsAbs(strings.TrimSpace(c.Command)) {
			errs = append(errs, fmt.Errorf("%s.command must be an absolute path for shellca", where))
		}
		for name, ref := range c.EnvRefs {
			if strings.TrimSpace(name) == "" || strings.Contains(name, "=") {
				errs = append(errs, fmt.Errorf("%s.env_refs contains invalid environment name %q", where, name))
			}
			credential(ref, "env_refs["+name+"]", false)
		}
	case "smallstep":
		require(c.ProvisionerName, "provisioner_name")
		credential(c.ProvisionerKeyRef, "provisioner_key_ref", false)
	case "vaultpki":
		require(c.Mount, "mount")
		require(c.Role, "role")
		credential(c.BearerTokenRef, "bearer_token_ref", false)
	case "venafi":
		credential(c.AccessTokenRef, "access_token_ref", false)
		require(c.PolicyDN, "policy_dn")
	}
	// Upstream DV is ACME-only, and setting it elsewhere is rejected rather
	// than ignored. An operator who writes upstream_dns01 on their DigiCert
	// entry has stated an intent the platform cannot carry out; accepting the
	// file and dropping the field would leave them believing validation is
	// automated right up until the reuse window closes.
	if c.Type != "letsencrypt" && (c.UpstreamDNS01 || strings.TrimSpace(c.CAAIssuerDomain) != "") {
		errs = append(errs, fmt.Errorf(
			"%s.upstream_dns01/caa_issuer_domain apply only to ACME (letsencrypt) authorities, not %q",
			where, c.Type))
	}
	return errs
}

func externalCAEndpoint(c ExternalCAConfig) string {
	if c.Type == "letsencrypt" && strings.TrimSpace(c.DirectoryURL) != "" {
		return strings.TrimSpace(c.DirectoryURL)
	}
	return strings.TrimSpace(c.Endpoint)
}

func validateExternalCACredentialRef(raw string) error {
	path, ok := strings.CutPrefix(strings.TrimSpace(raw), "file:")
	if !ok || !filepath.IsAbs(strings.TrimSpace(path)) {
		return errors.New("must use file:/absolute/path")
	}
	return nil
}

func normalizedExternalCAStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
