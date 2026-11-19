// SPDX-License-Identifier: BUSL-1.1

// Package outboundcred holds the operator's bindings for the env:NAME credential
// references that tenant-authored integrations may name (CR-008).
//
// Such a reference points at a deployment secret: an Azure or GCP reader-token
// file, an AWS STS session, a Vault, Splunk or Jira token. Approving the name is
// not enough, because the tenant that names it also chooses where the integration
// sends it. A binding therefore gives one reference to exactly one tenant, for named
// integration kinds, toward exact destination origins. The API checks a declaration
// against the bindings; the worker checks again immediately before it reads the
// value and pins the HTTP client it hands the value to, so the value reaches no
// other origin: not a redirect, not a provider-chosen token service, not a default
// endpoint the binding does not name.
package outboundcred

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// The discovery source kinds whose stored configuration resolves an env
// reference. They are the only source kinds a binding may name (CR-008): every
// other catalog kind never reads an env value, and binding one would let a
// provider connection stored beside one of its findings use the credential
// through an OAuth or access-key action.
const (
	IntegrationAzureMachineIdentity    = "azure_machine_identity"
	IntegrationGCPMachineIdentity      = "gcp_machine_identity"
	IntegrationCloudMachineEntitlement = "cloud_machine_entitlement"
	IntegrationCloudCertificate        = "cloud_certificate"
	IntegrationCloudSecret             = "cloud_secret"
	IntegrationSecretStore             = "secret_store"
	IntegrationCloudAccessKey          = "cloud_access_key"
	IntegrationCloudKMSKey             = "cloud_kms_key"
	IntegrationLoadBalancerTLS         = "load_balancer_tls"
	IntegrationCloudNetworkPath        = "cloud_network_path"
	IntegrationOAuthGrant              = "oauth_grant"
)

// Integration kinds beyond the discovery source catalog.
const (
	// IntegrationAuditFeed is a scheduled audit feed's collector credential.
	IntegrationAuditFeed = "audit_feed"
	// IntegrationResponseIntegration is an incident response dispatch's Splunk or
	// Jira token.
	IntegrationResponseIntegration = "response_integration"
	// IntegrationCloudMachineChange is the writer STS session a reviewed cloud
	// machine change executes with.
	IntegrationCloudMachineChange = "cloud_machine_change"
	// IntegrationSecretThirdParty is a third-party secret scan's collection or
	// annotation connection (its source kind).
	IntegrationSecretThirdParty = "secret_third_party"
	// IntegrationSecretRepository is a repository secret scan's annotation
	// connection (its source kind).
	IntegrationSecretRepository = "secret_repo"
)

// ErrNotBound refuses a reference outside its binding: another tenant, another
// integration, or a destination origin the binding does not name.
var ErrNotBound = errors.New("env credential reference is not bound to this use")

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ValidEnvName reports whether name is a well-formed environment variable name
// an env:NAME reference may carry: letters, digits and underscores, at most 128
// bytes, not starting with a digit.
func ValidEnvName(name string) bool { return envName.MatchString(name) }

// Binding is one operator approval: the env:NAME reference, the one tenant that may
// name it, the integration kinds that may use it, and the exact origins
// (scheme://host[:port]) its value may be sent to.
type Binding struct {
	Ref          string
	TenantID     string
	Integrations []string
	Origins      []string
}

// Validate reports the first problem with the binding.
func (b Binding) Validate() error {
	if _, ok := canonicalRef(b.Ref); !ok {
		return errors.New("ref must be an env:NAME reference (NAME: letters, digits and underscores, not starting with a digit)")
	}
	if err := uuid.Validate(strings.TrimSpace(b.TenantID)); err != nil {
		return errors.New("tenant_id must be the UUID of the one tenant that may use the reference")
	}
	if len(b.Integrations) == 0 {
		return errors.New("integrations must name at least one integration kind")
	}
	for _, name := range b.Integrations {
		if !KnownIntegration(name) {
			return fmt.Errorf("integrations contains %q, which is not an integration kind; use one of %s", strings.TrimSpace(name), strings.Join(Integrations(), ", "))
		}
	}
	if len(b.Origins) == 0 {
		return errors.New("origins must name at least one exact destination origin, for example https://graph.microsoft.com")
	}
	for _, raw := range b.Origins {
		if _, err := CanonicalOrigin(raw); err != nil {
			return fmt.Errorf("origins contains %q: %w", strings.TrimSpace(raw), err)
		}
	}
	return nil
}

// bindableIntegrations is every integration kind a binding may name: the
// sixteen kinds whose stored configuration resolves an env reference.
var bindableIntegrations = []string{
	IntegrationAzureMachineIdentity, IntegrationGCPMachineIdentity, IntegrationCloudMachineEntitlement,
	IntegrationCloudCertificate, IntegrationCloudSecret, IntegrationSecretStore, IntegrationCloudAccessKey,
	IntegrationCloudKMSKey, IntegrationLoadBalancerTLS, IntegrationCloudNetworkPath, IntegrationOAuthGrant,
	IntegrationSecretThirdParty, IntegrationSecretRepository, IntegrationCloudMachineChange,
	IntegrationAuditFeed, IntegrationResponseIntegration,
}

// Integrations lists every integration kind a binding may name, sorted.
func Integrations() []string {
	out := slices.Clone(bindableIntegrations)
	sort.Strings(out)
	return out
}

// KnownIntegration reports whether name is an integration kind a binding may name.
func KnownIntegration(name string) bool {
	return slices.Contains(bindableIntegrations, strings.TrimSpace(name))
}

// NormalizeRef returns ref as env:NAME with surrounding space removed, as the
// workers resolve it, and whether it is an env reference at all.
func NormalizeRef(ref string) (string, bool) {
	name, ok := strings.CutPrefix(strings.TrimSpace(ref), "env:")
	if !ok {
		return "", false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	return "env:" + name, true
}

// canonicalRef accepts only the exact env:NAME form an operator binding names.
func canonicalRef(ref string) (string, bool) {
	name, ok := strings.CutPrefix(strings.TrimSpace(ref), "env:")
	if !ok || !envName.MatchString(name) {
		return "", false
	}
	return "env:" + name, true
}

var defaultPorts = map[string]string{"https": "443", "http": "80", "syslog+tls": "6514"}

// CanonicalOrigin returns a binding origin in canonical form: lowercase scheme and
// host, a scheme's default port removed. It accepts https, http, syslog+tls and
// relp+tls origins with no credentials, path, query or fragment.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("an origin is scheme://host[:port]")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("an origin is scheme://host[:port], with no path, query or fragment")
	}
	return originOf(u)
}

// DestinationOrigin returns the canonical origin a destination URL sends to; the
// URL may carry a path.
func DestinationOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("the destination is not a URL")
	}
	return originOf(u)
}

func originOf(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https", "http", "syslog+tls", "relp+tls":
	default:
		return "", errors.New("an origin's scheme is https, http, syslog+tls or relp+tls")
	}
	if u.Opaque != "" || u.User != nil {
		return "", errors.New("an origin carries no credentials")
	}
	// RELP has no default port, so a relp+tls origin always names one.
	if scheme == "relp+tls" && u.Port() == "" {
		return "", errors.New("a relp+tls origin names its port")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("an origin names a host")
	}
	port := u.Port()
	if port == "" && strings.HasSuffix(u.Host, ":") {
		return "", errors.New("an origin's port is a number from 1 to 65535")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("an origin's port is a number from 1 to 65535")
		}
		if defaultPorts[scheme] == port {
			port = ""
		}
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

type entry struct {
	tenantID     string
	integrations map[string]bool
	origins      []string
}

// Bindings is the operator's set of bindings. A nil *Bindings binds nothing.
type Bindings struct {
	byRef map[string][]entry
}

// New validates bindings and builds the set. A reference may have several
// bindings: for several tenants, each named explicitly, or for one tenant with
// different integrations and origins.
func New(bindings []Binding) (*Bindings, error) {
	out := &Bindings{byRef: map[string][]entry{}}
	for i, b := range bindings {
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("outbound env credential binding %d: %w", i, err)
		}
		ref, _ := canonicalRef(b.Ref)
		tenant, _ := uuid.Parse(strings.TrimSpace(b.TenantID))
		e := entry{tenantID: tenant.String(), integrations: map[string]bool{}}
		for _, name := range b.Integrations {
			e.integrations[strings.TrimSpace(name)] = true
		}
		seen := map[string]bool{}
		for _, raw := range b.Origins {
			origin, _ := CanonicalOrigin(raw)
			if !seen[origin] {
				seen[origin] = true
				e.origins = append(e.origins, origin)
			}
		}
		sort.Strings(e.origins)
		out.byRef[ref] = append(out.byRef[ref], e)
	}
	return out, nil
}

// Refs lists the bound references, sorted.
func (b *Bindings) Refs() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.byRef))
	for ref := range b.byRef {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// Authorize checks that tenantID's integration may use ref and that every
// destination's origin is bound to it. It returns every origin the binding lets
// this use reach, for the caller to pin its client to. The error never says
// whether the reference is bound for another tenant.
func (b *Bindings) Authorize(ref, tenantID, integration string, destinations ...string) ([]string, error) {
	norm, ok := NormalizeRef(ref)
	if !ok {
		return nil, fmt.Errorf("%w: it is not an env:NAME reference", ErrNotBound)
	}
	tenant, err := uuid.Parse(strings.TrimSpace(tenantID))
	integration = strings.TrimSpace(integration)
	var allowed []string
	if b != nil && err == nil && integration != "" {
		seen := map[string]bool{}
		for _, e := range b.byRef[norm] {
			if e.tenantID != tenant.String() || !e.integrations[integration] {
				continue
			}
			for _, origin := range e.origins {
				if !seen[origin] {
					seen[origin] = true
					allowed = append(allowed, origin)
				}
			}
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: the operator has not bound it to this tenant for the %s integration", ErrNotBound, integration)
	}
	sort.Strings(allowed)
	for _, destination := range destinations {
		origin, err := DestinationOrigin(destination)
		if err != nil {
			return nil, fmt.Errorf("%w: it cannot be sent to that destination: %v", ErrNotBound, err)
		}
		if !containsString(allowed, origin) {
			return nil, fmt.Errorf("%w: the operator has not bound it to send to %s", ErrNotBound, origin)
		}
	}
	return allowed, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// PinClient wraps client's transport so every request it sends, redirects
// included, must go to one of origins (http and https only). A request elsewhere
// is refused before DNS, dialing or any credential I/O. client is changed in place
// so a caller cannot keep using an unpinned copy; pinning twice keeps both checks.
func PinClient(client *http.Client, origins []string) error {
	if client == nil {
		return errors.New("outboundcred: no HTTP client to pin")
	}
	if client == http.DefaultClient {
		// Pinning it would pin every user of the process-wide client.
		return errors.New("outboundcred: http.DefaultClient is shared by the whole process and is never pinned")
	}
	allowed := map[string]bool{}
	for _, raw := range origins {
		origin, err := CanonicalOrigin(raw)
		if err != nil {
			return fmt.Errorf("outboundcred: pin origin %q: %w", raw, err)
		}
		allowed[origin] = true
	}
	if len(allowed) == 0 {
		return errors.New("outboundcred: no origin to pin the HTTP client to")
	}
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	client.Transport = &pinnedTransport{allowed: allowed, next: next}
	return nil
}

type pinnedTransport struct {
	allowed map[string]bool
	next    http.RoundTripper
}

func (t *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("%w: the request names no destination", ErrNotBound)
	}
	scheme := strings.ToLower(req.URL.Scheme)
	origin, err := originOf(req.URL)
	if err != nil || (scheme != "https" && scheme != "http") || !t.allowed[origin] {
		if origin == "" {
			origin = "an unbound destination"
		}
		return nil, fmt.Errorf("%w: a request to %s is outside the origins the credential is bound to", ErrNotBound, origin)
	}
	return t.next.RoundTrip(req)
}

func (t *pinnedTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
