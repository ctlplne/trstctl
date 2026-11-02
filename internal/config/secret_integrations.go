// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/redisacl"
)

// SecretIntegrationsConfig is the operator-owned, tenant-bound configuration for
// dynamic-secret issuers and outbound secret-sync targets.  It deliberately holds
// references to credentials, never credential bytes.  A reference is resolved at
// delivery time so authority-bearing material is not retained by the process-wide
// registry.
type SecretIntegrationsConfig struct {
	DynamicProviders []DynamicSecretProviderConfig `json:"dynamic_providers,omitempty"`
	SyncTargets      []SecretSyncTargetConfig      `json:"sync_targets,omitempty"`
	HoneyAWSAccounts []AWSHoneyAccountConfig       `json:"honey_aws_accounts,omitempty"`
}

// AWSHoneyAccountConfig grants one tenant an operator-approved AWS account for
// decoy IAM keys. Credential refs are reread for each outbox delivery, so an
// operator can use independently rotated, short-lived caller sessions. The
// public AWS endpoints are defaults; private overrides require an explicit
// allowlist and are intended for owned labs or private cloud endpoints.
type AWSHoneyAccountConfig struct {
	TenantID                 string            `json:"tenant_id"`
	ID                       string            `json:"id"`
	AccountID                string            `json:"account_id"`
	Regions                  []string          `json:"regions"`
	IAMCredentialsRef        string            `json:"iam_credentials_ref"`
	CloudTrailCredentialsRef string            `json:"cloudtrail_credentials_ref"`
	IAMEndpoint              string            `json:"iam_endpoint,omitempty"`
	CloudTrailEndpoints      map[string]string `json:"cloudtrail_endpoints,omitempty"`
	UsernamePrefix           string            `json:"username_prefix,omitempty"`
	MaxTTL                   string            `json:"max_ttl"`
	PollInterval             string            `json:"poll_interval"`
	AllowPrivate             bool              `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback    bool              `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs       []string          `json:"private_egress_cidrs,omitempty"`
}

func (c AWSHoneyAccountConfig) MaxTTLDuration() (time.Duration, error) {
	return time.ParseDuration(c.MaxTTL)
}

func (c AWSHoneyAccountConfig) PollIntervalDuration() (time.Duration, error) {
	return time.ParseDuration(c.PollInterval)
}

// DynamicSecretProviderConfig configures one named provider for exactly one
// tenant. Type is one of the eight built-ins. Fields not used by that type must be
// left empty; validation rejects incomplete entries before the server starts.
type DynamicSecretProviderConfig struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`
	Type     string `json:"type"`

	Endpoint    string `json:"endpoint,omitempty"`
	AdminDSNRef string `json:"admin_dsn_ref,omitempty"`
	Database    string `json:"database,omitempty"`
	Schema      string `json:"schema,omitempty"`
	Addr        string `json:"addr,omitempty"`
	AccountHost string `json:"account_host,omitempty"`
	// MySQL host patterns containing % or _ can admit clients outside a
	// single named host. Require an explicit operator opt-in for that scope.
	AllowWildcardAccountHost bool   `json:"allow_wildcard_account_host,omitempty"`
	Namespace                string `json:"namespace,omitempty"`
	Region                   string `json:"region,omitempty"`
	AccessKeyID              string `json:"access_key_id,omitempty"`
	Project                  string `json:"project,omitempty"`
	ServiceAccount           string `json:"service_account,omitempty"`
	ApplicationObject        string `json:"application_object_id,omitempty"`
	ApplicationClient        string `json:"application_client_id,omitempty"`
	AzureTenant              string `json:"azure_tenant_id,omitempty"`
	DB                       int    `json:"db,omitempty"`
	UsernamePrefix           string `json:"username_prefix,omitempty"`

	// IAMEndpoint is where an aws-iam or aws-sts provider reads the policies
	// of the roles its leases assume (G2). Empty means AWS IAM for the
	// region's partition.
	IAMEndpoint string `json:"iam_endpoint,omitempty"`

	PasswordRef             string `json:"password_ref,omitempty"`
	SecretAccessRef         string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef         string `json:"session_token_ref,omitempty"`
	BearerTokenRef          string `json:"bearer_token_ref,omitempty"`
	KubernetesAudience      string `json:"kubernetes_audience,omitempty"`
	KubernetesTLSCARef      string `json:"kubernetes_tls_ca_ref,omitempty"`
	KubernetesTLSServerName string `json:"kubernetes_tls_server_name,omitempty"`
	// BindDN and UsersDN are the LDAP provider's administrator and the
	// container its leased entries are created in (A239).
	BindDN  string `json:"bind_dn,omitempty"`
	UsersDN string `json:"users_dn,omitempty"`
	// TLSCARef pins a private CA and TLSServerName names the certificate the
	// A239 providers verify; AllowPlaintext permits an unencrypted connection
	// to a literal loopback or private IP only.
	TLSCARef       string `json:"tls_ca_ref,omitempty"`
	TLSServerName  string `json:"tls_server_name,omitempty"`
	AllowPlaintext bool   `json:"allow_plaintext,omitempty"`
	// SeedRef is a TOTP provider's shared secret (base32, as an authenticator
	// enrolls it); Digits (6, 7 or 8), Period (30s or 60s) and Algorithm
	// (SHA1, SHA256 or SHA512) default to 6, 30s and SHA1 (A239).
	SeedRef   string `json:"seed_ref,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    string `json:"period,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	// ClientID and ClientSecretRef are an oauth-client-credentials provider's
	// confidential client at the authorization server whose token endpoint is
	// Endpoint; RevocationEndpoint (RFC 7009) is optional, and without it
	// revocation waits for each token's expiry (A239).
	ClientID           string   `json:"client_id,omitempty"`
	ClientSecretRef    string   `json:"client_secret_ref,omitempty"`
	RevocationEndpoint string   `json:"revocation_endpoint,omitempty"`
	AllowedRoles       []string `json:"allowed_roles"`
	// RoleBindings maps an allowed role to its provider-native authority. AWS
	// dynamic values are assumable IAM role ARNs; Kubernetes values are Role/name or
	// ClusterRole/name. Fixed-authority providers may omit it.
	RoleBindings map[string]string `json:"role_bindings,omitempty"`
	// RedisACLRoles gives each allowed Redis role literal key namespaces and an
	// explicit command allowlist. Raw ACL rules and categories are forbidden.
	RedisACLRoles       map[string]redisacl.Role `json:"redis_acl_roles,omitempty"`
	RedisTLSCARef       string                   `json:"redis_tls_ca_ref,omitempty"`
	RedisTLSServerName  string                   `json:"redis_tls_server_name,omitempty"`
	AllowPlaintextRedis bool                     `json:"allow_plaintext_redis,omitempty"`
	MaxTTL              string                   `json:"max_ttl,omitempty"`
	// AllowStaticRotation lets the static-rotation worker mint long-lived
	// credentials with no native expiry through this provider (postgresql,
	// mysql, aws-iam) for roles in allowed_roles. Off by default: a dynamic
	// provider that only ever issues bounded leases keeps that guarantee.
	AllowStaticRotation   bool     `json:"allow_static_rotation,omitempty"`
	AllowPrivate          bool     `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// StaticRotationProviderTypes are the dynamic-provider types whose backends can
// mint a credential without native expiry and revoke it by reference, which is
// what scheduled static rotation needs (A14).
var StaticRotationProviderTypes = map[string]bool{"postgresql": true, "mysql": true, "aws-iam": true}

// MaxTTLDuration is the hard validity ceiling for a generated credential. A
// shorter requested lease can be renewed only up to this bound.
func (c DynamicSecretProviderConfig) MaxTTLDuration() (time.Duration, error) {
	value := strings.TrimSpace(c.MaxTTL)
	if value == "" {
		return 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}

// SecretSyncTargetConfig configures one outbound target for exactly one tenant.
// Token/secret fields are references resolved immediately before one push.
type SecretSyncTargetConfig struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`
	Type     string `json:"type"`

	Endpoint         string   `json:"endpoint"`
	Owner            string   `json:"owner,omitempty"`
	Repo             string   `json:"repo,omitempty"`
	Region           string   `json:"region,omitempty"`
	AccessKeyID      string   `json:"access_key_id,omitempty"`
	Project          string   `json:"project,omitempty"`
	APIVersion       string   `json:"api_version,omitempty"`
	ProjectID        string   `json:"project_id,omitempty"`
	TeamID           string   `json:"team_id,omitempty"`
	Namespace        string   `json:"namespace,omitempty"`
	Provider         string   `json:"provider,omitempty"`
	EnvironmentScope string   `json:"environment_scope,omitempty"`
	Targets          []string `json:"targets,omitempty"`
	// Terraform Cloud/OpenTofu Variables API fields.
	WorkspaceID      string `json:"workspace_id,omitempty"`
	VariableCategory string `json:"variable_category,omitempty"`
	HCL              bool   `json:"hcl,omitempty"`
	Description      string `json:"description,omitempty"`
	// Vault KV v2 fields. VaultNamespace is an Enterprise namespace header;
	// Namespace above remains the Kubernetes namespace.
	Mount          string `json:"mount,omitempty"`
	PathPrefix     string `json:"path_prefix,omitempty"`
	Field          string `json:"field,omitempty"`
	VaultNamespace string `json:"vault_namespace,omitempty"`

	// Signed webhook (type webhook): the HMAC key reference the receiver
	// shares, and an optional JSON body template with ${key}, ${value},
	// ${value_base64}, ${delivery_id} and ${timestamp} placeholders.
	SigningKeyRef string `json:"signing_key_ref,omitempty"`
	BodyTemplate  string `json:"body_template,omitempty"`
	// Netlify (type netlify): the account (team) and optional site that own
	// the variables, the deploy context of the value, and a new variable's scopes.
	AccountID     string   `json:"account_id,omitempty"`
	SiteID        string   `json:"site_id,omitempty"`
	DeployContext string   `json:"deploy_context,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	// Parameter Store (type aws-parameter-store): the KMS key that encrypts
	// SecureString values; empty uses the account's key for SSM.
	KMSKeyID string `json:"kms_key_id,omitempty"`

	TokenRef        string `json:"token_ref,omitempty"`
	SecretAccessRef string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef string `json:"session_token_ref,omitempty"`
	// AWSWorkloadIdentity explicitly opts this target into tenant-authored
	// short-lived AWS STS credentials. It is false by default. When true, static
	// AWS access-key fields are forbidden and the bounded secret-sync outbox
	// worker is the only component allowed to use WorkloadIdentityEndpoint.
	AWSWorkloadIdentity                   bool     `json:"aws_workload_identity,omitempty"`
	GCPWorkloadIdentity                   bool     `json:"gcp_workload_identity,omitempty"`
	AzureWorkloadIdentity                 bool     `json:"azure_workload_identity,omitempty"`
	WorkloadIdentityEndpoint              string   `json:"workload_identity_endpoint,omitempty"`
	WorkloadIdentityImpersonationEndpoint string   `json:"workload_identity_impersonation_endpoint,omitempty"`
	AllowPrivate                          bool     `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback                 bool     `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs                    []string `json:"private_egress_cidrs,omitempty"`
}

var dynamicSecretTypes = map[string]struct{}{
	"postgresql": {}, "mysql": {}, "mongodb": {}, "aws-iam": {}, "aws-sts": {},
	"gcp-iam": {}, "azure-entra": {}, "kubernetes": {}, "redis": {}, "ldap": {},
	"totp": {}, "oauth-client-credentials": {},
}

// tlsProviderTypes take the shared tls_ca_ref, tls_server_name and
// allow_plaintext settings (A239).
var tlsProviderTypes = map[string]bool{"ldap": true}

var dynamicAWSRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

var secretSyncTypes = map[string]struct{}{
	"aws-secrets-manager": {}, "gcp-secret-manager": {}, "azure-key-vault": {},
	"github-actions": {}, "gitlab-ci": {}, "vercel": {},
	"generic-ci-json": {}, "kubernetes-secrets": {},
	"terraform-cloud-opentofu": {}, "vault-kv-v2": {},
	"webhook": {}, "aws-parameter-store": {}, "netlify": {},
}

// ValidateSecretIntegrations is exported for config-focused tests and embedders.
// Config.Validate calls the package-local twin from config.go's validator list.
func ValidateSecretIntegrations(cfg SecretIntegrationsConfig, secretsEnabled bool) error {
	return errors.Join(validateSecretIntegrations(cfg, secretsEnabled)...)
}

func validateSecretIntegrations(cfg SecretIntegrationsConfig, secretsEnabled bool) []error {
	var errs []error
	if !secretsEnabled && (len(cfg.DynamicProviders) > 0 || len(cfg.SyncTargets) > 0 || len(cfg.HoneyAWSAccounts) > 0) {
		errs = append(errs, errors.New("secret integrations require secrets.enable_api=true"))
	}
	dynamicIDs := map[string]bool{}
	for i, item := range cfg.DynamicProviders {
		where := fmt.Sprintf("secret_integrations.dynamic_providers[%d]", i)
		item.TenantID = strings.TrimSpace(item.TenantID)
		item.ID = strings.TrimSpace(item.ID)
		item.Type = strings.TrimSpace(item.Type)
		if item.TenantID == "" || item.ID == "" {
			errs = append(errs, fmt.Errorf("%s tenant_id and id are required", where))
		}
		key := item.TenantID + "\x00" + item.ID
		if dynamicIDs[key] {
			errs = append(errs, fmt.Errorf("%s duplicates tenant/id %q/%q", where, item.TenantID, item.ID))
		}
		dynamicIDs[key] = true
		if _, ok := dynamicSecretTypes[item.Type]; !ok {
			errs = append(errs, fmt.Errorf("%s type %q is not a built-in dynamic-secret backend", where, item.Type))
			continue
		}
		if len(normalizedStrings(item.AllowedRoles)) == 0 {
			errs = append(errs, fmt.Errorf("%s allowed_roles must contain at least one role", where))
		}
		if item.AllowStaticRotation && !StaticRotationProviderTypes[strings.TrimSpace(item.Type)] {
			errs = append(errs, fmt.Errorf("secret_integrations.dynamic_providers[%d]: allow_static_rotation is served for postgresql, mysql and aws-iam providers only", i))
		}
		if ttl, err := item.MaxTTLDuration(); err != nil || ttl <= 0 {
			errs = append(errs, fmt.Errorf("%s max_ttl must be a positive duration", where))
		}
		errs = append(errs, validateDynamicProvider(where, item)...)
		errs = append(errs, validatePrivateEgress(where, item.AllowPrivate, item.PrivateEgressCIDRs)...)
	}
	syncIDs := map[string]bool{}
	for i, item := range cfg.SyncTargets {
		where := fmt.Sprintf("secret_integrations.sync_targets[%d]", i)
		item.TenantID = strings.TrimSpace(item.TenantID)
		item.ID = strings.TrimSpace(item.ID)
		item.Type = strings.TrimSpace(item.Type)
		if item.TenantID == "" || item.ID == "" {
			errs = append(errs, fmt.Errorf("%s tenant_id and id are required", where))
		}
		key := item.TenantID + "\x00" + item.ID
		if syncIDs[key] {
			errs = append(errs, fmt.Errorf("%s duplicates tenant/id %q/%q", where, item.TenantID, item.ID))
		}
		syncIDs[key] = true
		if _, ok := secretSyncTypes[item.Type]; !ok {
			errs = append(errs, fmt.Errorf("%s type %q is not a built-in secret-sync target", where, item.Type))
			continue
		}
		if err := validateSecretIntegrationEndpoint(item.Endpoint, item.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s endpoint: %w", where, err))
		}
		errs = append(errs, validateSyncTarget(where, item)...)
		errs = append(errs, validatePrivateEgress(where, item.AllowPrivate, item.PrivateEgressCIDRs)...)
	}
	honeyIDs := map[string]bool{}
	honeyAccountOwners := map[string]string{}
	for i, item := range cfg.HoneyAWSAccounts {
		where := fmt.Sprintf("secret_integrations.honey_aws_accounts[%d]", i)
		key := item.TenantID + "\x00" + item.ID
		if honeyIDs[key] {
			errs = append(errs, fmt.Errorf("%s duplicates tenant/id %q/%q", where, item.TenantID, item.ID))
		}
		honeyIDs[key] = true
		if owner, exists := honeyAccountOwners[item.AccountID]; exists && owner != item.TenantID {
			errs = append(errs, fmt.Errorf("%s AWS account %q is already attached to another tenant; regional CloudTrail quota requires one tenant owner", where, item.AccountID))
		}
		honeyAccountOwners[item.AccountID] = item.TenantID
		errs = append(errs, validateAWSHoneyAccount(where, item)...)
	}
	return errs
}

var awsHoneyRegion = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
var awsHoneyAccount = regexp.MustCompile(`^[0-9]{12}$`)

func validateAWSHoneyAccount(where string, item AWSHoneyAccountConfig) []error {
	var errs []error
	if strings.TrimSpace(item.TenantID) == "" || strings.TrimSpace(item.ID) == "" {
		errs = append(errs, fmt.Errorf("%s tenant_id and id are required", where))
	}
	if !awsHoneyAccount.MatchString(item.AccountID) {
		errs = append(errs, fmt.Errorf("%s account_id must be a 12-digit AWS account", where))
	}
	if len(item.Regions) == 0 || len(item.Regions) > 32 {
		errs = append(errs, fmt.Errorf("%s requires 1-32 explicit CloudTrail regions", where))
	}
	regions := map[string]bool{}
	for _, region := range item.Regions {
		if !awsHoneyRegion.MatchString(region) || regions[region] {
			errs = append(errs, fmt.Errorf("%s regions must be unique AWS region names", where))
		}
		regions[region] = true
	}
	for region := range item.CloudTrailEndpoints {
		if !regions[region] {
			errs = append(errs, fmt.Errorf("%s cloudtrail_endpoints[%q] has no monitored region", where, region))
		}
	}
	for name, ref := range map[string]string{
		"iam_credentials_ref":        item.IAMCredentialsRef,
		"cloudtrail_credentials_ref": item.CloudTrailCredentialsRef,
	} {
		if err := validateCredentialRef(ref); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	if ttl, err := item.MaxTTLDuration(); err != nil || ttl < time.Hour || ttl > 365*24*time.Hour {
		errs = append(errs, fmt.Errorf("%s max_ttl must be explicit and between 1h and 365d", where))
	}
	if interval, err := item.PollIntervalDuration(); err != nil || interval < time.Minute || interval > time.Hour {
		errs = append(errs, fmt.Errorf("%s poll_interval must be explicit and between 1m and 1h", where))
	} else if ttl, err := item.MaxTTLDuration(); err == nil && ttl < 2*interval {
		errs = append(errs, fmt.Errorf("%s max_ttl must cover at least two CloudTrail polling intervals", where))
	}
	endpoints := append([]string{item.IAMEndpoint}, mapValues(item.CloudTrailEndpoints)...)
	for _, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}
		if err := validateSecretIntegrationEndpoint(endpoint, item.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s endpoint: %w", where, err))
		}
		parsed, parseErr := url.Parse(endpoint)
		if parseErr == nil {
			host := parsed.Hostname()
			address := net.ParseIP(host)
			if !item.AllowPrivate && (netsec.IsLoopbackHost(host) || (address != nil && (address.IsPrivate() || address.IsLinkLocalUnicast()))) {
				errs = append(errs, fmt.Errorf("%s private IAM/CloudTrail endpoint requires allow_private_endpoint and a CIDR allowlist", where))
			}
		}
	}
	errs = append(errs, validatePrivateEgress(where, item.AllowPrivate, item.PrivateEgressCIDRs)...)
	return errs
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func validateDynamicProvider(where string, c DynamicSecretProviderConfig) []error {
	errs := validateProviderFieldScopes(where, c)
	require := func(value, name string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for %s", where, name, c.Type))
		}
	}
	ref := func(value, name string, optional bool) {
		if strings.TrimSpace(value) == "" && optional {
			return
		}
		if err := validateCredentialRef(value); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	switch c.Type {
	case "postgresql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
	case "mysql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		require(c.Database, "database")
		require(c.Addr, "addr")
		require(c.AccountHost, "account_host")
		if strings.ContainsAny(c.AccountHost, "%_") && !c.AllowWildcardAccountHost {
			errs = append(errs, fmt.Errorf("%s wildcard account_host requires allow_wildcard_account_host=true", where))
		}
	case "mongodb":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		require(c.Database, "database")
	case "redis":
		require(c.Addr, "addr")
		ref(c.PasswordRef, "password_ref", false)
		ref(c.RedisTLSCARef, "redis_tls_ca_ref", true)
		if c.DB != 0 {
			errs = append(errs, fmt.Errorf("%s redis db must be 0 because Redis ACLs cannot scope SELECT to one database", where))
		}
		if c.AllowPlaintextRedis {
			if c.RedisTLSCARef != "" || c.RedisTLSServerName != "" {
				errs = append(errs, fmt.Errorf("%s plaintext Redis forbids TLS settings", where))
			}
			host, _, splitErr := net.SplitHostPort(c.Addr)
			address := net.ParseIP(host)
			if splitErr != nil || address == nil || (!address.IsLoopback() && !address.IsPrivate()) {
				errs = append(errs, fmt.Errorf("%s allow_plaintext_redis requires a literal loopback or private IP address", where))
			}
		} else {
			require(c.RedisTLSServerName, "redis_tls_server_name")
		}
		allowed := make(map[string]bool, len(c.AllowedRoles))
		for _, role := range normalizedStrings(c.AllowedRoles) {
			allowed[role] = true
			policy, found := c.RedisACLRoles[role]
			if !found {
				errs = append(errs, fmt.Errorf("%s redis_acl_roles[%q] is required", where, role))
				continue
			}
			if _, err := redisacl.Compile(policy); err != nil {
				errs = append(errs, fmt.Errorf("%s redis_acl_roles[%q]: %w", where, role, err))
			}
		}
		for role := range c.RedisACLRoles {
			if !allowed[role] {
				errs = append(errs, fmt.Errorf("%s redis_acl_roles[%q] has no matching allowed role", where, role))
			}
		}
	case "ldap":
		errs = append(errs, validateLDAPProvider(where, c)...)
	case "totp":
		errs = append(errs, validateTOTPProvider(where, c)...)
	case "oauth-client-credentials":
		errs = append(errs, validateOAuthClientCredentialsProvider(where, c)...)
	case "kubernetes":
		require(c.Endpoint, "endpoint")
		require(c.Namespace, "namespace")
		require(c.KubernetesAudience, "kubernetes_audience")
		ref(c.BearerTokenRef, "bearer_token_ref", false)
		ref(c.KubernetesTLSCARef, "kubernetes_tls_ca_ref", true)
		if c.KubernetesTLSServerName != "" && c.KubernetesTLSCARef == "" {
			errs = append(errs, fmt.Errorf("%s kubernetes_tls_server_name requires kubernetes_tls_ca_ref", where))
		}
		if maxTTL, err := c.MaxTTLDuration(); err == nil && maxTTL < 10*time.Minute {
			errs = append(errs, fmt.Errorf("%s kubernetes max_ttl must be at least 10 minutes", where))
		}
		for _, role := range normalizedStrings(c.AllowedRoles) {
			binding := strings.TrimSpace(c.RoleBindings[role])
			if !strings.HasPrefix(binding, "Role/") && !strings.HasPrefix(binding, "ClusterRole/") {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be Role/name or ClusterRole/name", where, role))
			}
		}
	case "aws-iam", "aws-sts":
		require(c.Endpoint, "endpoint")
		require(c.Region, "region")
		require(c.AccessKeyID, "access_key_id")
		ref(c.SecretAccessRef, "secret_access_key_ref", false)
		ref(c.SessionTokenRef, "session_token_ref", true)
		if c.MaxTTL == "" {
			errs = append(errs, fmt.Errorf("%s AWS STS max_ttl must be explicit (15m to 12h)", where))
		} else if ttl, err := c.MaxTTLDuration(); err == nil && (ttl < 15*time.Minute || ttl > 12*time.Hour) {
			errs = append(errs, fmt.Errorf("%s AWS STS max_ttl must be between 15m and 12h", where))
		}
		for _, role := range normalizedStrings(c.AllowedRoles) {
			if !dynamicAWSRoleARN.MatchString(strings.TrimSpace(c.RoleBindings[role])) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be a full IAM role ARN for STS AssumeRole", where, role))
			}
		}
	case "gcp-iam":
		require(c.Endpoint, "endpoint")
		require(c.Project, "project")
		require(c.ServiceAccount, "service_account")
		ref(c.BearerTokenRef, "bearer_token_ref", false)
	case "azure-entra":
		require(c.Endpoint, "endpoint")
		require(c.ApplicationObject, "application_object_id")
		require(c.ApplicationClient, "application_client_id")
		require(c.AzureTenant, "azure_tenant_id")
		ref(c.BearerTokenRef, "bearer_token_ref", false)
	}
	if c.IAMEndpoint != "" {
		if c.Type != "aws-iam" && c.Type != "aws-sts" {
			errs = append(errs, fmt.Errorf("%s iam_endpoint is only valid for aws-iam and aws-sts", where))
		} else if err := validateSecretIntegrationEndpoint(c.IAMEndpoint, c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s iam_endpoint: %w", where, err))
		}
	}
	if c.Endpoint != "" {
		if err := validateSecretIntegrationEndpoint(c.Endpoint, c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s endpoint: %w", where, err))
		}
	} else if c.AllowInsecureLoopback {
		errs = append(errs, fmt.Errorf("%s allow_insecure_loopback requires an HTTP loopback endpoint", where))
	}
	return errs
}

func validateSyncTarget(where string, c SecretSyncTargetConfig) []error {
	var errs []error
	if c.AWSWorkloadIdentity && c.Type != "aws-secrets-manager" {
		errs = append(errs, fmt.Errorf("%s aws_workload_identity is only valid for aws-secrets-manager", where))
	}
	if c.GCPWorkloadIdentity && c.Type != "gcp-secret-manager" {
		errs = append(errs, fmt.Errorf("%s gcp_workload_identity is only valid for gcp-secret-manager", where))
	}
	if c.AzureWorkloadIdentity && c.Type != "azure-key-vault" {
		errs = append(errs, fmt.Errorf("%s azure_workload_identity is only valid for azure-key-vault", where))
	}
	require := func(value, name string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for %s", where, name, c.Type))
		}
	}
	ref := func(value, name string, optional bool) {
		if strings.TrimSpace(value) == "" && optional {
			return
		}
		if err := validateCredentialRef(value); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	switch c.Type {
	case "aws-secrets-manager":
		require(c.Region, "region")
		if c.AWSWorkloadIdentity {
			if strings.TrimSpace(c.AccessKeyID) != "" || strings.TrimSpace(c.SecretAccessRef) != "" || strings.TrimSpace(c.SessionTokenRef) != "" {
				errs = append(errs, fmt.Errorf("%s AWS workload identity forbids static access_key_id, secret_access_key_ref, and session_token_ref", where))
			}
			if c.WorkloadIdentityEndpoint != "" {
				if err := validateSecretIntegrationEndpoint(c.WorkloadIdentityEndpoint, c.AllowInsecureLoopback); err != nil {
					errs = append(errs, fmt.Errorf("%s workload_identity_endpoint: %w", where, err))
				}
			}
			if strings.TrimSpace(c.WorkloadIdentityImpersonationEndpoint) != "" {
				errs = append(errs, fmt.Errorf("%s workload_identity_impersonation_endpoint is only valid for GCP", where))
			}
		} else {
			require(c.AccessKeyID, "access_key_id")
			ref(c.SecretAccessRef, "secret_access_key_ref", false)
			ref(c.SessionTokenRef, "session_token_ref", true)
			if strings.TrimSpace(c.WorkloadIdentityEndpoint) != "" {
				errs = append(errs, fmt.Errorf("%s workload_identity_endpoint requires aws_workload_identity=true", where))
			}
		}
	case "gcp-secret-manager":
		require(c.Project, "project")
		if c.GCPWorkloadIdentity {
			if strings.TrimSpace(c.TokenRef) != "" {
				errs = append(errs, fmt.Errorf("%s GCP workload identity forbids static token_ref", where))
			}
			if c.WorkloadIdentityEndpoint != "" {
				if err := validateSecretIntegrationEndpoint(c.WorkloadIdentityEndpoint, c.AllowInsecureLoopback); err != nil {
					errs = append(errs, fmt.Errorf("%s workload_identity_endpoint: %w", where, err))
				}
			}
			if c.WorkloadIdentityImpersonationEndpoint != "" {
				if err := validateSecretIntegrationEndpoint(c.WorkloadIdentityImpersonationEndpoint, c.AllowInsecureLoopback); err != nil {
					errs = append(errs, fmt.Errorf("%s workload_identity_impersonation_endpoint: %w", where, err))
				}
			}
		} else {
			ref(c.TokenRef, "token_ref", false)
			if strings.TrimSpace(c.WorkloadIdentityEndpoint) != "" ||
				strings.TrimSpace(c.WorkloadIdentityImpersonationEndpoint) != "" {
				errs = append(errs, fmt.Errorf("%s workload identity endpoints require gcp_workload_identity=true", where))
			}
		}
	case "azure-key-vault":
		if c.AzureWorkloadIdentity {
			if strings.TrimSpace(c.TokenRef) != "" {
				errs = append(errs, fmt.Errorf("%s Azure workload identity forbids static token_ref", where))
			}
			if c.WorkloadIdentityEndpoint != "" {
				if err := validateSecretIntegrationEndpoint(c.WorkloadIdentityEndpoint, c.AllowInsecureLoopback); err != nil {
					errs = append(errs, fmt.Errorf("%s workload_identity_endpoint: %w", where, err))
				}
			}
			if strings.TrimSpace(c.WorkloadIdentityImpersonationEndpoint) != "" {
				errs = append(errs, fmt.Errorf("%s workload_identity_impersonation_endpoint is only valid for GCP", where))
			}
		} else {
			ref(c.TokenRef, "token_ref", false)
			if strings.TrimSpace(c.WorkloadIdentityEndpoint) != "" {
				errs = append(errs, fmt.Errorf("%s workload_identity_endpoint requires azure_workload_identity=true", where))
			}
		}
	case "github-actions":
		require(c.Owner, "owner")
		require(c.Repo, "repo")
		ref(c.TokenRef, "token_ref", false)
	case "gitlab-ci":
		require(c.ProjectID, "project_id")
		ref(c.TokenRef, "token_ref", false)
	case "vercel":
		require(c.ProjectID, "project_id")
		ref(c.TokenRef, "token_ref", false)
	case "generic-ci-json":
		require(c.Provider, "provider")
		ref(c.TokenRef, "token_ref", true)
	case "kubernetes-secrets":
		require(c.Namespace, "namespace")
		ref(c.TokenRef, "token_ref", false)
	case "terraform-cloud-opentofu":
		require(c.WorkspaceID, "workspace_id")
		ref(c.TokenRef, "token_ref", false)
		category := strings.ToLower(strings.TrimSpace(c.VariableCategory))
		if category != "" && category != "terraform" && category != "env" {
			errs = append(errs, fmt.Errorf("%s variable_category must be terraform or env", where))
		}
		if category == "env" && c.HCL {
			errs = append(errs, fmt.Errorf("%s hcl=true is valid only for terraform variables", where))
		}
	case "webhook", "aws-parameter-store", "netlify":
		errs = append(errs, validateDeliverySyncTarget(where, c)...)
	case "vault-kv-v2":
		require(c.Mount, "mount")
		ref(c.TokenRef, "token_ref", false)
		if err := validateVaultSyncPath(c.Mount, false); err != nil {
			errs = append(errs, fmt.Errorf("%s mount %w", where, err))
		}
		if err := validateVaultSyncPath(c.PathPrefix, true); err != nil {
			errs = append(errs, fmt.Errorf("%s path_prefix %w", where, err))
		}
		if strings.ContainsRune(c.Field, '\x00') {
			errs = append(errs, fmt.Errorf("%s field must not contain a NUL byte", where))
		}
	}
	return errs
}

// validateDeliverySyncTarget checks the signed webhook, Parameter Store and
// Netlify targets (A202).
func validateDeliverySyncTarget(where string, c SecretSyncTargetConfig) []error {
	var errs []error
	require := func(value, name string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for %s", where, name, c.Type))
		}
	}
	ref := func(value, name string, optional bool) {
		if strings.TrimSpace(value) == "" && optional {
			return
		}
		if err := validateCredentialRef(value); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	require(c.Endpoint, "endpoint")
	switch c.Type {
	case "webhook":
		ref(c.SigningKeyRef, "signing_key_ref", false)
		ref(c.TokenRef, "token_ref", true)
	case "aws-parameter-store":
		require(c.Region, "region")
		require(c.AccessKeyID, "access_key_id")
		ref(c.SecretAccessRef, "secret_access_key_ref", false)
		ref(c.SessionTokenRef, "session_token_ref", true)
		if err := validateVaultSyncPath(c.PathPrefix, true); err != nil {
			errs = append(errs, fmt.Errorf("%s path_prefix %w", where, err))
		}
	case "netlify":
		require(c.AccountID, "account_id")
		ref(c.TokenRef, "token_ref", false)
	}
	return errs
}

func validateVaultSyncPath(raw string, allowEmpty bool) error {
	value := strings.Trim(strings.TrimSpace(raw), "/")
	if value == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("is required")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return errors.New("must not contain dot path components")
		}
		if part == "" {
			return errors.New("must not contain empty path components")
		}
		if strings.ContainsAny(part, "\x00\\") {
			return errors.New("must not contain a NUL byte or backslash")
		}
	}
	return nil
}

func validateCredentialRef(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "file:"):
		path := strings.TrimSpace(strings.TrimPrefix(raw, "file:"))
		if path == "" || !filepath.IsAbs(path) {
			return errors.New("file reference must contain an absolute path")
		}
		return nil
	case strings.HasPrefix(raw, "secret://") && strings.Trim(strings.TrimPrefix(raw, "secret://"), "/") != "":
		return nil
	default:
		return errors.New("must use file:/absolute/path or tenant-scoped secret://name")
	}
}

func validateSecretIntegrationEndpoint(raw string, allowInsecureLoopback bool) error {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(raw, allowInsecureLoopback); err != nil {
		return err
	}
	if allowInsecureLoopback && !netsec.IsInsecureLoopbackHTTPURL(raw) {
		return errors.New("allow_insecure_loopback is valid only with an HTTP localhost/loopback endpoint")
	}
	return nil
}

func validatePrivateEgress(where string, allow bool, cidrs []string) []error {
	var errs []error
	if !allow && len(normalizedStrings(cidrs)) > 0 {
		errs = append(errs, fmt.Errorf("%s private_egress_cidrs require allow_private_endpoint=true", where))
	}
	if allow && len(normalizedStrings(cidrs)) == 0 {
		errs = append(errs, fmt.Errorf("%s allow_private_endpoint requires private_egress_cidrs", where))
	}
	for _, raw := range normalizedStrings(cidrs) {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("%s private_egress_cidrs contains invalid CIDR %q", where, raw))
		}
	}
	return errs
}

func normalizedStrings(values []string) []string {
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

// validateProviderFieldScopes refuses a type-specific setting on a provider of
// another type.
func validateProviderFieldScopes(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if c.AllowWildcardAccountHost && c.Type != "mysql" {
		errs = append(errs, fmt.Errorf("%s allow_wildcard_account_host is only valid for mysql", where))
	}
	if len(c.RedisACLRoles) > 0 && c.Type != "redis" {
		errs = append(errs, fmt.Errorf("%s redis_acl_roles is only valid for redis", where))
	}
	if c.Type != "redis" && (c.RedisTLSCARef != "" || c.RedisTLSServerName != "" || c.AllowPlaintextRedis) {
		errs = append(errs, fmt.Errorf("%s Redis transport settings are only valid for redis", where))
	}
	if c.Type != "kubernetes" && (c.KubernetesAudience != "" || c.KubernetesTLSCARef != "" || c.KubernetesTLSServerName != "") {
		errs = append(errs, fmt.Errorf("%s Kubernetes audience and TLS settings are only valid for kubernetes", where))
	}
	if !tlsProviderTypes[c.Type] && (c.TLSCARef != "" || c.TLSServerName != "" || c.AllowPlaintext) {
		errs = append(errs, fmt.Errorf("%s tls_ca_ref, tls_server_name and allow_plaintext are not valid for %s", where, c.Type))
	}
	if c.Type != "ldap" && (c.BindDN != "" || c.UsersDN != "") {
		errs = append(errs, fmt.Errorf("%s bind_dn and users_dn are only valid for ldap", where))
	}
	if c.Type != "totp" && (c.SeedRef != "" || c.Digits != 0 || c.Period != "" || c.Algorithm != "") {
		errs = append(errs, fmt.Errorf("%s seed_ref, digits, period and algorithm are only valid for totp", where))
	}
	if c.Type != "oauth-client-credentials" && (c.ClientID != "" || c.ClientSecretRef != "" || c.RevocationEndpoint != "") {
		errs = append(errs, fmt.Errorf("%s client_id, client_secret_ref and revocation_endpoint are only valid for oauth-client-credentials", where))
	}
	return errs
}

// validateOAuthClientCredentialsProvider checks an OAuth 2.0 client-credentials
// provider: endpoint is the token endpoint, revocation_endpoint is optional, the
// client is confidential, max_ttl is the longest token lifetime the
// authorization server issues this client, and each allowed role's
// role_bindings value is its space-separated scopes (A239).
func validateOAuthClientCredentialsProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the token endpoint) is required for oauth-client-credentials", where))
	}
	if c.RevocationEndpoint != "" {
		if err := validateSecretIntegrationEndpoint(c.RevocationEndpoint, c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s revocation_endpoint: %w", where, err))
		}
	}
	if id := strings.TrimSpace(c.ClientID); id == "" || id != c.ClientID || strings.ContainsFunc(id, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s client_id is required for oauth-client-credentials, without surrounding spaces or control characters", where))
	}
	if err := validateCredentialRef(c.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s client_secret_ref: %w", where, err))
	}
	if strings.TrimSpace(c.MaxTTL) == "" {
		errs = append(errs, fmt.Errorf("%s max_ttl is required for oauth-client-credentials: the longest token lifetime the authorization server issues this client", where))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		if err := validOAuthScopes(c.RoleBindings[role]); err != nil {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must list the role's scopes: %w", where, role, err))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

// validOAuthScopes accepts one or more space-separated RFC 6749 scope-tokens
// (%x21 / %x23-5B / %x5D-7E).
func validOAuthScopes(raw string) error {
	scopes := strings.Fields(raw)
	if len(scopes) == 0 {
		return errors.New("at least one scope is required")
	}
	for _, scope := range scopes {
		for _, c := range []byte(scope) {
			if c < 0x21 || c == 0x22 || c == 0x5c || c > 0x7e {
				return fmt.Errorf("scope %q is not an RFC 6749 scope-token", scope)
			}
		}
	}
	return nil
}

// validateTOTPProvider checks a TOTP provider's seed reference and code
// parameters. A code lasts one period, so max_ttl must be set and no longer
// than the period: a lease can't outlast its code by more than one period (A239).
func validateTOTPProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if err := validateCredentialRef(c.SeedRef); err != nil {
		errs = append(errs, fmt.Errorf("%s seed_ref: %w", where, err))
	}
	if c.Digits != 0 && (c.Digits < 6 || c.Digits > 8) {
		errs = append(errs, fmt.Errorf("%s digits must be 6, 7 or 8", where))
	}
	period := 30 * time.Second
	switch strings.TrimSpace(c.Period) {
	case "", "30s":
	case "60s", "1m":
		period = 60 * time.Second
	default:
		errs = append(errs, fmt.Errorf("%s period must be 30s or 60s", where))
	}
	switch strings.ToUpper(strings.TrimSpace(c.Algorithm)) {
	case "", "SHA1", "SHA256", "SHA512":
	default:
		errs = append(errs, fmt.Errorf("%s algorithm must be SHA1, SHA256 or SHA512", where))
	}
	if strings.TrimSpace(c.MaxTTL) == "" {
		errs = append(errs, fmt.Errorf("%s max_ttl is required for totp and must not exceed the period", where))
	} else if ttl, err := c.MaxTTLDuration(); err == nil && ttl > period {
		errs = append(errs, fmt.Errorf("%s max_ttl %s exceeds the %s period a code lasts", where, ttl, period))
	}
	if len(c.RoleBindings) > 0 {
		errs = append(errs, fmt.Errorf("%s role_bindings are not used by totp: every allowed role reads the same seed's codes", where))
	}
	return errs
}

// validateLDAPProvider checks an LDAP provider's directory, administrator and
// role groups (A239).
func validateLDAPProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	for name, value := range map[string]string{"addr": c.Addr, "bind_dn": c.BindDN, "users_dn": c.UsersDN} {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for ldap", where, name))
		}
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	if strings.TrimSpace(c.TLSCARef) != "" {
		if err := validateCredentialRef(c.TLSCARef); err != nil {
			errs = append(errs, fmt.Errorf("%s tls_ca_ref: %w", where, err))
		}
	}
	errs = append(errs, validateProviderTransport(where, c)...)
	return append(errs, validateRoleBindingsCoverRoles(where, c)...)
}

// validateProviderTransport keeps an A239 provider's connection on verified
// TLS unless the operator allowed plaintext to a literal loopback or private IP.
func validateProviderTransport(where string, c DynamicSecretProviderConfig) []error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(c.Addr))
	if err != nil || host == "" {
		return []error{fmt.Errorf("%s addr must be host:port", where)}
	}
	address := net.ParseIP(host)
	if !c.AllowPlaintext {
		if address != nil && c.TLSServerName == "" {
			return []error{fmt.Errorf("%s tls_server_name is required when addr is an IP address", where)}
		}
		return nil
	}
	if c.TLSCARef != "" || c.TLSServerName != "" {
		return []error{fmt.Errorf("%s allow_plaintext forbids TLS settings", where)}
	}
	if address == nil || (!address.IsLoopback() && !address.IsPrivate()) {
		return []error{fmt.Errorf("%s allow_plaintext requires a literal loopback or private IP addr", where)}
	}
	return nil
}

// validateRoleBindingsCoverRoles requires exactly one binding per allowed
// role, and none for a role that isn't allowed.
func validateRoleBindingsCoverRoles(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		if strings.TrimSpace(c.RoleBindings[role]) == "" {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] is required for %s", where, role, c.Type))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}
