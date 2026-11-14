// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/accessdesktop"
	"unicode"

	"trstctl.com/trstctl/internal/dbaccess"
	"trstctl.com/trstctl/internal/hostedkey"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/redisacl"
	"trstctl.com/trstctl/internal/synctarget"
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
	// Trail (N4) is a CloudTrail trail's S3 delivery the decoy monitor also
	// reads: an organization trail covers every account in the organization,
	// and a trail that logs data events adds them; LookupEvents returns
	// neither.
	Trail *AWSHoneyTrailConfig `json:"trail,omitempty"`
}

// AWSHoneyTrailConfig is the bucket a trail delivers its log files to. Its
// credentials need only s3:ListBucket and s3:GetObject on the trail's prefix.
type AWSHoneyTrailConfig struct {
	Bucket       string `json:"bucket"`
	BucketRegion string `json:"bucket_region"`
	// KeyPrefix is the trail's S3 key prefix, if it has one.
	KeyPrefix string `json:"key_prefix,omitempty"`
	// OrganizationID (o-…) marks an organization trail, whose files sit under
	// AWSLogs/<organization-id>/.
	OrganizationID string `json:"organization_id,omitempty"`
	// Accounts limits the accounts read; empty reads every account the
	// bucket holds.
	Accounts []string `json:"accounts,omitempty"`
	// S3Endpoint is an S3-compatible endpoint (default
	// https://s3.<bucket_region>.amazonaws.com); PathStyle addresses
	// <endpoint>/<bucket>.
	S3Endpoint     string `json:"s3_endpoint,omitempty"`
	PathStyle      bool   `json:"path_style,omitempty"`
	CredentialsRef string `json:"credentials_ref"`
	// NotificationsQueueURL (N4-L1) is an SQS queue receiving the bucket's
	// object-created notifications (S3 event notifications, through
	// EventBridge, or the trail's own SNS topic): the monitor reads the files
	// they name instead of listing every account, Region and day folder, and
	// lists the bucket in full only on its first pass and once a day after,
	// for a notification that never came. The credentials then also need
	// sqs:ReceiveMessage and sqs:DeleteMessage on the queue.
	NotificationsQueueURL string `json:"notifications_queue_url,omitempty"`
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
var azureGatewayTenant = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// SSHCertificateRole is what one role of an ssh-certificate provider
// certifies (A239-L11). Each lease gets a fresh Ed25519 key pair and a
// certificate from the control plane's SSH CA for exactly these principals.
type SSHCertificateRole struct {
	// CertificateType is user (the default) or host.
	CertificateType string            `json:"certificate_type,omitempty"`
	Principals      []string          `json:"principals"`
	Extensions      map[string]string `json:"extensions,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
}

// DynamicSecretGatewayConfig pins where a brokered cloud account can call.
// These are public routing facts, covered by the provider's reviewed configuration identity.
type DynamicSecretGatewayConfig struct {
	Endpoint      string   `json:"endpoint"`
	Service       string   `json:"service,omitempty"`
	Region        string   `json:"region,omitempty"`
	TokenEndpoint string   `json:"token_endpoint,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
}

type DynamicSecretProviderConfig struct {
	// WindowsHostAgentID selects the native enrolled-host transport. Role bindings
	// then contain local account SIDs, never SSH usernames or remote authorities.
	WindowsHostAgentID string                      `json:"windows_host_agent_id,omitempty"`
	ADReconcile        *ADReconcileConfig          `json:"ad_reconcile,omitempty"`
	Desktop            *accessdesktop.Binding      `json:"desktop,omitempty"`
	Console            *accessconsole.Binding      `json:"console,omitempty"`
	Gateway            *DynamicSecretGatewayConfig `json:"gateway,omitempty"`
	TenantID           string                      `json:"tenant_id"`
	ID                 string                      `json:"id"`
	Type               string                      `json:"type"`
	// SecretEnvironment places the provider in a secrets project
	// environment, "<project>/<environment>" (A235-L2). When that
	// environment is restricted, only the members granted it see the
	// provider and its leases (read) or issue, renew and revoke them
	// (write); while the environment does not exist the provider is closed.
	SecretEnvironment string `json:"secret_environment,omitempty"`

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
	// AuthorityHost (azure-entra) is the Microsoft identity platform a rotated
	// client secret is proven at (A240); https://login.microsoftonline.com by
	// default.
	AuthorityHost  string `json:"authority_host,omitempty"`
	DB             int    `json:"db,omitempty"`
	UsernamePrefix string `json:"username_prefix,omitempty"`

	// IAMEndpoint is where an aws-iam or aws-sts provider reads the policies
	// of the roles its leases assume (G2), and where a gcp-iam provider reads
	// its project's IAM policy (G2-L2). Empty means AWS IAM for the region's
	// partition, or Google's Resource Manager.
	IAMEndpoint string `json:"iam_endpoint,omitempty"`
	// RevokeWithDenyPolicy (aws-sts) ends a revoked lease's session before its
	// expiry with an inline deny policy on its role for that one session (N3).
	// The provider's credentials then also need iam:PutRolePolicy,
	// iam:GetRolePolicy, iam:ListRolePolicies and iam:DeleteRolePolicy on the
	// bound roles. Without it a revoked session lapses at its expiry.
	RevokeWithDenyPolicy bool `json:"revoke_with_deny_policy,omitempty"`
	// AllowRoleChaining (aws-sts) lets a lease's session assume other roles
	// (N3-L3). Without it each lease is issued with a session policy that
	// denies sts:AssumeRole, so no session outlives its revocation as another
	// role. With it a revocation waits an hour past the session's expiry (the
	// longest a chained session runs), and it can't be combined with
	// revoke_with_deny_policy.
	AllowRoleChaining bool `json:"allow_role_chaining,omitempty"`
	// DenyAccessKeyID, DenySecretAccessRef and DenySessionTokenRef (aws-sts,
	// N3-L1) are a second IAM credential used only to write, read back and
	// prune the revoke_with_deny_policy denials, so the credential that issues
	// sessions needs no IAM write permission. Empty uses the provider's own.
	DenyAccessKeyID     string `json:"deny_access_key_id,omitempty"`
	DenySecretAccessRef string `json:"deny_secret_access_key_ref,omitempty"`
	DenySessionTokenRef string `json:"deny_session_token_ref,omitempty"`
	// DenyQuotaFallback (aws-sts, N3-L2) is "token_issue_time": when a role's
	// inline policies are at IAM's size quota, a revocation attaches a managed
	// policy denying every session of the role issued before now
	// (aws:TokenIssueTime), the revoked one with them, instead of failing.
	// Every other session of the role issued before then is denied too.
	DenyQuotaFallback string `json:"deny_quota_fallback,omitempty"`

	PasswordRef             string `json:"password_ref,omitempty"`
	SecretAccessRef         string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef         string `json:"session_token_ref,omitempty"`
	BearerTokenRef          string `json:"bearer_token_ref,omitempty"`
	KubernetesAudience      string `json:"kubernetes_audience,omitempty"`
	KubernetesTLSCARef      string `json:"kubernetes_tls_ca_ref,omitempty"`
	KubernetesTLSServerName string `json:"kubernetes_tls_server_name,omitempty"`
	// BindDN and UsersDN are the LDAP provider's administrator and the
	// container its leased entries are created in (A239).
	DirectoryMode string            `json:"directory_mode,omitempty"`
	ADLogonNames  map[string]string `json:"ad_logon_names,omitempty"`
	BindDN        string            `json:"bind_dn,omitempty"`
	UsersDN       string            `json:"users_dn,omitempty"`
	// TLSCARef pins a private CA and TLSServerName names the certificate the
	// A239 providers verify; AllowPlaintext permits an unencrypted connection
	// to a literal loopback or private IP only.
	TLSCARef       string `json:"tls_ca_ref,omitempty"`
	TLSServerName  string `json:"tls_server_name,omitempty"`
	AllowPlaintext bool   `json:"allow_plaintext,omitempty"`
	// StartTLS (ldap) connects to the directory's plain LDAP port and
	// upgrades with StartTLS, verifying tls_server_name against tls_ca_ref
	// (or system roots) before the administrator binds; it never falls back
	// to plaintext (A239-L3). Without it addr is the LDAPS listener.
	StartTLS bool `json:"start_tls,omitempty"`
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
	ClientID           string `json:"client_id,omitempty"`
	ClientSecretRef    string `json:"client_secret_ref,omitempty"`
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// PrivateKeyRef and InstallationID are a github-app provider's app private
	// key (PEM) and the installation its tokens are minted for; ClientID is the
	// app's client ID (A239).
	PrivateKeyRef  string `json:"private_key_ref,omitempty"`
	InstallationID string `json:"installation_id,omitempty"`
	// Account is a snowflake provider's account identifier (<orgname>-
	// <accountname>); its administrator is admin_user with the key pair whose
	// private key is private_key_ref (A239).
	Account string `json:"account,omitempty"`
	// UserGroup is the ElastiCache user group, or the MemoryDB ACL, that an
	// aws-elasticache or aws-memorydb lease's user joins; Engine is
	// ElastiCache's user engine, redis (default) or valkey (A239).
	UserGroup string `json:"user_group,omitempty"`
	Engine    string `json:"engine,omitempty"`
	// APIKeyRef is an ibm-api-connect provider's platform API key, exchanged
	// with client_id and client_secret_ref for a platform token (A239), a
	// datadog provider's administrator API key, or an openai provider's
	// organization admin key (A240).
	APIKeyRef string `json:"api_key_ref,omitempty"`
	// ApplicationKeyRef is a datadog provider's administrator application key,
	// sent with api_key_ref on every key-management call (A240).
	ApplicationKeyRef string `json:"application_key_ref,omitempty"`
	// HostKeyFingerprint pins a unix provider's SSH host key
	// ("SHA256:..."); Sudo runs its chpasswd through `sudo -n` for an
	// admin_user that is not root (A240).
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	Sudo               bool   `json:"sudo,omitempty"`
	// AdminUser is the administrator a clickhouse, rabbitmq, couchbase or milvus
	// provider creates and deletes leased users as, an elasticsearch provider creates and
	// invalidates API keys as, a kafka provider's SCRAM user that sets
	// credentials and ACLs, or the role a cassandra provider creates, grants and
	// drops login roles as (its password is password_ref, A239).
	AdminUser string `json:"admin_user,omitempty"`
	// SSOAdmin is a vcenter-sso provider's single sign-on administrator,
	// user@domain, whose password is password_ref; admin_user and
	// private_key_ref are the appliance's root shell (A271).
	SSOAdmin string `json:"sso_admin,omitempty"`
	// TOTPProviders (A272) maps an identity provider administrator role to
	// the totp provider holding that account's MFA seed: an emergency
	// release carries the current code, never the seed.
	TOTPProviders map[string]string `json:"totp_providers,omitempty"`
	// HardwareKeyHolders (A272) records, per role, who holds the account's
	// hardware security keys; the keys stay with those people.
	HardwareKeyHolders map[string][]string `json:"hardware_key_holders,omitempty"`
	// Tailnet is a tailscale provider's tailnet, "-" (the API token's own) by
	// default; its API token is bearer_token_ref (A239).
	Tailnet      string   `json:"tailnet,omitempty"`
	AllowedRoles []string `json:"allowed_roles"`
	// RoleBindings maps an allowed role to its provider-native authority. AWS
	// dynamic values are assumable IAM role ARNs; Kubernetes values are Role/name or
	// ClusterRole/name. Fixed-authority providers may omit it.
	RoleBindings map[string]string `json:"role_bindings,omitempty"`
	// RoleAccess gives each allowed role of a postgresql, mysql or mongodb
	// provider its access class, read or readwrite (A239-L1). A role named as
	// a class (readonly, reader or read; writer or readwrite) needs none; any
	// other role must have one, because a class is never read from a name.
	RoleAccess map[string]string `json:"role_access,omitempty"`
	// RedisACLRoles gives each allowed Redis role literal key namespaces and an
	// explicit command allowlist. Raw ACL rules and categories are forbidden.
	RedisACLRoles map[string]redisacl.Role `json:"redis_acl_roles,omitempty"`
	// SSHRoles gives each allowed role of an ssh-certificate provider the
	// certificate its leases carry (A239-L11): the principals it certifies,
	// user or host, and its extensions and critical options.
	SSHRoles            map[string]SSHCertificateRole `json:"ssh_roles,omitempty"`
	RedisTLSCARef       string                        `json:"redis_tls_ca_ref,omitempty"`
	RedisTLSServerName  string                        `json:"redis_tls_server_name,omitempty"`
	AllowPlaintextRedis bool                          `json:"allow_plaintext_redis,omitempty"`
	MaxTTL              string                        `json:"max_ttl,omitempty"`
	// AllowStaticRotation lets the static-rotation worker mint long-lived
	// credentials with no native expiry through this provider (postgresql,
	// mysql, aws-iam) for roles in allowed_roles. Off by default: a dynamic
	// provider that only ever issues bounded leases keeps that guarantee.
	AllowStaticRotation bool `json:"allow_static_rotation,omitempty"`
	// RotationAccounts makes a role's static rotation two-user (A240): the role
	// alternates between these two existing accounts, which the database's
	// owner provisions with the role's grants. A rotation sets a new password
	// on the account consumers are not using, publishes it, and then retires
	// the other by replacing its password; no account is created or dropped,
	// so the grants persist. Needs allow_static_rotation (postgresql).
	RotationAccounts      map[string][]string `json:"rotation_accounts,omitempty"`
	AllowPrivate          bool                `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback bool                `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs    []string            `json:"private_egress_cidrs,omitempty"`
}

// StaticRotationProviderTypes are the dynamic-provider types whose backends can
// mint a credential without native expiry and revoke it by reference, which is
// what scheduled static rotation needs (A14).
var StaticRotationProviderTypes = map[string]bool{"postgresql": true, "mysql": true, "aws-iam": true, "auth0": true, "datadog": true, "openai": true, "ldap": true, "unix": true, "mongodb": true, "oracle": true, "mssql": true, "azure-sql": true, "openrouter": true, "fireworks": true, "litellm": true, "supabase": true, "convex": true, "dbt": true, "cloudflare": true, "cloudflare-r2": true, "azure-entra": true, "okta": true, "databricks": true, "windows": true, "gcp-iam": true, "snowflake": true, "iosxe": true, "junos": true, "eos": true, "fortigate": true, "bigip": true, "redfish": true, "esxi": true, "vcenter-sso": true, "okta-user": true, "entra-user": true, "google-workspace-user": true}

// SinglePhaseRotationProviderTypes are the static-rotation types whose provider
// invalidates the current credential when it issues the next one: a rotation
// through them runs only when acknowledged (A240).
var SinglePhaseRotationProviderTypes = map[string]bool{"auth0": true, "iosxe": true, "junos": true, "eos": true, "fortigate": true, "bigip": true, "redfish": true, "esxi": true, "vcenter-sso": true,
	"okta-user": true, "entra-user": true, "google-workspace-user": true}

// TwoUserRotationProviderTypes are the static-rotation types whose roles may
// alternate between two fixed accounts (rotation_accounts, A240).
var TwoUserRotationProviderTypes = map[string]bool{"postgresql": true, "ldap": true, "unix": true, "mongodb": true, "oracle": true, "mssql": true, "azure-sql": true, "windows": true}

// sortedTrueKeys lists a type set's members in order, for messages.
func sortedTrueKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key, ok := range set {
		if ok {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

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
	// ${value_base64}, ${delivery_id} and ${timestamp} placeholders. A
	// generic CI push (type generic-ci-json) may name a signing key too
	// (OD-12); its pushes then carry the same signature headers.
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

	// Hosted targets (A241, internal/synctarget): what the destination is,
	// in the type's binding grammar, and the user, key ID or client name a
	// type that takes one authenticates with beside token_ref.
	Binding  string `json:"binding,omitempty"`
	Username string `json:"username,omitempty"`

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
	"totp": {}, "oauth-client-credentials": {}, "clickhouse": {}, "elasticsearch": {}, "rabbitmq": {},
	"tailscale": {}, "mongodb-atlas": {}, "kafka": {}, "couchbase": {}, "milvus": {}, "mssql": {}, "azure-sql": {},
	"github-app": {}, "snowflake": {}, "aws-elasticache": {}, "aws-memorydb": {}, "ibm-api-connect": {}, "auth0": {},
	"datadog": {}, "openai": {}, "unix": {}, "cassandra": {}, "oracle": {}, "hana": {},
	"openrouter": {}, "fireworks": {}, "litellm": {}, "supabase": {}, "convex": {}, "dbt": {}, "cloudflare": {}, "cloudflare-r2": {},
	"okta": {}, "databricks": {}, "windows": {}, "iosxe": {}, "junos": {}, "eos": {}, "fortigate": {}, "bigip": {}, "redfish": {}, "esxi": {}, "vcenter-sso": {},
	"okta-user": {}, "entra-user": {}, "google-workspace-user": {}, "ssh-certificate": {},
}

// clientIDProviderTypes take client_id, and clientSecretProviderTypes
// client_secret_ref: an OAuth client the provider authenticates as.
var (
	clientIDProviderTypes     = map[string]bool{"oauth-client-credentials": true, "mongodb-atlas": true, "github-app": true, "ibm-api-connect": true, "auth0": true, "databricks": true, "entra-user": true}
	clientSecretProviderTypes = map[string]bool{"oauth-client-credentials": true, "mongodb-atlas": true, "ibm-api-connect": true, "auth0": true, "databricks": true, "entra-user": true}
)

// apiKeyProviderTypes take api_key_ref, an administrator's key or token
// (A239, A240).
var apiKeyProviderTypes = map[string]bool{
	"ibm-api-connect": true, "datadog": true, "openai": true,
	"openrouter": true, "fireworks": true, "litellm": true, "supabase": true, "convex": true, "dbt": true, "cloudflare": true, "cloudflare-r2": true,
	"okta": true, "fortigate": true, "okta-user": true,
}

// adminUserProviderTypes take admin_user (A239).
var adminUserProviderTypes = map[string]bool{"clickhouse": true, "elasticsearch": true, "rabbitmq": true, "kafka": true, "couchbase": true, "milvus": true, "snowflake": true, "unix": true, "cassandra": true, "windows": true, "iosxe": true, "junos": true, "eos": true, "fortigate": true, "bigip": true, "redfish": true, "esxi": true, "vcenter-sso": true, "google-workspace-user": true}

// tlsProviderTypes take the shared tls_ca_ref, tls_server_name and
// allow_plaintext settings (A239).
var tlsProviderTypes = map[string]bool{"ldap": true, "kafka": true, "cassandra": true, "eos": true, "fortigate": true, "bigip": true, "redfish": true, "esxi": true, "vcenter-sso": true}

var dynamicAWSRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

var secretSyncTypes = map[string]struct{}{
	"aws-secrets-manager": {}, "gcp-secret-manager": {}, "azure-key-vault": {},
	"github-actions": {}, "gitlab-ci": {}, "vercel": {},
	"generic-ci-json": {}, "kubernetes-secrets": {},
	"terraform-cloud-opentofu": {}, "vault-kv-v2": {},
	"webhook": {}, "aws-parameter-store": {}, "netlify": {},
}

// secretEnvironmentPlacement is a provider's secret_environment: a secrets
// project slug and one of its environment slugs (A235-L2).
var secretEnvironmentPlacement = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9-]{0,62}$`)

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
		if env := strings.TrimSpace(item.SecretEnvironment); env != "" && !secretEnvironmentPlacement.MatchString(env) {
			errs = append(errs, fmt.Errorf("%s secret_environment must be <project>/<environment>: two slugs of lowercase letters, digits and hyphens", where))
		}
		if item.AllowStaticRotation && !StaticRotationProviderTypes[strings.TrimSpace(item.Type)] {
			errs = append(errs, fmt.Errorf("secret_integrations.dynamic_providers[%d]: allow_static_rotation is served for %s providers only", i, strings.Join(sortedTrueKeys(StaticRotationProviderTypes), ", ")))
		}
		if ttl, err := item.MaxTTLDuration(); err != nil || ttl <= 0 {
			errs = append(errs, fmt.Errorf("%s max_ttl must be a positive duration", where))
		}
		if item.WindowsHostAgentID != "" && item.Type != "windows" {
			errs = append(errs, fmt.Errorf("%s windows_host_agent_id requires windows", where))
		}
		errs = append(errs, validateRotationAccounts(where, item)...)
		errs = append(errs, validateDynamicProvider(where, item)...)
		errs = append(errs, validatePrivateEgress(where, item.AllowPrivate, item.PrivateEgressCIDRs)...)
	}
	errs = append(errs, validateBreakGlassTOTP(cfg.DynamicProviders)...)
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
		_, builtIn := secretSyncTypes[item.Type]
		if _, hosted := synctarget.Lookup(item.Type); !builtIn && !hosted {
			errs = append(errs, fmt.Errorf("%s type %q is not a built-in secret-sync target", where, item.Type))
			continue
		}
		// A hosted target may leave endpoint empty for its vendor's API base.
		if t, hosted := synctarget.Lookup(item.Type); !hosted || strings.TrimSpace(item.Endpoint) != "" || t.Endpoint == "" {
			if err := validateSecretIntegrationEndpoint(item.Endpoint, item.AllowInsecureLoopback); err != nil {
				errs = append(errs, fmt.Errorf("%s endpoint: %w", where, err))
			}
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
	if item.Trail != nil {
		errs = append(errs, validateAWSHoneyTrail(where+" trail", *item.Trail, item.AllowInsecureLoopback, item.AllowPrivate)...)
	}
	return errs
}

var (
	awsHoneyBucket       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	awsHoneyQueuePath    = regexp.MustCompile(`^/[0-9]{12}/[A-Za-z0-9_-]{1,80}(\.fifo)?$`)
	awsHoneyOrganization = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	awsHoneyKeyPrefix    = regexp.MustCompile(`^[A-Za-z0-9!_.*'()-]+(/[A-Za-z0-9!_.*'()-]+)*$`)
)

// validateAWSHoneyTrail checks an N4 trail delivery: a real bucket and Region,
// an organization ID when given, at most 1,000 explicit accounts, and an
// S3 endpoint under the same rules as every secret-integration endpoint.
func validateAWSHoneyTrail(where string, trail AWSHoneyTrailConfig, allowInsecureLoopback, allowPrivate bool) []error {
	var errs []error
	if !awsHoneyBucket.MatchString(trail.Bucket) || strings.Contains(trail.Bucket, "..") {
		errs = append(errs, fmt.Errorf("%s bucket must be an S3 bucket name", where))
	}
	if !awsHoneyRegion.MatchString(trail.BucketRegion) {
		errs = append(errs, fmt.Errorf("%s bucket_region must be an AWS region name", where))
	}
	if trail.KeyPrefix != "" && (!awsHoneyKeyPrefix.MatchString(trail.KeyPrefix) || strings.Contains(trail.KeyPrefix, "..")) {
		errs = append(errs, fmt.Errorf("%s key_prefix must be a relative S3 key prefix without a trailing slash", where))
	}
	if trail.OrganizationID != "" && !awsHoneyOrganization.MatchString(trail.OrganizationID) {
		errs = append(errs, fmt.Errorf("%s organization_id must be an AWS organization ID (o-…)", where))
	}
	if len(trail.Accounts) > 1000 {
		errs = append(errs, fmt.Errorf("%s accounts lists more than 1,000 accounts", where))
	}
	seen := map[string]bool{}
	for _, account := range trail.Accounts {
		if !awsHoneyAccount.MatchString(account) || seen[account] {
			errs = append(errs, fmt.Errorf("%s accounts must be unique 12-digit AWS accounts", where))
			break
		}
		seen[account] = true
	}
	if err := validateCredentialRef(trail.CredentialsRef); err != nil {
		errs = append(errs, fmt.Errorf("%s credentials_ref: %w", where, err))
	}
	if queue := trail.NotificationsQueueURL; queue != "" {
		parsed, err := url.Parse(queue)
		switch {
		case err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !awsHoneyQueuePath.MatchString(parsed.Path):
			errs = append(errs, fmt.Errorf("%s notifications_queue_url must be an SQS queue URL (https://sqs.<region>.amazonaws.com/<account>/<queue>)", where))
		default:
			if err := validateSecretIntegrationEndpoint(parsed.Scheme+"://"+parsed.Host, allowInsecureLoopback); err != nil {
				errs = append(errs, fmt.Errorf("%s notifications_queue_url: %w", where, err))
			}
			host := parsed.Hostname()
			address := net.ParseIP(host)
			if !allowPrivate && (netsec.IsLoopbackHost(host) || (address != nil && (address.IsPrivate() || address.IsLinkLocalUnicast()))) {
				errs = append(errs, fmt.Errorf("%s private notifications_queue_url requires allow_private_endpoint and a CIDR allowlist", where))
			}
		}
	}
	if trail.S3Endpoint != "" {
		if err := validateSecretIntegrationEndpoint(trail.S3Endpoint, allowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s s3_endpoint: %w", where, err))
		}
		if parsed, err := url.Parse(trail.S3Endpoint); err == nil {
			host := parsed.Hostname()
			address := net.ParseIP(host)
			if !allowPrivate && (netsec.IsLoopbackHost(host) || (address != nil && (address.IsPrivate() || address.IsLinkLocalUnicast()))) {
				errs = append(errs, fmt.Errorf("%s private s3_endpoint requires allow_private_endpoint and a CIDR allowlist", where))
			}
		}
	}
	return errs
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

// a239ProviderValidators check the A239 library's providers, one function each.
var a239ProviderValidators = map[string]func(string, DynamicSecretProviderConfig) []error{
	"ldap": validateLDAPProvider, "totp": validateTOTPProvider, "ssh-certificate": validateSSHCertificateProvider,
	"oauth-client-credentials": validateOAuthClientCredentialsProvider, "clickhouse": validateClickHouseProvider,
	"elasticsearch": validateElasticsearchProvider, "rabbitmq": validateRabbitMQProvider,
	"tailscale": validateTailscaleProvider, "mongodb-atlas": validateMongoDBAtlasProvider, "kafka": validateKafkaProvider,
	"couchbase": validateCouchbaseProvider, "milvus": validateMilvusProvider,
	"mssql": validateMSSQLProvider, "azure-sql": validateMSSQLProvider, "github-app": validateGitHubAppProvider,
	"snowflake": validateSnowflakeProvider, "aws-elasticache": validateAWSCacheProvider, "aws-memorydb": validateAWSCacheProvider,
	"ibm-api-connect": validateAPIConnectProvider, "cassandra": validateCassandraProvider, "oracle": validateOracleProvider,
	"hana":  validateHANAProvider,
	"auth0": validateAuth0Provider, "datadog": validateDatadogProvider, "openai": validateOpenAIProvider,
	"openrouter": validateHostedKeyProvider, "fireworks": validateHostedKeyProvider, "litellm": validateHostedKeyProvider, "supabase": validateHostedKeyProvider, "convex": validateHostedKeyProvider, "dbt": validateHostedKeyProvider, "cloudflare": validateHostedKeyProvider, "cloudflare-r2": validateHostedKeyProvider,
	"unix": validateUnixProvider, "windows": validateUnixProvider,
	"iosxe": validateNetworkDeviceProvider, "junos": validateNetworkDeviceProvider,
	"eos": validateNetworkAPIProvider, "fortigate": validateNetworkAPIProvider, "bigip": validateNetworkAPIProvider,
	"redfish": validateNetworkAPIProvider, "esxi": validateNetworkAPIProvider, "vcenter-sso": validateVCenterSSOProvider,
	"okta-user": validateIdPAdminProvider, "entra-user": validateIdPAdminProvider, "google-workspace-user": validateIdPAdminProvider,
	"okta": validateClientSecretProvider, "databricks": validateClientSecretProvider,
}

// validateRotationAccounts checks a provider's two-user pairs (A240): each
// names an allowed role and two distinct accounts, and no account serves two
// roles, because a rotation of one would retire the other's live credential.
func validateRotationAccounts(where string, c DynamicSecretProviderConfig) []error {
	if len(c.RotationAccounts) == 0 {
		return nil
	}
	var errs []error
	if !TwoUserRotationProviderTypes[c.Type] || !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s rotation_accounts needs allow_static_rotation on a provider of type %s", where, strings.Join(sortedTrueKeys(TwoUserRotationProviderTypes), " or ")))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
	}
	owner := map[string]string{}
	roles := make([]string, 0, len(c.RotationAccounts))
	for role := range c.RotationAccounts {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		accounts := c.RotationAccounts[role]
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s rotation_accounts role %q is not in allowed_roles", where, role))
		}
		if len(accounts) != 2 || accounts[0] != strings.TrimSpace(accounts[0]) || accounts[1] != strings.TrimSpace(accounts[1]) ||
			accounts[0] == "" || accounts[1] == "" || accounts[0] == accounts[1] {
			errs = append(errs, fmt.Errorf("%s rotation_accounts role %q needs two distinct account names", where, role))
			continue
		}
		for _, account := range accounts {
			switch {
			case c.Type == "ldap" && (!strings.Contains(account, "=") ||
				!strings.HasSuffix(strings.ToLower(account), ","+strings.ToLower(strings.TrimSpace(c.UsersDN)))):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not an entry under users_dn", where, account))
			case c.Type == "mongodb" && !mongoUserName.MatchString(account):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not a MongoDB user name", where, account))
			case (c.Type == "unix" || c.Type == "windows") && !unixAccountName.MatchString(account):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not a local account name", where, account))
			case c.Type == "oracle" && !oracleIdentifier.MatchString(account):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not an Oracle user name", where, account))
			case (c.Type == "mssql" || c.Type == "azure-sql") && !mssqlAccountName.MatchString(account):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not a plain SQL Server account name", where, account))
			case c.Type == "postgresql" && (len(account) > 63 || strings.ContainsRune(account, 0)):
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q is not a PostgreSQL role name", where, account))
			}
			if other, taken := owner[account]; taken {
				errs = append(errs, fmt.Errorf("%s rotation_accounts account %q serves roles %q and %q", where, account, other, role))
			}
			owner[account] = role
		}
	}
	return errs
}

func validateDynamicProvider(where string, c DynamicSecretProviderConfig) []error {
	errs := validateProviderFieldScopes(where, c)
	if validate, ok := a239ProviderValidators[c.Type]; ok {
		errs = append(errs, validate(where, c)...)
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
	case "postgresql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		errs = append(errs, validateDatabaseRoleAccess(where, c)...)
	case "mysql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		errs = append(errs, validateDatabaseRoleAccess(where, c)...)
		require(c.Database, "database")
		require(c.Addr, "addr")
		require(c.AccountHost, "account_host")
		if strings.ContainsAny(c.AccountHost, "%_") && !c.AllowWildcardAccountHost {
			errs = append(errs, fmt.Errorf("%s wildcard account_host requires allow_wildcard_account_host=true", where))
		}
	case "mongodb":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		errs = append(errs, validateDatabaseRoleAccess(where, c)...)
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
		if c.AuthorityHost != "" {
			if err := validateSecretIntegrationEndpoint(c.AuthorityHost, c.AllowInsecureLoopback); err != nil {
				errs = append(errs, fmt.Errorf("%s authority_host: %w", where, err))
			}
		}
	}
	if c.Desktop != nil {
		if c.Desktop.AccountKind != "" || len(c.Desktop.Accounts) != 0 {
			errs = append(errs, fmt.Errorf("%s desktop account identities are derived from the provider's reviewed AD role, use ad_logon_names", where))
		}
		if (c.Type != "unix" && c.Type != "windows" && c.Type != "ldap") || !c.AllowStaticRotation {
			errs = append(errs, fmt.Errorf("%s desktop needs a static-rotation unix, windows or ldap provider", where))
		}
		if c.Gateway != nil || c.Console != nil {
			errs = append(errs, fmt.Errorf("%s desktop cannot mix HTTP or cloud console routing", where))
		}
		if err := c.Desktop.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s desktop: %w", where, err))
		}
	}
	if c.Console != nil {
		if c.Type != "aws-sts" {
			errs = append(errs, fmt.Errorf("%s console binding requires aws-sts", where))
		}
		if err := c.Console.Validate(c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s console: %w", where, err))
		}
	}

	if c.Gateway != nil {
		switch c.Type {
		case "aws-sts":
			if c.Gateway.Service != "s3" && c.Gateway.Service != "sts" {
				errs = append(errs, fmt.Errorf("%s gateway service must be s3 or sts", where))
			}
			if !awsHoneyRegion.MatchString(c.Gateway.Region) {
				errs = append(errs, fmt.Errorf("%s gateway region must be explicit", where))
			}
			if c.Gateway.TokenEndpoint != "" || len(c.Gateway.Scopes) != 0 {
				errs = append(errs, fmt.Errorf("%s AWS gateway cannot carry OAuth scope", where))
			}
		case "gcp-iam", "azure-entra":
			if c.Gateway.Service != "" || c.Gateway.Region != "" {
				errs = append(errs, fmt.Errorf("%s OAuth gateway cannot carry AWS scope", where))
			}
			if err := validateSecretIntegrationEndpoint(c.Gateway.TokenEndpoint, c.AllowInsecureLoopback); err != nil {
				errs = append(errs, fmt.Errorf("%s gateway token_endpoint: %w", where, err))
			}
			u, err := url.Parse(c.Gateway.TokenEndpoint)
			if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				errs = append(errs, fmt.Errorf("%s gateway token_endpoint must be a fixed URL without credentials or query", where))
			}
			if len(c.Gateway.Scopes) == 0 || len(c.Gateway.Scopes) > 16 {
				errs = append(errs, fmt.Errorf("%s gateway needs one to sixteen explicit OAuth scopes", where))
			}
			seen := map[string]bool{}
			for _, scope := range c.Gateway.Scopes {
				u, err := url.Parse(scope)
				if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(scope) > 256 || strings.ContainsAny(scope, " \t\r\n") || seen[scope] {
					errs = append(errs, fmt.Errorf("%s gateway has an invalid or duplicate OAuth scope", where))
				}
				seen[scope] = true
			}
			if c.Type == "azure-entra" {
				authority := c.AuthorityHost
				if authority == "" {
					authority = "https://login.microsoftonline.com"
				}
				u, err := url.Parse(authority)
				if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
					errs = append(errs, fmt.Errorf("%s Azure authority_host must be a fixed origin", where))
				}
				if !azureGatewayTenant.MatchString(c.AzureTenant) || strings.EqualFold(c.AzureTenant, "common") || strings.EqualFold(c.AzureTenant, "organizations") || strings.EqualFold(c.AzureTenant, "consumers") {
					errs = append(errs, fmt.Errorf("%s Azure gateway requires one explicit tenant", where))
				}
				expected := strings.TrimRight(authority, "/") + "/" + url.PathEscape(c.AzureTenant) + "/oauth2/v2.0/token"
				if c.Gateway.TokenEndpoint != expected {
					errs = append(errs, fmt.Errorf("%s Azure gateway token endpoint must match the configured authority and tenant", where))
				}
				if len(c.Gateway.Scopes) != 1 || !strings.HasSuffix(c.Gateway.Scopes[0], "/.default") {
					errs = append(errs, fmt.Errorf("%s Azure gateway requires one explicit resource /.default scope", where))
				}
			}

		default:
			errs = append(errs, fmt.Errorf("%s gateway is supported only for aws-sts, gcp-iam or azure-entra", where))
		}
		if err := validateSecretIntegrationEndpoint(c.Gateway.Endpoint, c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s gateway endpoint: %w", where, err))
		}
		endpoint, err := url.Parse(c.Gateway.Endpoint)
		if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
			errs = append(errs, fmt.Errorf("%s gateway endpoint must name only a fixed origin", where))
		}
	}
	if c.Type != "azure-entra" && c.Type != "entra-user" && c.Type != "google-workspace-user" && c.AuthorityHost != "" {
		errs = append(errs, fmt.Errorf("%s authority_host is only valid for azure-entra, entra-user and google-workspace-user", where))
	}
	if c.RevokeWithDenyPolicy && c.Type != "aws-iam" && c.Type != "aws-sts" {
		errs = append(errs, fmt.Errorf("%s revoke_with_deny_policy is only valid for aws-sts", where))
	}
	if c.AllowRoleChaining && c.Type != "aws-iam" && c.Type != "aws-sts" {
		errs = append(errs, fmt.Errorf("%s allow_role_chaining is only valid for aws-sts", where))
	}
	if c.AllowRoleChaining && c.RevokeWithDenyPolicy {
		errs = append(errs, fmt.Errorf("%s allow_role_chaining can't be combined with revoke_with_deny_policy: a denial on the lease's role does not reach a session chained into another role", where))
	}
	switch c.DenyQuotaFallback {
	case "":
	case "token_issue_time":
		if !c.RevokeWithDenyPolicy || (c.Type != "aws-iam" && c.Type != "aws-sts") {
			errs = append(errs, fmt.Errorf("%s deny_quota_fallback is only valid for aws-sts with revoke_with_deny_policy", where))
		}
	default:
		errs = append(errs, fmt.Errorf("%s deny_quota_fallback %q must be token_issue_time or empty", where, c.DenyQuotaFallback))
	}
	if c.DenyAccessKeyID != "" || c.DenySecretAccessRef != "" || c.DenySessionTokenRef != "" {
		switch {
		case !c.RevokeWithDenyPolicy || (c.Type != "aws-iam" && c.Type != "aws-sts"):
			errs = append(errs, fmt.Errorf("%s deny_access_key_id, deny_secret_access_key_ref and deny_session_token_ref are only valid for aws-sts with revoke_with_deny_policy", where))
		case strings.TrimSpace(c.DenyAccessKeyID) == "" || strings.TrimSpace(c.DenySecretAccessRef) == "":
			errs = append(errs, fmt.Errorf("%s the denial credential needs both deny_access_key_id and deny_secret_access_key_ref", where))
		default:
			if err := validateCredentialRef(c.DenySecretAccessRef); err != nil {
				errs = append(errs, fmt.Errorf("%s deny_secret_access_key_ref: %w", where, err))
			}
			if c.DenySessionTokenRef != "" {
				if err := validateCredentialRef(c.DenySessionTokenRef); err != nil {
					errs = append(errs, fmt.Errorf("%s deny_session_token_ref: %w", where, err))
				}
			}
		}
	}
	if c.IAMEndpoint != "" {
		if c.Type != "aws-iam" && c.Type != "aws-sts" && c.Type != "gcp-iam" {
			errs = append(errs, fmt.Errorf("%s iam_endpoint is only valid for aws-iam, aws-sts and gcp-iam", where))
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
	if t, hosted := synctarget.Lookup(c.Type); hosted {
		return validateHostedSyncTarget(where, t, c)
	}
	var errs []error
	if strings.TrimSpace(c.Binding) != "" || strings.TrimSpace(c.Username) != "" {
		errs = append(errs, fmt.Errorf("%s binding and username are for hosted targets (%s), not %s", where, strings.Join(synctarget.Types(), ", "), c.Type))
	}
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
		ref(c.SigningKeyRef, "signing_key_ref", true)
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

// validateHostedSyncTarget checks a hosted target (A241): its binding in the
// type's grammar, its token reference, a username where the type takes one,
// and an endpoint for a self-hosted type.
func validateHostedSyncTarget(where string, t synctarget.Target, c SecretSyncTargetConfig) []error {
	var errs []error
	if _, err := synctarget.ParseBinding(c.Type, c.Binding); err != nil {
		errs = append(errs, fmt.Errorf("%s %w", where, err))
	}
	if err := validateCredentialRef(c.TokenRef); err != nil {
		errs = append(errs, fmt.Errorf("%s token_ref: %w", where, err))
	}
	switch {
	case t.Credential == synctarget.UserAndToken && strings.TrimSpace(c.Username) == "":
		errs = append(errs, fmt.Errorf("%s username is required for %s", where, c.Type))
	case t.Credential != synctarget.UserAndToken && strings.TrimSpace(c.Username) != "":
		errs = append(errs, fmt.Errorf("%s username is not used by %s", where, c.Type))
	}
	if t.Endpoint == "" && strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s %s has no fixed API base: endpoint is required (the instance, account, workspace or regional URL)", where, c.Type))
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
	if len(c.RoleAccess) > 0 && c.Type != "postgresql" && c.Type != "mysql" && c.Type != "mongodb" {
		errs = append(errs, fmt.Errorf("%s role_access is only valid for mongodb, mysql and postgresql", where))
	}
	if len(c.SSHRoles) > 0 && c.Type != "ssh-certificate" {
		errs = append(errs, fmt.Errorf("%s ssh_roles is only valid for ssh-certificate", where))
	}
	if len(c.RedisACLRoles) > 0 && c.Type != "redis" && c.Type != "aws-elasticache" && c.Type != "aws-memorydb" {
		errs = append(errs, fmt.Errorf("%s redis_acl_roles is only valid for redis, aws-elasticache and aws-memorydb", where))
	}
	if c.Type != "aws-elasticache" && c.Type != "aws-memorydb" && c.UserGroup != "" {
		errs = append(errs, fmt.Errorf("%s user_group is only valid for aws-elasticache and aws-memorydb", where))
	}
	if c.Type != "aws-elasticache" && c.Engine != "" {
		errs = append(errs, fmt.Errorf("%s engine is only valid for aws-elasticache", where))
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
	errs = append(errs, validateADReconcile(where, c)...)
	if c.StartTLS && c.Type != "ldap" {
		errs = append(errs, fmt.Errorf("%s start_tls is only valid for ldap", where))
	}
	if c.Type != "ldap" && (c.BindDN != "" || c.UsersDN != "" || c.DirectoryMode != "" || len(c.ADLogonNames) != 0) {
		errs = append(errs, fmt.Errorf("%s bind_dn, users_dn and directory_mode are only valid for ldap", where))
	}
	if c.Type != "totp" && (c.SeedRef != "" || c.Digits != 0 || c.Period != "" || c.Algorithm != "") {
		errs = append(errs, fmt.Errorf("%s seed_ref, digits, period and algorithm are only valid for totp", where))
	}
	if c.Type != "oauth-client-credentials" && c.RevocationEndpoint != "" {
		errs = append(errs, fmt.Errorf("%s revocation_endpoint is only valid for oauth-client-credentials", where))
	}
	if !clientSecretProviderTypes[c.Type] && c.ClientSecretRef != "" {
		errs = append(errs, fmt.Errorf("%s client_secret_ref is only valid for %s", where, strings.Join(sortedTrueKeys(clientSecretProviderTypes), ", ")))
	}
	if !clientIDProviderTypes[c.Type] && c.ClientID != "" {
		errs = append(errs, fmt.Errorf("%s client_id is only valid for %s", where, strings.Join(sortedTrueKeys(clientIDProviderTypes), ", ")))
	}
	if !apiKeyProviderTypes[c.Type] && c.APIKeyRef != "" {
		errs = append(errs, fmt.Errorf("%s api_key_ref is only valid for %s", where, strings.Join(sortedTrueKeys(apiKeyProviderTypes), ", ")))
	}
	if c.Type != "datadog" && c.ApplicationKeyRef != "" {
		errs = append(errs, fmt.Errorf("%s application_key_ref is only valid for datadog", where))
	}
	if c.Type != "github-app" && c.InstallationID != "" {
		errs = append(errs, fmt.Errorf("%s installation_id is only valid for github-app", where))
	}
	if c.Type != "github-app" && c.Type != "snowflake" && c.Type != "unix" && c.Type != "windows" && c.Type != "vcenter-sso" && c.Type != "google-workspace-user" && c.PrivateKeyRef != "" {
		errs = append(errs, fmt.Errorf("%s private_key_ref is only valid for github-app, snowflake, unix, windows, vcenter-sso and google-workspace-user", where))
	}
	if c.Type != "vcenter-sso" && c.SSOAdmin != "" {
		errs = append(errs, fmt.Errorf("%s sso_admin is only valid for vcenter-sso", where))
	}
	if c.Type != "okta-user" && c.Type != "entra-user" && c.Type != "google-workspace-user" && (len(c.TOTPProviders) != 0 || len(c.HardwareKeyHolders) != 0) {
		errs = append(errs, fmt.Errorf("%s totp_providers and hardware_key_holders are only valid for okta-user, entra-user and google-workspace-user", where))
	}
	if c.Type != "unix" && c.Type != "windows" && c.Type != "vcenter-sso" && !networkDeviceProviderTypes[c.Type] && !networkAPIDeviceTypes[c.Type] && c.HostKeyFingerprint != "" {
		errs = append(errs, fmt.Errorf("%s host_key_fingerprint is only valid for unix, windows and network devices", where))
	}
	if c.Type != "unix" && c.Sudo {
		errs = append(errs, fmt.Errorf("%s sudo is only valid for unix", where))
	}
	if c.Type != "snowflake" && c.Account != "" {
		errs = append(errs, fmt.Errorf("%s account is only valid for snowflake", where))
	}
	if c.Type != "tailscale" && c.Tailnet != "" {
		errs = append(errs, fmt.Errorf("%s tailnet is only valid for tailscale", where))
	}
	if !adminUserProviderTypes[c.Type] && c.AdminUser != "" {
		errs = append(errs, fmt.Errorf("%s admin_user is only valid for %s", where, strings.Join(sortedTrueKeys(adminUserProviderTypes), ", ")))
	}
	return errs
}

var (
	elasticsearchPrivilege = regexp.MustCompile(`^[a-z_]{1,64}$`)
	elasticsearchPattern   = regexp.MustCompile(`^[A-Za-z0-9._*-]{1,255}$`)
)

// validateElasticsearchProvider checks an Elasticsearch provider (A239):
// endpoint is the cluster's HTTPS URL, admin_user and password_ref the user
// that creates and invalidates API keys, and each allowed role is bound to
// "<index privileges> on <index patterns>", for example "read on logs-*".
func validateElasticsearchProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint is required for elasticsearch", where))
	}
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for elasticsearch", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		if err := validElasticsearchIndexGrant(c.RoleBindings[role]); err != nil {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

func validElasticsearchIndexGrant(binding string) error {
	privileges, names, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	if !ok {
		return errors.New(`must be "<index privileges> on <index patterns>", for example "read on logs-*"`)
	}
	for _, p := range strings.Split(privileges, ",") {
		if !elasticsearchPrivilege.MatchString(strings.TrimSpace(p)) {
			return fmt.Errorf("index privilege %q is not a privilege name", strings.TrimSpace(p))
		}
	}
	for _, n := range strings.Split(names, ",") {
		if !elasticsearchPattern.MatchString(strings.TrimSpace(n)) {
			return fmt.Errorf("index pattern %q is not an index name or pattern", strings.TrimSpace(n))
		}
	}
	return nil
}

var (
	rabbitmqPermission = regexp.MustCompile(`^(configure|write|read)$`)
	rabbitmqResource   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
	rabbitmqVHost      = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
)

// validateRabbitMQProvider checks a RabbitMQ provider (A239): endpoint is the
// management API's HTTPS URL, admin_user and password_ref an administrator that
// creates and deletes users, and each allowed role is bound to
// "<permissions> on <resources> in <vhost>", for example "read on orders in /".
func validateRabbitMQProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the management API) is required for rabbitmq", where))
	}
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for rabbitmq", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		if err := validRabbitMQGrant(c.RoleBindings[role]); err != nil {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

func validRabbitMQGrant(binding string) error {
	perms, rest, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	names, vhost, ok2 := strings.Cut(rest, " in ")
	if !ok || !ok2 {
		return errors.New(`must be "<permissions> on <resources> in <vhost>", for example "read on orders in /"`)
	}
	if !rabbitmqVHost.MatchString(strings.TrimSpace(vhost)) {
		return fmt.Errorf("virtual host %q is not a plain name", strings.TrimSpace(vhost))
	}
	for _, p := range strings.Split(perms, ",") {
		if !rabbitmqPermission.MatchString(strings.TrimSpace(p)) {
			return fmt.Errorf("permission %q is not configure, write or read", strings.TrimSpace(p))
		}
	}
	for _, n := range strings.Split(names, ",") {
		if !rabbitmqResource.MatchString(strings.TrimSpace(n)) {
			return fmt.Errorf("resource %q is not a literal queue or exchange name", strings.TrimSpace(n))
		}
	}
	return nil
}

var apiConnectSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

var auth0ClientID = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)

// validateAuth0Provider checks an Auth0 client-secret rotator (A240): endpoint
// is the tenant domain, client_id and client_secret_ref a machine-to-machine
// application with the Management API's update:client_keys scope, and each
// allowed role is bound to the application client ID it rotates. It rotates
// only (allow_static_rotation); it issues no leases.
func validateAuth0Provider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the tenant domain) is required for auth0", where))
	}
	if !auth0ClientID.MatchString(c.ClientID) {
		errs = append(errs, fmt.Errorf("%s client_id must be the management application's client ID for auth0", where))
	}
	if err := validateCredentialRef(c.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s client_secret_ref: %w", where, err))
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s auth0 rotates an application's client secret and issues no leases: set allow_static_rotation", where))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" && !auth0ClientID.MatchString(binding) {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be the Auth0 application client ID it rotates", where, role))
		}
	}
	return errs
}

// validateDatadogProvider checks a Datadog key provider (A240): endpoint is
// the site's API, api_key_ref and application_key_ref the administrator's
// keys, and each allowed role is bound to "api_key" or to "application_key
// <service-account-id> <scope>,<scope>" (an application key of that service
// account, restricted to those scopes).
func validateDatadogProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the site's API, https://api.datadoghq.com or another site) is required for datadog", where))
	}
	for name, ref := range map[string]string{"api_key_ref": c.APIKeyRef, "application_key_ref": c.ApplicationKeyRef} {
		if err := validateCredentialRef(ref); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" {
			if err := validateDatadogBinding(binding); err != nil {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
			}
		}
	}
	return errs
}

var (
	datadogServiceAccountID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	datadogScopeName        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
)

// validateDatadogBinding is dynsecret.ParseDatadogBinding's grammar; config
// stays free of the provider packages.
func validateDatadogBinding(binding string) error {
	fields := strings.Fields(binding)
	switch {
	case len(fields) == 1 && fields[0] == "api_key":
		return nil
	case len(fields) == 3 && fields[0] == "application_key":
		if !datadogServiceAccountID.MatchString(fields[1]) {
			return fmt.Errorf("%q is not a service account ID", fields[1])
		}
		for _, scope := range strings.Split(fields[2], ",") {
			if !datadogScopeName.MatchString(scope) {
				return fmt.Errorf("%q is not an authorization scope", scope)
			}
		}
		return nil
	default:
		return errors.New(`must be "api_key" or "application_key <service-account-id> <scope>,<scope>"`)
	}
}

var openAIProjectID = regexp.MustCompile(`^proj_[A-Za-z0-9]{1,64}$`)

// mongoUserName is a MongoDB database user a two-user role alternates between
// (A240): letters, digits and . _ - only.
var mongoUserName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// unixAccountName is crypto.ValidSSHAccountName's grammar; config stays free
// of the crypto boundary.
var unixAccountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validateUnixProvider checks a local-account rotator (A240): addr is the
// host's SSH endpoint, admin_user and private_key_ref an administrator that
// may run chpasswd (through sudo -n when sudo is set), host_key_fingerprint
// pins the host key, and each allowed role names its account in
// role_bindings, or two in rotation_accounts. It rotates only.
func validateUnixProvider(where string, c DynamicSecretProviderConfig) []error {
	if c.WindowsHostAgentID != "" {
		return validateNativeWindowsProvider(where, c)
	}
	var errs []error
	if host, port, err := net.SplitHostPort(strings.TrimSpace(c.Addr)); err != nil || host == "" || port == "" {
		errs = append(errs, fmt.Errorf("%s addr must be the host's SSH host:port for %s", where, c.Type))
	}
	switch {
	case c.Type == "windows" && !unixAccountName.MatchString(c.AdminUser):
		errs = append(errs, fmt.Errorf("%s admin_user must be a local account in Administrators for windows", where))
	case !unixAccountName.MatchString(c.AdminUser):
		errs = append(errs, fmt.Errorf("%s admin_user must be a local account allowed to run chpasswd for unix", where))
	}
	if err := validateCredentialRef(c.PrivateKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s private_key_ref: %w", where, err))
	}
	if !strings.HasPrefix(c.HostKeyFingerprint, "SHA256:") || len(c.HostKeyFingerprint) < 20 {
		errs = append(errs, fmt.Errorf("%s host_key_fingerprint must pin the host key (SHA256:...) for %s", where, c.Type))
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s %s rotates local account passwords and issues no leases: set allow_static_rotation", where, c.Type))
	}
	if c.Type == "windows" {
		// A Windows local account name has at most 20 characters.
		for role, account := range c.RoleBindings {
			if len(strings.TrimSpace(account)) > 20 {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] names a Windows account longer than 20 characters", where, role))
			}
		}
		for role, accounts := range c.RotationAccounts {
			for _, account := range accounts {
				if len(account) > 20 {
					errs = append(errs, fmt.Errorf("%s rotation_accounts[%q] names a Windows account longer than 20 characters", where, role))
				}
			}
		}
	}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if _, paired := c.RotationAccounts[role]; paired {
			continue
		}
		if account := strings.TrimSpace(c.RoleBindings[role]); !unixAccountName.MatchString(account) {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name the local account it rotates, or rotation_accounts two", where, role))
		}
	}
	return errs
}

// validateOpenAIProvider checks an OpenAI service-account key provider
// (A240): endpoint is the API, api_key_ref an organization admin key, and each
// allowed role is bound to the project its service accounts are created in.
func validateOpenAIProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the API, https://api.openai.com) is required for openai", where))
	}
	if err := validateCredentialRef(c.APIKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s api_key_ref: %w", where, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" && !openAIProjectID.MatchString(binding) {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be the project ID (proj_...) its service accounts are created in", where, role))
		}
	}
	return errs
}

// validateHostedKeyProvider checks a hosted API key provider (A240): endpoint
// is the vendor's API, api_key_ref the administrator's key or token, and each
// allowed role is bound in the grammar internal/hostedkey gives the vendor.
func validateHostedKeyProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	spec := hostedkey.Providers[c.Type]
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (%s) is required for %s", where, spec.Endpoint, c.Type))
	}
	if err := validateCredentialRef(c.APIKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s api_key_ref (%s): %w", where, spec.AdminKey, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" {
			if _, err := hostedkey.ParseBinding(c.Type, binding); err != nil {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
			}
		}
	}
	return errs
}

// validateClientSecretProvider checks a client secret rotator (A240): it
// rotates only, so allow_static_rotation is required; endpoint is the vendor's
// API; Okta authenticates with an API token (api_key_ref) and Databricks as an
// account admin service principal (client_id and client_secret_ref); each
// allowed role is bound to the client whose secret rotates.
func validateClientSecretProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	spec := hostedkey.Providers[c.Type]
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (%s) is required for %s", where, spec.Endpoint, c.Type))
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s %s rotates client secrets and issues no leases: set allow_static_rotation", where, c.Type))
	}
	switch c.Type {
	case "okta":
		if err := validateCredentialRef(c.APIKeyRef); err != nil {
			errs = append(errs, fmt.Errorf("%s api_key_ref (%s): %w", where, spec.AdminKey, err))
		}
	case "databricks":
		if strings.TrimSpace(c.ClientID) == "" {
			errs = append(errs, fmt.Errorf("%s client_id (the admin service principal's application ID) is required for databricks", where))
		}
		if err := validateCredentialRef(c.ClientSecretRef); err != nil {
			errs = append(errs, fmt.Errorf("%s client_secret_ref (%s): %w", where, spec.AdminKey, err))
		}
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" {
			if _, err := hostedkey.ParseBinding(c.Type, binding); err != nil {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
			}
		}
	}
	return errs
}

// validateAPIConnectProvider checks an IBM API Connect provider (A239):
// endpoint is the platform API, client_id, client_secret_ref and api_key_ref
// the administrator's api_key grant, and each allowed role is bound to the
// consumer app "<org>/<catalog>/<consumer-org>/<app>" whose credentials leases
// are.
func validateAPIConnectProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the platform API) is required for ibm-api-connect", where))
	}
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, fmt.Errorf("%s client_id is required for ibm-api-connect", where))
	}
	for name, ref := range map[string]string{"client_secret_ref": c.ClientSecretRef, "api_key_ref": c.APIKeyRef} {
		if err := validateCredentialRef(ref); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		parts := strings.Split(binding, "/")
		valid := len(parts) == 4
		for _, part := range parts {
			valid = valid && apiConnectSegment.MatchString(part)
		}
		if !valid {
			errs = append(errs, fmt.Errorf(`%s role_bindings[%q] must be "<org>/<catalog>/<consumer-org>/<app>"`, where, role))
		}
	}
	return errs
}

var awsCacheGroupName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,39}$`)

// validateAWSCacheProvider checks an ElastiCache (aws-elasticache) or MemoryDB
// (aws-memorydb) provider (A239): region and the AWS access key
// (access_key_id, secret_access_key_ref, optional session_token_ref) of a
// principal allowed to manage RBAC users and the group, user_group the
// ElastiCache user group or MemoryDB ACL, and each allowed role a
// redis_acl_roles policy of literal key prefixes and explicit commands.
func validateAWSCacheProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Region) == "" || strings.TrimSpace(c.AccessKeyID) == "" {
		errs = append(errs, fmt.Errorf("%s region and access_key_id are required for %s", where, c.Type))
	}
	if err := validateCredentialRef(c.SecretAccessRef); err != nil {
		errs = append(errs, fmt.Errorf("%s secret_access_key_ref: %w", where, err))
	}
	if strings.TrimSpace(c.SessionTokenRef) != "" {
		if err := validateCredentialRef(c.SessionTokenRef); err != nil {
			errs = append(errs, fmt.Errorf("%s session_token_ref: %w", where, err))
		}
	}
	if !awsCacheGroupName.MatchString(c.UserGroup) {
		errs = append(errs, fmt.Errorf("%s user_group (the ElastiCache user group or MemoryDB ACL) is required for %s", where, c.Type))
	}
	if c.Engine != "" && c.Engine != "redis" && c.Engine != "valkey" {
		errs = append(errs, fmt.Errorf("%s engine must be redis or valkey", where))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		policy, found := c.RedisACLRoles[role]
		if !found {
			errs = append(errs, fmt.Errorf("%s redis_acl_roles[%q] is required for %s", where, role, c.Type))
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
	return errs
}

var (
	snowflakeAccountID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	snowflakeRoleName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,254}$`)
)

// validateSnowflakeProvider checks a Snowflake provider (A239): endpoint is the
// account URL, account its identifier, admin_user and private_key_ref a user
// allowed to create, alter and drop users and grant the bound roles, with its
// registered key pair, and each allowed role is bound to Snowflake roles.
func validateSnowflakeProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the account URL) is required for snowflake", where))
	}
	if !snowflakeAccountID.MatchString(c.Account) {
		errs = append(errs, fmt.Errorf("%s account (the <orgname>-<accountname> identifier) is required for snowflake", where))
	}
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for snowflake", where))
	}
	if err := validateCredentialRef(c.PrivateKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s private_key_ref: %w", where, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		// "user <NAME>": the role rotates that existing user's key pair (A240).
		if fields := strings.Fields(binding); len(fields) == 2 && fields[0] == "user" {
			if !snowflakeRoleName.MatchString(fields[1]) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a Snowflake user name", where, role, fields[1]))
			}
			if !c.AllowStaticRotation {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] rotates a user's key pair: set allow_static_rotation", where, role))
			}
			continue
		}
		for _, name := range strings.Split(binding, ",") {
			if !snowflakeRoleName.MatchString(strings.TrimSpace(name)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a Snowflake role name", where, role, strings.TrimSpace(name)))
			}
		}
	}
	return errs
}

var (
	githubPermissionGrant = regexp.MustCompile(`^[a-z][a-z_]{1,63}:(read|write|admin)$`)
	githubRepositoryName  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubInstallationID  = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// validateGitHubAppProvider checks a GitHub App provider (A239): client_id and
// private_key_ref are the app's, installation_id the installation tokens are
// minted for, max_ttl at most GitHub's one-hour token lifetime, endpoint
// optional (https://api.github.com), and each allowed role is bound to
// "<permission>:<level>[,...] on <repository>[,...]".
func validateGitHubAppProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, fmt.Errorf("%s client_id (the app's client ID) is required for github-app", where))
	}
	if err := validateCredentialRef(c.PrivateKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s private_key_ref: %w", where, err))
	}
	if !githubInstallationID.MatchString(c.InstallationID) {
		errs = append(errs, fmt.Errorf("%s installation_id must be GitHub's numeric installation ID", where))
	}
	if ttl, err := c.MaxTTLDuration(); err == nil && ttl > time.Hour {
		errs = append(errs, fmt.Errorf("%s max_ttl must be at most 1h: GitHub ends installation tokens after an hour", where))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		perms, repos, ok := strings.Cut(binding, " on ")
		if !ok {
			errs = append(errs, fmt.Errorf(`%s role_bindings[%q] must be "<permission>:<level> on <repositories>", for example "contents:read on api"`, where, role))
			continue
		}
		for _, p := range strings.Split(perms, ",") {
			if !githubPermissionGrant.MatchString(strings.TrimSpace(p)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not <permission>:read, :write or :admin", where, role, strings.TrimSpace(p)))
			}
		}
		for _, r := range strings.Split(repos, ",") {
			if !githubRepositoryName.MatchString(strings.TrimSpace(r)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a repository name", where, role, strings.TrimSpace(r)))
			}
		}
	}
	return errs
}

var (
	mssqlDatabaseName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_@#$-]{0,127}$`)
	mssqlRoleName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_@#$]{0,127}$`)
)

// validateMSSQLProvider checks a SQL Server (mssql) or Azure SQL (azure-sql,
// contained database users) provider (A239): admin_dsn_ref is a sqlserver://
// DSN of an administrator, database the database leased principals get roles
// in, and each allowed role is bound to database roles, for example
// "db_datareader".
func validateMSSQLProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if err := validateCredentialRef(c.AdminDSNRef); err != nil {
		errs = append(errs, fmt.Errorf("%s admin_dsn_ref: %w", where, err))
	}
	if !mssqlDatabaseName.MatchString(c.Database) {
		errs = append(errs, fmt.Errorf("%s database is required for %s and must be a plain database name", where, c.Type))
	}
	// A role that rotates between two existing accounts (A240) needs no
	// role_bindings: the accounts already hold its grants.
	bindings := c
	bindings.AllowedRoles = nil
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if len(c.RotationAccounts[role]) == 0 {
			bindings.AllowedRoles = append(bindings.AllowedRoles, role)
		}
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, bindings)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		for _, name := range strings.Split(binding, ",") {
			if !mssqlRoleName.MatchString(strings.TrimSpace(name)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a database role name", where, role, strings.TrimSpace(name)))
			}
		}
	}
	return errs
}

// mssqlAccountName is a login or contained user a two-user rotation alternates
// between (A240), passed to QUOTENAME.
var mssqlAccountName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

var milvusRoleName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)

// validateMilvusProvider checks a Milvus provider (A239): endpoint is the
// proxy's RESTful API, admin_user and password_ref a user allowed to manage
// users and grant roles, and each allowed role is bound to Milvus roles that
// exist with the lease's privileges, for example "orders_reader".
func validateMilvusProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the RESTful API) is required for milvus", where))
	}
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsAny(c.AdminUser, ":") || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for milvus and must not contain a colon", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		for _, name := range strings.Split(binding, ",") {
			if !milvusRoleName.MatchString(strings.TrimSpace(name)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a Milvus role name", where, role, strings.TrimSpace(name)))
			}
		}
	}
	return errs
}

var (
	couchbaseRole     = regexp.MustCompile(`^[a-z][a-z_]{1,63}$`)
	couchbaseKeyspace = regexp.MustCompile(`^[A-Za-z0-9._%-]{1,100}(:[A-Za-z0-9_%-]{1,251}){0,2}$`)
)

// validateCouchbaseProvider checks a Couchbase provider (A239): endpoint is the
// management REST API, admin_user and password_ref a user allowed to manage
// users, and each allowed role is bound to "<roles> on <buckets>", for example
// "bucket_full_access on orders".
func validateCouchbaseProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the management REST API) is required for couchbase", where))
	}
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for couchbase", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			continue
		}
		roles, keyspaces, ok := strings.Cut(binding, " on ")
		if !ok {
			errs = append(errs, fmt.Errorf(`%s role_bindings[%q] must be "<roles> on <buckets>", for example "bucket_full_access on orders"`, where, role))
			continue
		}
		for _, r := range strings.Split(roles, ",") {
			if !couchbaseRole.MatchString(strings.TrimSpace(r)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: role %q is not a Couchbase role name", where, role, strings.TrimSpace(r)))
			}
		}
		for _, k := range strings.Split(keyspaces, ",") {
			if !couchbaseKeyspace.MatchString(strings.TrimSpace(k)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: keyspace %q is not a bucket or bucket:scope:collection", where, role, strings.TrimSpace(k)))
			}
		}
	}
	return errs
}

var (
	kafkaOperation    = regexp.MustCompile(`^(read|write|describe|describe_configs|create|delete|alter|alter_configs)$`)
	kafkaResourceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,249}$`)
)

// validateKafkaProvider checks a Kafka provider (A239): addr is a bootstrap
// broker (SASL_SSL, or SASL_PLAINTEXT at a literal loopback or private IP with
// allow_plaintext), admin_user and password_ref a SCRAM-SHA-512 user that sets
// credentials and ACLs, and each allowed role is bound to its ACLs.
func validateKafkaProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for kafka", where))
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
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		if binding := strings.TrimSpace(c.RoleBindings[role]); binding != "" {
			if err := validKafkaGrant(binding); err != nil {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %w", where, role, err))
			}
		}
	}
	return errs
}

// validKafkaGrant checks "<operations> on <resources>" clauses separated by
// ";", for example "read,describe on topic:orders; read on group:orders-app";
// a name ending in * is a prefix and a bare * is refused.
func validKafkaGrant(binding string) error {
	for _, clause := range strings.Split(binding, ";") {
		ops, resources, ok := strings.Cut(strings.TrimSpace(clause), " on ")
		if !ok {
			return errors.New(`must be "<operations> on <resources>", for example "read,describe on topic:orders; read on group:orders-app"`)
		}
		for _, op := range strings.Split(ops, ",") {
			if !kafkaOperation.MatchString(strings.TrimSpace(op)) {
				return fmt.Errorf("operation %q is not read, write, describe, describe_configs, create, delete, alter or alter_configs", strings.TrimSpace(op))
			}
		}
		for _, item := range strings.Split(resources, ",") {
			kind, name, _ := strings.Cut(strings.TrimSpace(item), ":")
			if (kind != "topic" && kind != "group" && kind != "transactional_id") || !kafkaResourceName.MatchString(strings.TrimSuffix(name, "*")) {
				return fmt.Errorf("resource %q is not topic:, group: or transactional_id: and a name or name prefix", strings.TrimSpace(item))
			}
		}
	}
	return nil
}

// hanaRoleName is an SAP HANA role as HANA stores it (an unquoted name is
// stored in upper case).
var hanaRoleName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,126}$`)

// validateHANAProvider checks an SAP HANA provider (A239): admin_dsn_ref is
// the administrator's go-hdb URL, and each allowed role is bound to existing
// HANA roles.
func validateHANAProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if err := validateCredentialRef(c.AdminDSNRef); err != nil {
		errs = append(errs, fmt.Errorf("%s admin_dsn_ref: %w", where, err))
	}
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		for _, name := range strings.Split(c.RoleBindings[role], ",") {
			if name = strings.TrimSpace(name); name != "" && !hanaRoleName.MatchString(name) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a HANA role name", where, role, name))
			}
		}
	}
	return errs
}

// oracleIdentifier is an Oracle user or role name as Oracle stores it (an
// unquoted name is stored in upper case).
var oracleIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#]{0,127}$`)

// validateOracleProvider checks an Oracle Database provider (A239, A240):
// admin_dsn_ref is the administrator's go-ora URL, and each allowed role is
// bound to existing Oracle roles (role_bindings) or rotates between two
// existing users (rotation_accounts).
func validateOracleProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if err := validateCredentialRef(c.AdminDSNRef); err != nil {
		errs = append(errs, fmt.Errorf("%s admin_dsn_ref: %w", where, err))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		binding := strings.TrimSpace(c.RoleBindings[role])
		if binding == "" {
			if len(c.RotationAccounts[role]) == 0 {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] or rotation_accounts[%q] is required for oracle", where, role, role))
			}
			continue
		}
		for _, name := range strings.Split(binding, ",") {
			if name = strings.TrimSpace(name); !oracleIdentifier.MatchString(name) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not an Oracle role name", where, role, name))
			}
		}
	}
	bound := make([]string, 0, len(c.RoleBindings))
	for role := range c.RoleBindings {
		bound = append(bound, role)
	}
	sort.Strings(bound)
	for _, role := range bound {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

// cassandraRoleName is a role a cassandra provider grants, double-quoted
// into CQL as written.
var cassandraRoleName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// validateCassandraProvider checks a Cassandra provider (A239): addr is one
// node's native-protocol port (client encryption, or plaintext at a literal
// loopback or private IP with allow_plaintext), admin_user and password_ref a
// role that creates, grants and drops login roles, and each allowed role is
// bound to existing Cassandra roles.
func validateCassandraProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.AdminUser) == "" || strings.ContainsFunc(c.AdminUser, unicode.IsControl) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for cassandra", where))
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
	errs = append(errs, validateRoleBindingsCoverRoles(where, c)...)
	for _, role := range normalizedStrings(c.AllowedRoles) {
		for _, name := range strings.Split(c.RoleBindings[role], ",") {
			if name = strings.TrimSpace(name); name != "" && !cassandraRoleName.MatchString(name) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q]: %q is not a plain Cassandra role name", where, role, name))
			}
		}
	}
	return errs
}

var (
	tailscaleTag     = regexp.MustCompile(`^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	tailscaleTailnet = regexp.MustCompile(`^(-|[A-Za-z0-9.@_-]{1,253})$`)
)

// validateTailscaleProvider checks a Tailscale provider (A239): endpoint is the
// API (https://api.tailscale.com when empty), tailnet the tailnet ("-" when
// empty), bearer_token_ref an API access token allowed to manage auth keys, and
// each allowed role is bound to the ACL tags its keys give devices.
func validateTailscaleProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if c.Tailnet != "" && !tailscaleTailnet.MatchString(c.Tailnet) {
		errs = append(errs, fmt.Errorf("%s tailnet %q is not a tailnet name", where, c.Tailnet))
	}
	if err := validateCredentialRef(c.BearerTokenRef); err != nil {
		errs = append(errs, fmt.Errorf("%s bearer_token_ref (the Tailscale API token): %w", where, err))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		tags := strings.Split(c.RoleBindings[role], ",")
		for _, tag := range tags {
			if !tailscaleTag.MatchString(strings.TrimSpace(tag)) {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] must list ACL tags (tag:name), not %q", where, role, strings.TrimSpace(tag)))
				break
			}
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

var (
	atlasGroupID  = regexp.MustCompile(`^[0-9a-f]{24}$`)
	atlasRoleName = regexp.MustCompile(`^[A-Za-z]{1,64}$`)
	atlasDatabase = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// validateMongoDBAtlasProvider checks a MongoDB Atlas provider (A239): project
// is the Atlas project (group) ID, client_id and client_secret_ref a service
// account allowed to manage database users, max_ttl at most the seven days
// Atlas's deleteAfterDate allows, and each allowed role is bound to
// "<role> on <databases>", for example "read on orders".
func validateMongoDBAtlasProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if !atlasGroupID.MatchString(c.Project) {
		errs = append(errs, fmt.Errorf("%s project (the Atlas project ID, 24 hexadecimal characters) is required for mongodb-atlas", where))
	}
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, fmt.Errorf("%s client_id (the Atlas service account) is required for mongodb-atlas", where))
	}
	if err := validateCredentialRef(c.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s client_secret_ref: %w", where, err))
	}
	if ttl, err := c.MaxTTLDuration(); err == nil && ttl > 7*24*time.Hour {
		errs = append(errs, fmt.Errorf("%s max_ttl %s exceeds the seven days Atlas deletes a user within", where, ttl))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		roleName, databases, ok := strings.Cut(strings.TrimSpace(c.RoleBindings[role]), " on ")
		valid := ok && atlasRoleName.MatchString(strings.TrimSpace(roleName))
		for _, db := range strings.Split(databases, ",") {
			valid = valid && atlasDatabase.MatchString(strings.TrimSpace(db))
		}
		if !valid {
			errs = append(errs, fmt.Errorf(`%s role_bindings[%q] must be "<role> on <databases>", for example "read on orders"`, where, role))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

// clickHouseIdentifier is a ClickHouse user or role name the provider accepts:
// one that needs no quoting.
var clickHouseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// validateClickHouseProvider checks a ClickHouse provider (A239): endpoint is
// the HTTP interface, admin_user and password_ref the administrator that
// creates and drops leased users, and each allowed role is bound to an existing
// ClickHouse role that holds its grants.
func validateClickHouseProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) == "" {
		errs = append(errs, fmt.Errorf("%s endpoint (the HTTP interface) is required for clickhouse", where))
	}
	if !clickHouseIdentifier.MatchString(c.AdminUser) {
		errs = append(errs, fmt.Errorf("%s admin_user is required for clickhouse and must be a plain ClickHouse user name", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s password_ref: %w", where, err))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		if !clickHouseIdentifier.MatchString(c.RoleBindings[role]) {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name an existing ClickHouse role", where, role))
		}
	}
	for role := range c.RoleBindings {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] has no matching allowed role", where, role))
		}
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
	if c.StartTLS && c.AllowPlaintext {
		errs = append(errs, fmt.Errorf("%s start_tls and allow_plaintext are exclusive: StartTLS never falls back to plaintext", where))
	}
	if c.StartTLS && c.DirectoryMode == "active_directory" {
		errs = append(errs, fmt.Errorf("%s active_directory uses verified LDAPS; start_tls is for generic LDAP", where))
	}
	if c.DirectoryMode != "" && c.DirectoryMode != "active_directory" {
		errs = append(errs, fmt.Errorf("%s directory_mode is empty for generic LDAP or active_directory", where))
	}
	if c.DirectoryMode == "active_directory" {
		if c.Desktop != nil {
			refs := map[string]bool{}
			for role, dn := range c.RoleBindings {
				if pair, ok := c.RotationAccounts[role]; ok {
					for _, ref := range pair {
						refs[ref] = true
					}
				} else {
					refs[dn] = true
				}
			}
			for ref := range refs {
				name := c.ADLogonNames[ref]
				identity := *c.Desktop
				identity.AccountKind = "active_directory"
				identity.Accounts = []accessdesktop.BoundAccount{{Reference: ref, Username: name}}
				if identity.Validate() != nil {
					errs = append(errs, fmt.Errorf("%s ad_logon_names needs a bare RDP logon name for every bound account", where))
				}
			}
			for ref := range c.ADLogonNames {
				if !refs[ref] {
					errs = append(errs, fmt.Errorf("%s ad_logon_names names an account outside the role bindings", where))
				}
			}
		}

		if !c.AllowStaticRotation || c.AllowPlaintext {
			errs = append(errs, fmt.Errorf("%s active_directory requires allow_static_rotation and verified LDAPS; plaintext is forbidden", where))
		}
		owners := map[string]string{}
		for role, dn := range c.RoleBindings {
			if !strings.Contains(dn, "=") || !strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(strings.TrimSpace(c.UsersDN))) {
				errs = append(errs, fmt.Errorf("%s active_directory role %q must name an existing account under users_dn", where, role))
			}
			if other, found := owners[strings.ToLower(dn)]; found && other != role {
				errs = append(errs, fmt.Errorf("%s active_directory account is bound to more than one role", where))
			}
			owners[strings.ToLower(dn)] = role
		}
	}

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
	if len(c.ADLogonNames) != 0 && (c.DirectoryMode != "active_directory" || c.Desktop == nil) {
		errs = append(errs, fmt.Errorf("%s ad_logon_names requires an active_directory desktop profile", where))
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
// postgresDecoyRole is the PostgreSQL provider role that mints decoy logins
// (dynsecret.DecoyRole, Q6); it carries its own grants.
const postgresDecoyRole = "decoy"

// validateDatabaseRoleAccess requires every role of a PostgreSQL, MySQL or
// MongoDB provider to have an access class (A239-L1): role_access read or
// readwrite, or a role named as one (readonly, reader or read; writer or
// readwrite). A class is never read from part of a name. PostgreSQL's decoy
// role and a role two rotation_accounts serve carry their own grants.
func validateDatabaseRoleAccess(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		class := strings.TrimSpace(c.RoleAccess[role])
		if class == "" && ((c.Type == "postgresql" && role == postgresDecoyRole) || len(c.RotationAccounts[role]) > 0) {
			continue
		}
		if _, ok := dbaccess.OfRole(role, class); ok {
			continue
		}
		if class != "" {
			errs = append(errs, fmt.Errorf("%s role_access[%q] must be %s or %s", where, role, dbaccess.BindingRead, dbaccess.BindingReadWrite))
		} else {
			errs = append(errs, fmt.Errorf("%s role %q needs role_access[%q] of %s or %s: a %s role is granted an explicit access class, never one read from its name",
				where, role, role, dbaccess.BindingRead, dbaccess.BindingReadWrite, c.Type))
		}
	}
	classed := make([]string, 0, len(c.RoleAccess))
	for role := range c.RoleAccess {
		classed = append(classed, role)
	}
	sort.Strings(classed)
	for _, role := range classed {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s role_access[%q] has no matching allowed role", where, role))
		}
	}
	return errs
}

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

// networkDeviceProviderTypes rotate network device accounts through the
// device's own command line (A270).
var networkDeviceProviderTypes = map[string]bool{"iosxe": true, "junos": true}

// validateNetworkDeviceProvider checks a network device (A270): the device's
// SSH address and pinned host key, the administrator that makes each change
// and its password, static rotation of one bound account per role, never the
// administrator; on IOS-XE the account "enable" is the privileged-mode secret.
func validateNetworkDeviceProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if host, port, err := net.SplitHostPort(strings.TrimSpace(c.Addr)); err != nil || host == "" || port == "" {
		errs = append(errs, fmt.Errorf("%s addr must be the device's SSH host:port for %s", where, c.Type))
	}
	if !unixAccountName.MatchString(c.AdminUser) {
		errs = append(errs, fmt.Errorf("%s admin_user must name the device account that changes passwords for %s", where, c.Type))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil || strings.TrimSpace(c.PasswordRef) == "" {
		errs = append(errs, fmt.Errorf("%s password_ref must name the administrator's password for %s", where, c.Type))
	}
	if !strings.HasPrefix(c.HostKeyFingerprint, "SHA256:") || len(c.HostKeyFingerprint) < 20 {
		errs = append(errs, fmt.Errorf("%s host_key_fingerprint must pin the device's host key (SHA256:...) for %s", where, c.Type))
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s %s rotates device account passwords and issues no leases: set allow_static_rotation", where, c.Type))
	}
	if len(c.RotationAccounts) != 0 {
		errs = append(errs, fmt.Errorf("%s %s rotates one bound account per role in place; rotation_accounts is not used", where, c.Type))
	}
	for role, account := range c.RoleBindings {
		account = strings.TrimSpace(account)
		switch {
		case account == c.AdminUser:
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the administrator that makes the change", where, role))
		case account == "enable" && c.Type != "iosxe":
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the enable secret, which only iosxe has", where, role))
		case account != "enable" && !unixAccountName.MatchString(account):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name a device account", where, role))
		}
	}
	return errs
}

var networkAPIAccountName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// validateNetworkAPIProvider checks an EOS, FortiGate or BIG-IP device (A270):
// its HTTPS management endpoint with the device's certificate (or its CA)
// pinned, the administrator that makes each change (its password, or on
// FortiGate the REST API administrator's token), and static rotation of one
// bound account per role, never the administrator; on EOS the account
// "enable" is the enable password, and BIG-IP's root is not an iControl REST
// user.
func validateNetworkAPIProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if u, err := url.Parse(strings.TrimSpace(c.Endpoint)); err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, fmt.Errorf("%s endpoint must be the device's https://host[:port] for %s", where, c.Type))
	}
	if c.AllowInsecureLoopback || c.AllowPlaintext {
		errs = append(errs, fmt.Errorf("%s %s reaches the device over HTTPS only", where, c.Type))
	}
	if err := validateCredentialRef(c.TLSCARef); err != nil || strings.TrimSpace(c.TLSCARef) == "" {
		errs = append(errs, fmt.Errorf("%s tls_ca_ref must pin the device's certificate or its CA for %s", where, c.Type))
	}
	if !networkAPIAccountName.MatchString(c.AdminUser) {
		errs = append(errs, fmt.Errorf("%s admin_user must name the device account that changes passwords for %s", where, c.Type))
	}
	if c.Type == "fortigate" {
		if err := validateCredentialRef(c.APIKeyRef); err != nil || strings.TrimSpace(c.APIKeyRef) == "" {
			errs = append(errs, fmt.Errorf("%s api_key_ref must name the REST API administrator's token for fortigate", where))
		}
		if c.PasswordRef != "" {
			errs = append(errs, fmt.Errorf("%s fortigate signs in with api_key_ref; password_ref is not used", where))
		}
	} else if err := validateCredentialRef(c.PasswordRef); err != nil || strings.TrimSpace(c.PasswordRef) == "" {
		errs = append(errs, fmt.Errorf("%s password_ref must name the administrator's password for %s", where, c.Type))
	}
	if (c.Type == "redfish" || c.Type == "esxi") && (strings.TrimSpace(c.Addr) != "" || c.HostKeyFingerprint != "") {
		errs = append(errs, fmt.Errorf("%s %s has no SSH sessions; addr and host_key_fingerprint are not used", where, c.Type))
	} else if (strings.TrimSpace(c.Addr) == "") != (c.HostKeyFingerprint == "") {
		errs = append(errs, fmt.Errorf("%s %s sessions need both addr (the device's SSH host:port) and host_key_fingerprint, or neither", where, c.Type))
	} else if c.Addr != "" {
		if host, port, err := net.SplitHostPort(strings.TrimSpace(c.Addr)); err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("%s addr must be the device's SSH host:port for %s sessions", where, c.Type))
		}
		if !strings.HasPrefix(c.HostKeyFingerprint, "SHA256:") || len(c.HostKeyFingerprint) < 20 {
			errs = append(errs, fmt.Errorf("%s host_key_fingerprint must pin the device's SSH host key (SHA256:...) for %s sessions", where, c.Type))
		}
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s %s rotates device account passwords and issues no leases: set allow_static_rotation", where, c.Type))
	}
	if len(c.RotationAccounts) != 0 {
		errs = append(errs, fmt.Errorf("%s %s rotates one bound account per role in place; rotation_accounts is not used", where, c.Type))
	}
	for role, account := range c.RoleBindings {
		account = strings.TrimSpace(account)
		switch {
		case account == c.AdminUser:
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the administrator that makes the change", where, role))
		case account == "enable" && c.Type != "eos":
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the enable password, which only eos has", where, role))
		case account == "root" && c.Type == "bigip":
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names root, which is not an iControl REST user", where, role))
		case (account == "vpxuser" || account == "dcui") && c.Type == "esxi":
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names %s, which vCenter or the console manages", where, role, account))
		case !networkAPIAccountName.MatchString(account):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name a device account", where, role))
		}
	}
	return errs
}

// networkAPIDeviceTypes reach the device's management API over HTTPS; their
// optional addr and host_key_fingerprint are the device's SSH route for
// gateway sessions (A270).
var networkAPIDeviceTypes = map[string]bool{"eos": true, "fortigate": true, "bigip": true}

var vcenterSSOAdmin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// validateVCenterSSOProvider checks a vCenter single sign-on provider
// (A271): the appliance's HTTPS endpoint with its certificate pinned (the
// REST proof), its SSH address and host key with root's key (admin_user,
// private_key_ref) for dir-cli, the SSO administrator (sso_admin,
// user@domain) and its password, and static rotation of one SSO user (no
// domain) per role, never the administrator.
func validateVCenterSSOProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if u, err := url.Parse(strings.TrimSpace(c.Endpoint)); err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, fmt.Errorf("%s endpoint must be the appliance's https://host[:port] for vcenter-sso", where))
	}
	if c.AllowInsecureLoopback || c.AllowPlaintext {
		errs = append(errs, fmt.Errorf("%s vcenter-sso reaches the appliance over HTTPS only", where))
	}
	if err := validateCredentialRef(c.TLSCARef); err != nil || strings.TrimSpace(c.TLSCARef) == "" {
		errs = append(errs, fmt.Errorf("%s tls_ca_ref must pin the appliance's certificate or its CA for vcenter-sso", where))
	}
	if host, port, err := net.SplitHostPort(strings.TrimSpace(c.Addr)); err != nil || host == "" || port == "" {
		errs = append(errs, fmt.Errorf("%s addr must be the appliance's SSH host:port for vcenter-sso", where))
	}
	if !strings.HasPrefix(c.HostKeyFingerprint, "SHA256:") || len(c.HostKeyFingerprint) < 20 {
		errs = append(errs, fmt.Errorf("%s host_key_fingerprint must pin the appliance's SSH host key for vcenter-sso", where))
	}
	if !unixAccountName.MatchString(c.AdminUser) {
		errs = append(errs, fmt.Errorf("%s admin_user must name the appliance account whose shell runs dir-cli (root) for vcenter-sso", where))
	}
	if err := validateCredentialRef(c.PrivateKeyRef); err != nil || strings.TrimSpace(c.PrivateKeyRef) == "" {
		errs = append(errs, fmt.Errorf("%s private_key_ref must name admin_user's SSH key (PKCS#8) for vcenter-sso", where))
	}
	if !vcenterSSOAdmin.MatchString(c.SSOAdmin) {
		errs = append(errs, fmt.Errorf("%s sso_admin must be the SSO administrator's user@domain for vcenter-sso", where))
	}
	if err := validateCredentialRef(c.PasswordRef); err != nil || strings.TrimSpace(c.PasswordRef) == "" {
		errs = append(errs, fmt.Errorf("%s password_ref must name the SSO administrator's password for vcenter-sso", where))
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s vcenter-sso rotates SSO user passwords and issues no leases: set allow_static_rotation", where))
	}
	if len(c.RotationAccounts) != 0 {
		errs = append(errs, fmt.Errorf("%s vcenter-sso rotates one bound user per role in place; rotation_accounts is not used", where))
	}
	admin, _, _ := strings.Cut(c.SSOAdmin, "@")
	for role, account := range c.RoleBindings {
		account = strings.TrimSpace(account)
		switch {
		case strings.EqualFold(account, admin):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the SSO administrator that makes the change", where, role))
		case !networkAPIAccountName.MatchString(account):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name an SSO user, without its domain", where, role))
		}
	}
	return errs
}

var idpAdminAccount = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// validateIdPAdminProvider checks an identity provider administrator
// provider (A272): okta-user (endpoint, api_key_ref), entra-user (endpoint,
// authority_host, azure_tenant_id, client_id, client_secret_ref) or
// google-workspace-user (endpoint, authority_host, service_account,
// private_key_ref, admin_user as the impersonated super administrator), with
// static rotation of one account (user@domain) per role.
func validateIdPAdminProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	endpoint := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for %s", where, name, c.Type))
		} else if err := validateSecretIntegrationEndpoint(value, c.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", where, name, err))
		}
	}
	ref := func(name, value string) {
		if err := validateCredentialRef(value); err != nil || strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %s is required for %s", where, name, c.Type))
		}
	}
	endpoint("endpoint", c.Endpoint)
	switch c.Type {
	case "okta-user":
		ref("api_key_ref", c.APIKeyRef)
	case "entra-user":
		endpoint("authority_host", c.AuthorityHost)
		if strings.TrimSpace(c.AzureTenant) == "" || strings.TrimSpace(c.ClientID) == "" {
			errs = append(errs, fmt.Errorf("%s azure_tenant_id and client_id are required for entra-user", where))
		}
		ref("client_secret_ref", c.ClientSecretRef)
	case "google-workspace-user":
		endpoint("authority_host", c.AuthorityHost)
		if !idpAdminAccount.MatchString(c.ServiceAccount) || !idpAdminAccount.MatchString(c.AdminUser) {
			errs = append(errs, fmt.Errorf("%s service_account and admin_user (the super administrator it impersonates) are required for google-workspace-user", where))
		}
		ref("private_key_ref", c.PrivateKeyRef)
	}
	if !c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s %s rotates administrator passwords and issues no leases: set allow_static_rotation", where, c.Type))
	}
	if len(c.RotationAccounts) != 0 {
		errs = append(errs, fmt.Errorf("%s %s rotates one bound account per role in place; rotation_accounts is not used", where, c.Type))
	}
	for role, provider := range c.TOTPProviders {
		if _, bound := c.RoleBindings[role]; !bound || strings.TrimSpace(provider) == "" {
			errs = append(errs, fmt.Errorf("%s totp_providers[%q] must name a totp provider for a bound role", where, role))
		}
	}
	for role, holders := range c.HardwareKeyHolders {
		if _, bound := c.RoleBindings[role]; !bound || len(holders) == 0 || len(holders) > 10 {
			errs = append(errs, fmt.Errorf("%s hardware_key_holders[%q] must list 1-10 holders for a bound role", where, role))
		}
		for _, holder := range holders {
			if strings.TrimSpace(holder) == "" || len(holder) > 200 || strings.ContainsAny(holder, "\r\n\x00") {
				errs = append(errs, fmt.Errorf("%s hardware_key_holders[%q] has a holder that is not one line of 1-200 characters", where, role))
			}
		}
	}
	for role, account := range c.RoleBindings {
		account = strings.TrimSpace(account)
		switch {
		case !idpAdminAccount.MatchString(account):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] must name an account as user@domain", where, role))
		case strings.EqualFold(account, c.AdminUser):
			errs = append(errs, fmt.Errorf("%s role_bindings[%q] names the administrator the provider acts as", where, role))
		}
	}
	return errs
}

// validateBreakGlassTOTP checks that every identity provider administrator
// role's totp_providers entry names a totp provider in the same tenant that
// allows the same role, whose seed an emergency release turns into a code
// (A272).
func validateBreakGlassTOTP(providers []DynamicSecretProviderConfig) []error {
	totp := map[string]DynamicSecretProviderConfig{}
	for _, p := range providers {
		if strings.TrimSpace(p.Type) == "totp" {
			totp[strings.TrimSpace(p.TenantID)+"\x00"+strings.TrimSpace(p.ID)] = p
		}
	}
	var errs []error
	for i, p := range providers {
		for role, id := range p.TOTPProviders {
			target, ok := totp[strings.TrimSpace(p.TenantID)+"\x00"+strings.TrimSpace(id)]
			if !ok || !slices.Contains(normalizedStrings(target.AllowedRoles), role) {
				errs = append(errs, fmt.Errorf("secret_integrations.dynamic_providers[%d] totp_providers[%q] must name a totp provider in the same tenant that allows role %q", i, role, role))
			}
		}
	}
	return errs
}

// validateSSHCertificateProvider checks an ssh-certificate provider (A239-L11):
// it signs with the control plane's own SSH CA, so it takes no endpoint and
// no credential, and every allowed role names the certificate its leases
// carry. User principals must also be listed in protocols.ssh_user_principals,
// which bounds every user certificate the CA signs; issuance refuses one that
// isn't.
func validateSSHCertificateProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if strings.TrimSpace(c.Endpoint) != "" || c.AllowStaticRotation {
		errs = append(errs, fmt.Errorf("%s ssh-certificate signs with the control plane's SSH CA: it takes no endpoint and no static rotation", where))
	}
	allowed := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		allowed[role] = true
		r, ok := c.SSHRoles[role]
		if !ok {
			errs = append(errs, fmt.Errorf("%s role %q needs ssh_roles[%q]: the principals its certificates carry", where, role, role))
			continue
		}
		switch strings.TrimSpace(r.CertificateType) {
		case "", "user", "host":
		default:
			errs = append(errs, fmt.Errorf("%s ssh_roles[%q].certificate_type must be user or host", where, role))
		}
		if len(normalizedStrings(r.Principals)) == 0 {
			errs = append(errs, fmt.Errorf("%s ssh_roles[%q].principals must name at least one principal", where, role))
		}
		for _, principal := range r.Principals {
			if strings.TrimSpace(principal) == "" || strings.ContainsAny(principal, ", \t\r\n") {
				errs = append(errs, fmt.Errorf("%s ssh_roles[%q] principal %q must be one name with no spaces or commas", where, role, principal))
			}
		}
	}
	for role := range c.SSHRoles {
		if !allowed[role] {
			errs = append(errs, fmt.Errorf("%s ssh_roles[%q] is not an allowed role", where, role))
		}
	}
	return errs
}
