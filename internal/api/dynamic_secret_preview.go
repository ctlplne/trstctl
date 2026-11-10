// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
)

const dynamicSecretReviewDomain = "trstctl.api.f65-dynamic-secret-review.v1" // #nosec G101 -- public MAC domain, not a credential

type dynamicSecretProviderRequirement struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Kind        string `json:"kind"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type dynamicSecretSupportedProvider struct {
	Type    string `json:"type"`
	Label   string `json:"label"`
	Purpose string `json:"purpose"`
	// Authority is what a leased credential may do; Revocation is "confirmed"
	// when the provider deletes or denies the credential before its expiry and
	// "ttl_only" when it lapses only at its native expiry (A239).
	Authority    string                             `json:"authority"`
	Revocation   string                             `json:"revocation"`
	Requirements []dynamicSecretProviderRequirement `json:"requirements"`
}

type dynamicSecretConfiguredProvider struct {
	ID                    string   `json:"id"`
	Type                  string   `json:"type"`
	Label                 string   `json:"label"`
	AllowedRoles          []string `json:"allowed_roles"`
	MaximumTTLSeconds     int64    `json:"maximum_ttl_seconds"`
	Ready                 bool     `json:"ready"`
	ConfigurationRevision string   `json:"configuration_revision"`
	// Revocation is the type's catalog value, or what this provider's
	// configuration makes it (an OAuth provider without a revocation endpoint
	// is ttl_only, A239; an AWS STS provider with revoke_with_deny_policy is
	// deny_policy, N3).
	Revocation string `json:"revocation,omitempty"`
}

type dynamicSecretProviderCatalogResponse struct {
	Capability                  string                            `json:"capability"`
	ConfigurationMode           string                            `json:"configuration_mode"`
	ConfigurationChangesRestart bool                              `json:"configuration_changes_require_restart"`
	SecretDelivery              string                            `json:"secret_delivery"`
	SupportedProviders          []dynamicSecretSupportedProvider  `json:"supported_providers"`
	ConfiguredProviders         []dynamicSecretConfiguredProvider `json:"configured_providers"`
	Blockers                    []string                          `json:"blockers"`
	DocumentationPath           string                            `json:"documentation_path"`
	DataHandling                string                            `json:"secret_data_handling"`
}

type dynamicLeasePreviewResponse struct {
	Capability             string   `json:"capability"`
	Operation              string   `json:"operation"`
	Ready                  bool     `json:"ready"`
	EffectFree             bool     `json:"effect_free"`
	ProviderID             string   `json:"provider_id"`
	ProviderType           string   `json:"provider_type"`
	ProviderLabel          string   `json:"provider_label"`
	Role                   string   `json:"role"`
	RequestedTTLSeconds    int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds    int64    `json:"effective_ttl_seconds"`
	MaximumTTLSeconds      int64    `json:"maximum_ttl_seconds"`
	ConfigurationRevision  string   `json:"configuration_revision"`
	RequiredPermission     string   `json:"required_permission"`
	RequestFingerprint     string   `json:"request_fingerprint"`
	Blockers               []string `json:"blockers"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	ExecuteWrites          []string `json:"execute_writes"`
	ExecuteExternalEffects []string `json:"execute_external_effects"`
	RecoverySteps          []string `json:"recovery_steps"`
	VerificationSteps      []string `json:"verification_steps"`
	CLIArgv                []string `json:"cli_argv"`
	DataHandling           string   `json:"secret_data_handling"`
}

type dynamicSecretProviderReviewIdentity interface {
	DynamicSecretProviderType() string
	DynamicSecretAllowedRoles() []string
	DynamicSecretConfigurationRevision() string
}

type dynamicSecretMaximumTTL interface {
	MaximumTTL() time.Duration
}

func dynamicSecretRequirement(key, label, kind, description string, required bool) dynamicSecretProviderRequirement {
	return dynamicSecretProviderRequirement{Key: key, Label: label, Kind: kind, Required: required, Description: description}
}

func dynamicSecretCommonRequirements() []dynamicSecretProviderRequirement {
	return []dynamicSecretProviderRequirement{
		dynamicSecretRequirement("tenant_id", "Tenant ID", "tenant", "Tenant that exclusively owns this provider attachment.", true),
		dynamicSecretRequirement("id", "Provider ID", "identifier", "Stable name operators and automation use when requesting a lease.", true),
		dynamicSecretRequirement("allowed_roles", "Allowed roles", "role_allowlist", "One or more operator-selectable roles; undeclared roles fail before provider contact.", true),
		dynamicSecretRequirement("max_ttl", "Maximum TTL", "duration", "Original renewal ceiling for leases issued by this attachment. Expiry queues provider revocation; completion is tracked separately. Defaults to 24h.", false),
		dynamicSecretRequirement("username_prefix", "Username prefix", "value", "Optional prefix for generated backend identities.", false),
		dynamicSecretRequirement("allow_private_endpoint", "Private endpoint opt-in", "network_policy", "Must be explicit before private-network egress is allowed.", false),
		dynamicSecretRequirement("private_egress_cidrs", "Private egress CIDRs", "network_policy", "Narrow allowlist used only with the private-endpoint opt-in.", false),
	}
}

func dynamicSecretProviderRequirements(specific ...dynamicSecretProviderRequirement) []dynamicSecretProviderRequirement {
	return append(dynamicSecretCommonRequirements(), specific...)
}

func dynamicSecretAWSRequirements(specific ...dynamicSecretProviderRequirement) []dynamicSecretProviderRequirement {
	common := dynamicSecretCommonRequirements()
	for i := range common {
		if common[i].Key == "max_ttl" {
			common[i].Required = true
			common[i].Description = "Explicit AWS STS ceiling from 15m to 12h. The target role may enforce a smaller maximum; each issued session expires natively."
		}
	}
	return append(common, specific...)
}

func dynamicSecretSupportedProviders() []dynamicSecretSupportedProvider {
	credential := func(key, label, description string, required bool) dynamicSecretProviderRequirement {
		return dynamicSecretRequirement(key, label, "credential_reference", description+" Use a mode-0600 file: ref or tenant-scoped secret:// ref; never inline the value.", required)
	}
	value := func(key, label, description string, required bool) dynamicSecretProviderRequirement {
		return dynamicSecretRequirement(key, label, "value", description, required)
	}
	roles := func(description string) dynamicSecretProviderRequirement {
		return dynamicSecretRequirement("role_bindings", "Role bindings", "role_binding", description, true)
	}
	// A239-L1: a database lease's access class is explicit.
	roleAccess := value("role_access", "Role access", "Per allowed role, read or readwrite: the access class its leases are granted. A role named readonly, reader or read (or writer or readwrite) needs none; startup refuses any other role without one, because a class is never read from a role's name.", false)
	// N3: the AWS STS issuer's opt-in to end a revoked session early.
	awsDenyPolicy := value("revoke_with_deny_policy", "Deny revoked sessions",
		"Optional. Revoking a lease writes an inline policy on the role that denies that one session (aws:userid) until it expires, read back before the revocation counts; the caller then also needs iam:PutRolePolicy, iam:GetRolePolicy, iam:ListRolePolicies and iam:DeleteRolePolicy on the bound roles. Without it a revoked session lapses at its expiry.", false)
	// N3-L3: a lease's session can't chain into another role unless allowed.
	awsRoleChaining := value("allow_role_chaining", "Allow role chaining",
		"Optional. A lease's session may assume other roles. Without it each lease is issued with a session policy that denies sts:AssumeRole, so no session chained from it outlives its revocation. With it a revocation stays pending an hour past the session's expiry, the longest a chained session runs, and revoke_with_deny_policy can't be set.", false)
	awsGateway := value("gateway", "Gateway API binding", "Optional gateway-only account attachment: endpoint is a fixed HTTPS origin; service is s3 or sts; region is explicit. API callers get a gateway ticket, not STS key material. LocalStack wire and authorization stand-in are separate qualifications.", false)
	awsConsole := value("console", "Native console handoff binding", "Optional aws-sts attachment with fixed federation_endpoint and destination on supported AWS commercial HTTPS hosts. The browser receives a native sign-in form, never STS keys. Strict federation/login stand-in and LocalStack STS only. Recording attests the handoff, not native console actions; require_recording templates refuse this type. Native cookies/access keys and logout are unverified.", false)
	desktop := value("desktop", "Reviewed desktop gateway binding", "Optional static-account attachment for unix, windows or ldap: fixed RDP address, certificate_sha256, domain, width/height and explicit tls_only for xrdp. Requires a Linux gateway with the native helper, encrypted recordings and audit signing. xrdp stock-viewer/PNG replay stand-in proof; native Windows/AD sign-in unverified. Images can contain on-screen secrets; pixel redaction is not automatic.", false)
	providers := []dynamicSecretSupportedProvider{
		{Type: "postgresql", Label: "PostgreSQL", Purpose: "Creates and drops a scoped PostgreSQL login role.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin DSN reference", "Credential reference containing the least-privilege administrative DSN.", true),
			value("database", "Database", "Optional database placed in the generated connection result.", false),
			value("schema", "Schema", "Optional schema granted to the generated role.", false),
			roleAccess,
		)},
		{Type: "mysql", Label: "MySQL / MariaDB", Purpose: "Creates and drops a scoped MySQL account.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin DSN reference", "Credential reference containing the least-privilege administrative DSN.", true),
			value("addr", "Client address", "Host and port applications use for the generated account.", true),
			value("database", "Database", "Database granted to the generated account.", true),
			value("account_host", "Account host", "Required MySQL client host or network matcher; never defaults to %.", true),
			value("allow_wildcard_account_host", "Wildcard account host opt-in", "Required to use % or _ in account_host; review the matched client range before enabling.", false),
			roleAccess,
		)},
		{Type: "mongodb", Label: "MongoDB", Purpose: "Creates and drops a scoped MongoDB database user.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin URI reference", "Credential reference containing the least-privilege administrative MongoDB URI.", true),
			value("database", "Database", "Database in which the generated user is created.", true),
			roleAccess,
		)},
		{Type: "aws-sts", Label: "AWS STS", Purpose: "Assumes a bounded IAM role and returns an expiring AWS session that can't assume other roles unless allow_role_chaining is set. Early lease revocation remains pending until AWS session expiry, unless revoke_with_deny_policy denies the revoked session through an inline policy on its role.", Requirements: dynamicSecretAWSRequirements(
			value("endpoint", "STS endpoint", "HTTPS AWS STS Query API endpoint.", true),
			value("region", "AWS region", "Region used to sign STS requests.", true),
			value("access_key_id", "Caller access key ID", "Identifier of the identity allowed to call STS AssumeRole.", true),
			credential("secret_access_key_ref", "Caller secret access key reference", "AWS caller secret reference, resolved only during issuance.", true),
			credential("session_token_ref", "Caller session token reference", "Required when the caller itself uses temporary AWS credentials.", false),
			roles("Each allowed role maps to one full IAM role ARN trusted to allow sts:AssumeRole."),
			awsDenyPolicy, awsRoleChaining,
			awsConsole, awsGateway,
		)},
		{Type: "aws-iam", Label: "AWS STS (legacy aws-iam name)", Purpose: "Compatibility name for the same expiring AssumeRole session issuer; IAM user access keys are not created.", Requirements: dynamicSecretAWSRequirements(
			value("endpoint", "STS endpoint", "HTTPS AWS STS Query API endpoint.", true),
			value("region", "AWS region", "Region used to sign STS requests.", true),
			value("access_key_id", "Caller access key ID", "Identifier of the identity allowed to call STS AssumeRole.", true),
			credential("secret_access_key_ref", "Caller secret access key reference", "AWS caller secret reference, resolved only during issuance.", true),
			credential("session_token_ref", "Caller session token reference", "Required when the caller itself uses temporary AWS credentials.", false),
			roles("Each allowed role maps to one full IAM role ARN trusted to allow sts:AssumeRole."),
			awsDenyPolicy, awsRoleChaining,
		)},
		{Type: "gcp-iam", Label: "Google Cloud IAM", Purpose: "Creates and deletes a service-account key with a stable retry identity. A static rotation is two-phase: the successor is a new key of the service account beside the predecessor (an account holds ten), and retirement deletes the predecessor; only keys of the bound service account are ever deleted. A new key can take a minute to work and has no side-effect-free check, so verification reports not available and retirement waits for consumer evidence or the approved deadline.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "IAM endpoint", "HTTPS Google IAM API endpoint.", true),
			value("project", "Project", "Google Cloud project that owns the service account.", true),
			value("service_account", "Service account", "Email of the narrowly scoped service account.", true),
			value("gateway", "Gateway API binding", "Optional gateway-only account: endpoint is a fixed HTTPS API origin; token_endpoint is the fixed OAuth token URL; scopes is a nonempty array of explicit HTTPS scopes. Strict IAM/OAuth/API stand-in and stock curl proof only. Key deletion stops new grants, while issued access tokens retain native expiry. Human console sign-in is separate.", false),
			credential("bearer_token_ref", "Bearer token reference", "Short-lived Google access-token reference.", true),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
		)},
		{Type: "azure-entra", Label: "Azure Entra", Purpose: "Adds a client secret to the application through Microsoft Graph, named for the lease or rotation, and removes it at revocation after checking the provider named it. A static rotation is two-phase: the successor is a second secret beside the predecessor, which keeps working until the rotation retires it. Secrets are proven with a client-credentials token request. Rotation is built against a stand-in of Graph and the identity platform; no Entra proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Graph endpoint", "HTTPS Microsoft Graph endpoint.", true),
			value("application_object_id", "Application object ID", "Object ID of the application receiving the temporary credential.", true),
			value("application_client_id", "Application client ID", "Client ID returned with the generated credential.", true),
			value("gateway", "Gateway API binding", "Optional gateway-only API account: fixed endpoint origin, token_endpoint matching authority_host and azure_tenant_id, and one resource /.default scope. Graph/OAuth/scoped API stand-in and stock curl proof only. Removing the application password stops new grants, not already-issued tokens. Human Azure Portal and native Azure CLI are unverified.", false),
			value("azure_tenant_id", "Azure tenant ID", "Entra tenant containing the application.", true),
			credential("bearer_token_ref", "Bearer token reference", "Short-lived Microsoft Graph token reference.", true),
			value("authority_host", "Authority host", "Optional: the Microsoft identity platform a rotated secret is proven at (default https://login.microsoftonline.com).", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored client secret in two phases.", false),
		)},
		{Type: "kubernetes", Label: "Kubernetes", Purpose: "Requests a 10-minute-or-longer audience-scoped token bound to a temporary Secret; deleting the Secret invalidates the token.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Kubernetes API endpoint", "HTTPS Kubernetes API server endpoint.", true),
			value("namespace", "Namespace", "Namespace containing the temporary ServiceAccount.", true),
			value("kubernetes_audience", "Kubernetes API audience", "Exactly one audience accepted by the target API server. The cluster administrator supplies its configured --api-audiences value; Kubernetes requires a minimum 600-second TokenRequest TTL.", true),
			credential("bearer_token_ref", "Bearer token reference", "Administrative bearer token in a 0600 file: or tenant secret:// reference; it needs ServiceAccount, Secret, RoleBinding, TokenRequest, and bind permission on each target Role in the namespace.", true),
			credential("kubernetes_tls_ca_ref", "Kubernetes TLS CA reference", "Optional 0600 file: or tenant secret:// reference to the API server CA. If omitted, system roots are used.", false),
			value("kubernetes_tls_server_name", "Kubernetes TLS server name", "Optional certificate identity override when reaching the API by an internal alias; requires kubernetes_tls_ca_ref.", false),
			roles("Each allowed role maps to Role/name or ClusterRole/name."),
		)},
		{Type: "redis", Label: "Redis", Purpose: "Creates and deletes a scoped Redis ACL user.", Requirements: dynamicSecretProviderRequirements(
			value("addr", "Redis address", "Redis host and port.", true),
			credential("password_ref", "Admin password reference", "Required 0600 file: or tenant secret:// reference for the Redis ACL administrator.", true),
			value("redis_acl_roles", "Redis role policies", "For every allowed role, set literal key_prefixes and explicit safe commands. Raw ACL rules, categories, and global key access are refused. Redis must have a writable ACL file so ACL SAVE makes issue and revoke durable.", true),
			value("redis_tls_server_name", "Verified Redis TLS name", "Required server certificate DNS name or IP identity. TLS is used by default and the lease URI is rediss://.", true),
			credential("redis_tls_ca_ref", "Redis TLS CA reference", "Optional 0600 file: or tenant secret:// reference to the private Redis CA. When absent, system roots are used.", false),
			value("allow_plaintext_redis", "Local plaintext exception", "Explicitly permit plain Redis only at a literal loopback or private IP address. The returned URI is redis://; use only in a protected local lab.", false),
			value("db", "Database number", "Only database 0 is supported. Leased users cannot run SELECT because Redis ACLs cannot constrain its database argument.", false),
		)},
		{Type: "ldap", Label: "LDAP directory and AD accounts", Purpose: "Creates generic LDAP leased entries in the role's group, or in active_directory mode rotates an existing vaulted AD account without changing its memberships. Native Samba stand-in proof; native Windows and forest-wide revocation remain unverified.", Requirements: dynamicSecretProviderRequirements(
			desktop,
			value("directory_mode", "Directory account mode", "Empty for generic LDAP entry issuance. active_directory rotates existing named AD user accounts only, with allow_static_rotation and verified LDAPS. role_bindings values are account DNs under users_dn; optional rotation_accounts pairs preserve memberships. Native Samba stand-in proof: stock LDAP current/predecessor rejection, bounded lockout-aware verification and durable vault rotation. Existing sessions/Kerberos tickets and multi-DC revocation are not covered.", false),
			value("ad_logon_names", "AD desktop logon names", "Required with an active_directory desktop: map every managed account DN, including both members of a rotation pair, to its exact bare RDP logon name. The gateway freezes only the requested role's identities and refuses a different vaulted reference or logon name before native sign-in. Requires access.gateway.session.desktop.ad.v1; older native executors cannot claim it. Samba LDAP-only xrdp task, live termination and signed pixel replay stand-in proof; native Windows remains unverified.", false),
			value("addr", "Directory address", "host:port of the directory's LDAPS listener, verified against tls_server_name; plain LDAP only at a literal loopback or private IP with allow_plaintext.", true),
			value("bind_dn", "Administrator DN", "Directory account allowed to add and delete entries under users_dn and change the role groups' members.", true),
			credential("password_ref", "Administrator password reference", "The administrator's bind password.", true),
			value("users_dn", "Leased entries container", "DN of the container leased entries are created in.", true),
			credential("tls_ca_ref", "Directory TLS CA reference", "Optional private CA of the directory's certificate; system roots when omitted.", false),
			value("tls_server_name", "Directory TLS name", "Certificate name to verify; required when addr is an IP address, else addr's host.", false),
			value("allow_plaintext", "Local plaintext exception", "Explicitly permit ldap:// to a literal loopback or private IP only; use only in a protected lab.", false),
			roles("Each allowed role maps to the DN of one groupOfNames group; keep one permanent member in it, since a groupOfNames can't be empty."),
		)},
		{Type: "totp", Label: "TOTP codes", Purpose: "Issues the current RFC 6238 one-time code of a configured seed with the instant it stops being valid; a code can't be withdrawn or renewed, so it lapses at the end of its time step.", Requirements: dynamicSecretProviderRequirements(
			credential("seed_ref", "Seed reference", "The shared secret in base32, as an authenticator app enrolls it.", true),
			value("digits", "Digits", "6 (the default), 7 or 8.", false),
			value("period", "Period", "30s (the default) or 60s; max_ttl is required and must not exceed it.", false),
			value("algorithm", "Algorithm", "SHA1 (the default), SHA256 or SHA512.", false),
			roles("Every allowed role reads the same seed's codes; role_bindings are not used."),
		)},
		{Type: "oauth-client-credentials", Label: "OAuth access tokens", Purpose: "Requests a new access token from an OAuth 2.0 authorization server's token endpoint with the role's scopes (client credentials grant); a token can't be extended, and revoking the lease revokes the token at the revocation endpoint when one is configured, else the token lapses at its expiry.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Token endpoint", "HTTPS URL of the authorization server's token endpoint.", true),
			value("client_id", "Client ID", "The confidential client the tokens are issued to; give it only the scopes the roles need.", true),
			credential("client_secret_ref", "Client secret reference", "The client's secret, sent with HTTP Basic authentication.", true),
			value("revocation_endpoint", "Revocation endpoint", "Optional HTTPS URL of the RFC 7009 revocation endpoint. Without it revocation waits for each token's expiry.", false),
			value("max_ttl", "Maximum token lifetime", "The longest lifetime the authorization server gives this client's tokens; a longer-lived token is refused (and revoked when possible).", true),
			roles("Each allowed role maps to its space-separated scopes; a token granted any other scope is refused."),
		)},
		{Type: "clickhouse", Label: "ClickHouse users", Purpose: "Creates a ClickHouse user with a generated password, valid until the provider's maximum lifetime and holding the ClickHouse role its lease role is bound to, and drops it at revocation; ClickHouse then refuses its login.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "HTTP interface", "HTTPS URL of ClickHouse's HTTP interface.", true),
			value("admin_user", "Administrator", "A ClickHouse user with access management, allowed to create and drop users and to grant the bound roles.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			roles("Each allowed role maps to an existing ClickHouse role that holds its grants, for example SELECT on one database."),
		)},
		{Type: "elasticsearch", Label: "Elasticsearch API keys", Purpose: "Creates an Elasticsearch API key that expires with the provider's maximum lifetime and holds only the index privileges its role is bound to, and invalidates it at revocation; Elasticsearch then refuses it.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Cluster URL", "HTTPS URL of the Elasticsearch cluster.", true),
			value("admin_user", "Administrator", "A user allowed to manage API keys (manage_api_key) who holds at least the bound index privileges; keys never exceed it.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			roles(`Each allowed role maps to "<index privileges> on <index patterns>", for example "read on logs-*".`),
		)},
		{Type: "rabbitmq", Label: "RabbitMQ users", Purpose: "Creates a RabbitMQ user with a generated password and its role's permissions in one virtual host through the management API, and at revocation deletes it and closes its open connections; RabbitMQ then refuses its login.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Management API", "HTTPS URL of the RabbitMQ management API.", true),
			value("admin_user", "Administrator", "A user tagged administrator in the management API, allowed to create and delete users and set permissions.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to "<permissions> on <queues or exchanges> in <vhost>", for example "read on orders in /"; names match exactly.`),
		)},
		{Type: "tailscale", Label: "Tailscale auth keys", Purpose: "Creates a single-use, ephemeral, preauthorized Tailscale auth key carrying the role's ACL tags and expiring with the provider's maximum lifetime, and deletes it at revocation; Tailscale then refuses it. Devices it already registered stay until removed (an ephemeral one when it goes offline). Built against a stand-in of Tailscale's API; no tailnet proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "Tailscale API base URL; https://api.tailscale.com when empty.", false),
			value("tailnet", "Tailnet", `The tailnet's name; "-" (the API token's own tailnet) when empty.`, false),
			credential("bearer_token_ref", "API token reference", "A Tailscale API access token allowed to create and delete auth keys.", true),
			roles("Each allowed role maps to the comma-separated ACL tags its keys give the devices they register, for example tag:ci."),
		)},
		{Type: "mongodb-atlas", Label: "MongoDB Atlas database users", Purpose: "Creates a database user in one Atlas project with a generated password and its role's built-in roles, which Atlas deletes after the provider's maximum lifetime, and deletes it at revocation; Atlas then refuses its login. Built against a stand-in of the Atlas Admin API; no Atlas proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Atlas", "Atlas base URL; https://cloud.mongodb.com when empty.", false),
			value("project", "Project ID", "The Atlas project (group) ID, 24 hexadecimal characters.", true),
			value("client_id", "Service account client ID", "An Atlas service account allowed to manage the project's database users.", true),
			credential("client_secret_ref", "Service account secret reference", "The service account's client secret.", true),
			value("max_ttl", "Maximum lifetime", "At most 7 days: Atlas deletes each leased user at that age (deleteAfterDate).", true),
			roles(`Each allowed role maps to "<built-in role> on <databases>", for example "read on orders".`),
		)},
		{Type: "kafka", Label: "Kafka SCRAM users", Purpose: "Creates a SCRAM-SHA-512 user with a generated password and only its role's ACLs on topics, consumer groups and transactional IDs, and at revocation deletes the ACLs (refused from the user's next request, even on an open connection) and the credential; the brokers then refuse its login.", Requirements: dynamicSecretProviderRequirements(
			value("addr", "Bootstrap broker", "host:port of a broker's SASL_SSL listener, verified against tls_server_name; SASL_PLAINTEXT only at a literal loopback or private IP with allow_plaintext.", true),
			value("admin_user", "Administrator", "A SCRAM-SHA-512 user allowed to alter user SCRAM credentials and create and delete ACLs (ALTER on the cluster).", true),
			credential("password_ref", "Administrator password reference", "The administrator's SCRAM password.", true),
			credential("tls_ca_ref", "Broker TLS CA reference", "Optional private CA of the brokers' certificates; system roots when omitted.", false),
			value("tls_server_name", "Broker TLS name", "Certificate name every broker must carry; required when addr is an IP address, else each broker's advertised host name.", false),
			value("allow_plaintext", "Local plaintext exception", "Explicitly permit SASL_PLAINTEXT to a literal loopback or private IP only (and only to brokers advertised at such addresses); use only in a protected lab.", false),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to "<operations> on <resources>" clauses separated by ";", for example "read,describe on topic:orders; read on group:orders-app"; a name ending in * is a prefix.`),
		)},
		{Type: "cassandra", Label: "Cassandra login roles", Purpose: "Creates a Cassandra login role with a generated password (only its bcrypt hash travels in CQL) granted only its role's Cassandra roles, and drops it at revocation; the node then refuses its next login, and a connection already open once the node's role and permission caches expire.", Requirements: dynamicSecretProviderRequirements(
			value("addr", "Node", "host:port of one node's native-protocol port with client encryption, verified against tls_server_name; plaintext only at a literal loopback or private IP with allow_plaintext. Only this node is contacted.", true),
			value("admin_user", "Administrator", "A login role allowed to create, alter and drop roles and grant the bound roles (CREATE, ALTER, DROP and AUTHORIZE on ALL ROLES), or a superuser.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			credential("tls_ca_ref", "Node TLS CA reference", "Optional private CA of the node's certificate; system roots when omitted.", false),
			value("tls_server_name", "Node TLS name", "Certificate name the node must carry; required when addr is an IP address, else addr's host.", false),
			value("allow_plaintext", "Local plaintext exception", "Explicitly permit plaintext to a literal loopback or private IP only; use only in a protected lab.", false),
			value("username_prefix", "Role name prefix", "Optional prefix of leased roles (default trstctl); revocation only ever drops roles with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to existing Cassandra roles, comma separated, for example "orders_reader"; each carries the permissions the lease should have.`),
		)},
		{Type: "oracle", Label: "Oracle Database users", Purpose: "Creates an Oracle Database user with a generated password (sent only as a bind) granted only its role's Oracle roles, and at revocation locks it, kills its sessions and drops it; the database then refuses its login. A role with rotation_accounts instead rotates between two existing users.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator URL reference", "A go-ora URL (oracle://user:password@host:1521/service) of an administrator allowed to create, alter and drop users, grant the bound roles (or hold them WITH ADMIN OPTION) and kill sessions (ALTER SYSTEM, SELECT on V$SESSION).", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl, stored upper case); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: with rotation_accounts, rotate a role between two existing users in two phases; their grants never change.", false),
			roles(`Each allowed role maps to existing Oracle roles, comma separated, as Oracle stores them (for example "ORDERS_READER"); the roles carry CREATE SESSION and the lease's privileges. A role may instead name two existing users in rotation_accounts.`),
		)},
		{Type: "hana", Label: "SAP HANA users", Purpose: "Creates an SAP HANA user with a generated password (sent only as a bind) granted only its role's HANA roles, and at revocation deactivates it, disconnects its sessions and drops it; the database then refuses its login.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator URL reference", "A go-hdb URL (hdb://user:password@host:port, TLS options in its query) of an administrator with USER ADMIN, SESSION ADMIN and CATALOG READ who holds the bound roles WITH ADMIN OPTION.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl, stored upper case); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to existing HANA roles, comma separated, as HANA stores them (for example "ORDERS_READER").`),
		)},
		{Type: "couchbase", Label: "Couchbase users", Purpose: "Creates a local Couchbase user with a generated password and only its role's roles on the named buckets through the management REST API, and deletes it at revocation; Couchbase then refuses its next request.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Management REST API", "HTTPS URL of the cluster's management REST API (port 18091).", true),
			value("admin_user", "Administrator", "A user allowed to create and delete local users (Full Admin or Security Admin).", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to "<roles> on <buckets>", for example "bucket_full_access on orders" (the Community Edition's data role) or "data_reader,query_select on orders".`),
		)},
		{Type: "milvus", Label: "Milvus users", Purpose: "Creates a Milvus user with a generated password and only its role's Milvus roles through the RESTful API, and drops it at revocation; Milvus then refuses its next request.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "RESTful API", "HTTPS URL of the Milvus proxy's RESTful API (port 19530).", true),
			value("admin_user", "Administrator", "A Milvus user allowed to create and drop users and grant roles, such as root.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to existing Milvus roles, comma separated, for example "orders_reader"; each role carries the privileges the lease should have.`),
		)},
		{Type: "github-app", Label: "GitHub App installation tokens", Purpose: "Mints an installation access token for a GitHub App, narrowed to the role's permissions and named repositories, which GitHub ends after an hour, and at revocation ends it at once by presenting it. A lease can't be extended; a new lease mints a new token. Built against a stand-in of GitHub's API; no GitHub proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "GitHub API base URL; https://api.github.com when empty (GitHub Enterprise Server: https://<host>/api/v3).", false),
			value("client_id", "App client ID", "The GitHub App's client ID (or app ID), the issuer of the JWT each token request is signed with.", true),
			credential("private_key_ref", "App private key reference", "The GitHub App's private key (PEM).", true),
			value("installation_id", "Installation ID", "The numeric ID of the app's installation the tokens are minted for.", true),
			value("max_ttl", "Maximum lifetime", "At most 1h: GitHub ends installation tokens an hour after minting.", true),
			roles(`Each allowed role maps to "<permission>:<level> on <repositories>", for example "contents:read,metadata:read on api,web"; repositories are named explicitly.`),
		)},
		{Type: "snowflake", Label: "Snowflake service users", Purpose: "Creates a Snowflake service user (TYPE = SERVICE) that authenticates with a key pair the provider generates (the lease returns the private key; no password exists), granted only the role's roles and set to expire in Snowflake after the provider's maximum lifetime in whole days; at revocation disables it, which aborts its running queries, and drops it. Built against a stand-in of the SQL API; no Snowflake proof yet. A role bound to \"user <NAME>\" instead rotates that existing user's key pair in two phases through its two key slots (RSA_PUBLIC_KEY and RSA_PUBLIC_KEY_2): the successor goes in the slot the predecessor is not in, both sign in until retirement unsets the predecessor's slot, and a key pair is proven by running SELECT 1 as its user.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Account URL", "https://<orgname>-<accountname>.snowflakecomputing.com.", true),
			value("account", "Account identifier", "The account identifier the key-pair JWT names, <orgname>-<accountname>.", true),
			value("admin_user", "Administrator", "A user allowed to create, alter and drop users and grant the bound roles (USERADMIN or SECURITYADMIN), with a registered key pair.", true),
			credential("private_key_ref", "Administrator private key reference", "The administrator's private key (PEM) matching its RSA_PUBLIC_KEY.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Required for a role bound to \"user <NAME>\": it rotates that user's key pair and issues no leases.", false),
			roles(`Each allowed role maps to Snowflake roles, comma separated, for example "ANALYST" (the first is the user's default role), or to "user <NAME>" to rotate that existing user's key pair.`),
		)},
		{Type: "aws-elasticache", Label: "ElastiCache RBAC users", Purpose: "Creates an ElastiCache (Redis OSS or Valkey) RBAC user with a generated password and the role's literal key prefixes and explicit commands, adds it to the configured user group, and deletes it at revocation, which removes it from every group and cluster. Built against a stand-in of the ElastiCache API; no AWS proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("region", "Region", "The AWS region of the user group.", true),
			value("access_key_id", "Access key ID", "An AWS access key allowed to create, modify and delete users and modify the user group.", true),
			credential("secret_access_key_ref", "Secret access key reference", "The access key's secret.", true),
			credential("session_token_ref", "Session token reference", "Optional session token for temporary credentials.", false),
			value("user_group", "User group", "The ElastiCache user group, attached to the cluster, that leased users join.", true),
			value("engine", "Engine", "redis (default) or valkey, matching the user group.", false),
			value("redis_acl_roles", "Role policies", "For every allowed role, literal key_prefixes and explicit safe commands, as for the Redis provider; raw ACL rules and categories are refused.", true),
		)},
		{Type: "aws-memorydb", Label: "MemoryDB RBAC users", Purpose: "Creates a MemoryDB RBAC user with a generated password and the role's literal key prefixes and explicit commands, adds it to the configured ACL, and deletes it at revocation, which removes it from every ACL and cluster. Built against a stand-in of the MemoryDB API; no AWS proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("region", "Region", "The AWS region of the ACL.", true),
			value("access_key_id", "Access key ID", "An AWS access key allowed to create, update and delete users and update the ACL.", true),
			credential("secret_access_key_ref", "Secret access key reference", "The access key's secret.", true),
			credential("session_token_ref", "Session token reference", "Optional session token for temporary credentials.", false),
			value("user_group", "ACL", "The MemoryDB ACL, attached to the cluster, that leased users join.", true),
			value("redis_acl_roles", "Role policies", "For every allowed role, literal key_prefixes and explicit safe commands, as for the Redis provider; raw ACL rules and categories are refused.", true),
		)},
		{Type: "ibm-api-connect", Label: "IBM API Connect app credentials", Purpose: "Creates a credential (client ID and generated secret) on the consumer app the role is bound to through the API Connect platform API, carrying that app's subscriptions, and deletes it at revocation; the gateway then refuses its client ID. Built against a stand-in of the platform API; no API Connect proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Platform API", "HTTPS URL of the API Connect platform API.", true),
			value("client_id", "Platform client ID", "The client ID the API key grant authenticates with (a toolkit or registered client).", true),
			credential("client_secret_ref", "Platform client secret reference", "That client's secret.", true),
			credential("api_key_ref", "API key reference", "An API key of a user allowed to manage the bound apps' credentials.", true),
			value("username_prefix", "Credential name prefix", "Optional prefix of leased credential names (default trstctl); revocation only ever deletes credentials with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to the consumer app "<org>/<catalog>/<consumer-org>/<app>"; the app's subscriptions are the credential's authority.`),
		)},
		{Type: "auth0", Label: "Auth0 application client secret", Purpose: "Rotates the client secret of the application the role is bound to through the Management API (static rotation only; it issues no leases). Single phase: Auth0 invalidates the current secret the moment it issues the next, so a rotation runs only when acknowledged and consumers fail until they read the new version. Built against a stand-in of the Management API; no Auth0 proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Tenant domain", "HTTPS URL of the Auth0 tenant, https://<tenant>.<region>.auth0.com.", true),
			value("client_id", "Management client ID", "A machine-to-machine application granted the Management API's update:client_keys scope.", true),
			credential("client_secret_ref", "Management client secret reference", "That application's client secret.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role (the secret name) maps to the client ID of the application whose secret it rotates."),
		)},
		{Type: "datadog", Label: "Datadog API and application keys", Purpose: "Creates an API key, or an application key of a service account restricted to the role's scopes, through the Datadog API, and deletes it at revocation; Datadog then refuses it. A static rotation is two-phase: the new key is created next to the old one, which keeps working until the rotation retires it. API keys are proven at the site's validate endpoint; application keys have no side-effect-free proof. Built against a stand-in of the Datadog API; no Datadog proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Site API", "HTTPS URL of the Datadog site's API, for example https://api.datadoghq.com.", true),
			credential("api_key_ref", "Administrator API key reference", "An API key of the organization.", true),
			credential("application_key_ref", "Administrator application key reference", "An application key allowed to manage API keys (api_keys_write) and the bound service accounts' application keys.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of issued key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "api_key", or to "application_key <service-account-id> <scope>,<scope>" for an application key of that service account restricted to those scopes.`),
		)},
		{Type: "openai", Label: "OpenAI service account keys", Purpose: "Creates a service account in the project the role is bound to through the OpenAI admin API, whose API key the response returns once, and deletes the service account (and its key) at revocation; the API then refuses the key. A static rotation is two-phase: the successor is a new service account next to the predecessor, which keeps working until the rotation retires it. Keys are proven by listing models with them. Built against a stand-in of the admin API; no OpenAI proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "HTTPS URL of the API, https://api.openai.com.", true),
			credential("api_key_ref", "Admin key reference", "An organization admin key allowed to manage the bound projects' service accounts.", true),
			value("username_prefix", "Service account name prefix", "Optional prefix of issued service account names (default trstctl); revocation only ever deletes service accounts with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to the project ID ("proj_...") its service accounts are created in; the project's permissions are the key's authority.`),
		)},
		{Type: "openrouter", Label: "OpenRouter API keys", Purpose: "Creates an OpenRouter API key with a management key, named for the lease or rotation and held to the role's credit limit, and deletes it at revocation; OpenRouter then refuses it. A static rotation is two-phase: both keys work until the rotation retires the predecessor. Keys are proven by reading their own details with them. Built against a stand-in of the key management API; no OpenRouter proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "HTTPS URL of the API, https://openrouter.ai/api/v1.", true),
			credential("api_key_ref", "Management key reference", "A management key allowed to create, list and delete the account's API keys.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "unlimited" or "limit <USD>", the credit limit its keys are created with.`),
		)},
		{Type: "fireworks", Label: "Fireworks AI API keys", Purpose: "Creates an API key for the user the role is bound to with an account administrator's key, named for the lease or rotation, and deletes it at revocation; Fireworks returns a key's value only at creation. A static rotation is two-phase. Keys are proven by listing accounts with them. Built against a stand-in of the API; no Fireworks proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "HTTPS URL of the API, https://api.fireworks.ai.", true),
			credential("api_key_ref", "Administrator key reference", "An account administrator's API key, allowed to create, list and delete the bound users' API keys.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "<account-id>/<user-id>", the user its keys are created for; the user's permissions are the key's authority.`),
		)},
		{Type: "litellm", Label: "LiteLLM proxy virtual keys", Purpose: "Generates a virtual key on a LiteLLM proxy with its master key, aliased for the lease or rotation and limited to the role's models, and deletes it at revocation; the proxy then refuses it. A static rotation is two-phase. Keys are proven by reading their own details with them. Built against a stand-in of the proxy API; no LiteLLM proxy proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Proxy URL", "HTTPS URL of the LiteLLM proxy.", true),
			credential("api_key_ref", "Master key reference", "The proxy's master key.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "all-models" or "models <name>,<name>", the models its keys may call.`),
		)},
		{Type: "supabase", Label: "Supabase secret API keys", Purpose: "Creates a secret API key in the project the role is bound to through the Management API, named for the lease or rotation, and deletes it at revocation. A static rotation is two-phase. Supabase documents no side-effect-free check of a secret key, so verification reports not available and retirement waits for consumer evidence or the approved deadline. Built against a stand-in of the Management API; no Supabase proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Management API", "HTTPS URL of the Management API, https://api.supabase.com.", true),
			credential("api_key_ref", "Access token reference", "An access token allowed to create, read and delete the bound projects' API keys.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to a project reference (twenty lower-case letters), the project its secret keys are created in.`),
		)},
		{Type: "convex", Label: "Convex deploy keys", Purpose: "Creates a deploy key for the deployment the role is bound to through the Platform API, named for the lease or rotation and optionally limited to some actions, and deletes it by name at revocation. A static rotation is two-phase. Only the deployment checks a deploy key, so verification reports not available and retirement waits for consumer evidence or the approved deadline. Built against a stand-in of the Platform API; no Convex proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Platform API", "HTTPS URL of the Platform API, https://api.convex.dev/v1.", true),
			credential("api_key_ref", "Access token reference", "A team or personal access token allowed to manage the bound deployments' deploy keys.", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "<deployment>" or "<deployment> <action>,<action>" (deployment:deploy, say), the deployment its keys are for and the actions they are limited to.`),
		)},
		{Type: "dbt", Label: "dbt platform service tokens", Purpose: "Creates a service token with one permission grant through the v3 API, named for the lease or rotation, and deletes it at revocation; dbt then refuses it. A static rotation is two-phase. Tokens are proven by listing the accounts they reach. Built against a stand-in of the v3 API; no dbt platform proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Access URL", "HTTPS access URL of the account (https://cloud.getdbt.com, or a regional or cell host).", true),
			credential("api_key_ref", "Service token reference", "An administrator's service token (dbt refuses to create service tokens with a personal access token).", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "<account-id> <permission-set>" or "<account-id> <permission-set> project <project-id>", the one grant its tokens get (job_runner, say).`),
		)},
		{Type: "cloudflare", Label: "Cloudflare API tokens", Purpose: "Creates a Cloudflare API token that copies the policies and condition of a template token the operator made in the dashboard, named for the lease or rotation, and deletes it at revocation; Cloudflare then refuses it. A static rotation is two-phase: a new token beside the predecessor, unlike Cloudflare's roll, which ends the old value at once. Tokens are proven by Cloudflare's token verification route. Built against a stand-in of the API; no Cloudflare proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "HTTPS URL of the API, https://api.cloudflare.com/client/v4.", true),
			credential("api_key_ref", "Token reference", "A token allowed to read the template token and create, list and delete tokens (API Tokens Write; Account API Tokens Write for account tokens).", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "template <token-id>" (user tokens) or "account <account-id> template <token-id>" (account tokens); keys copy that template token's policies and condition.`),
		)},
		{Type: "cloudflare-r2", Label: "Cloudflare R2 access keys", Purpose: "Creates an account API token that copies a template token's R2 policies and returns its S3 pair: the token ID is the access key ID and the SHA-256 of its value the secret access key. Revocation deletes the token, which ends the pair. A static rotation is two-phase. The pair carries no token to check and R2's S3 endpoint is the account's own host, so verification reports not available. Built against a stand-in of the API; no Cloudflare proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "API", "HTTPS URL of the API, https://api.cloudflare.com/client/v4.", true),
			credential("api_key_ref", "Token reference", "A token allowed to read the template token and create, list and delete the account's tokens (Account API Tokens Write).", true),
			value("username_prefix", "Key name prefix", "Optional prefix of leased key names (default trstctl); revocation only ever deletes keys with it and the lease digest suffix the provider gives them.", false),
			value("allow_static_rotation", "Static rotation", "Optional: also rotate a stored key in two phases.", false),
			roles(`Each allowed role maps to "account <account-id> template <token-id>"; key pairs copy that template token's R2 policies.`),
		)},
		{Type: "okta", Label: "Okta app client secrets", Purpose: "Rotates an Okta app's client secret in two phases: a new secret is added beside the one consumers use (Okta allows two) and retirement deactivates and deletes the old one. Secrets carry no name, so the bound app is the boundary: only its secrets are removed. A secret is proven by authenticating the app at the org's introspection endpoint. It rotates only; it issues no leases. Built against a stand-in of the Okta API; no Okta proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Okta org", "HTTPS URL of the Okta org.", true),
			credential("api_key_ref", "API token reference", "An API token (SSWS) allowed to manage the bound apps' client secrets.", true),
			value("allow_static_rotation", "Static rotation", "Required: the provider rotates only.", true),
			roles(`Each allowed role maps to the app ID ("0oa...") whose client secret rotates.`),
		)},
		{Type: "databricks", Label: "Databricks service principal secrets", Purpose: "Rotates a Databricks service principal's OAuth secret in two phases at the account API, authenticating as an account admin service principal: a new secret beside the old one (a principal holds five), and retirement deletes the old one. Only secrets of the bound principal are removed. A secret is proven by getting an account-level OAuth token with it. It rotates only; it issues no leases. Built against a stand-in of the account API; no Databricks proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Account console", "HTTPS URL of the account console, https://accounts.cloud.databricks.com.", true),
			value("client_id", "Admin service principal", "The application ID of an account admin service principal.", true),
			credential("client_secret_ref", "Admin secret reference", "That service principal's OAuth secret.", true),
			value("allow_static_rotation", "Static rotation", "Required: the provider rotates only.", true),
			roles(`Each allowed role maps to "<account-id> <service-principal-id>", the principal whose OAuth secret rotates.`),
		)},
		{Type: "unix", Label: "Unix/Linux local accounts", Purpose: "Rotates local account passwords on a host over SSH as an administrator authenticating with a key, the host key pinned; the only command run is chpasswd with the change on stdin. A role with rotation_accounts alternates between two accounts its owner provisioned (two-phase: the predecessor keeps working until retirement sets a password nobody holds; groups and files stay). A role bound to one account changes its password in place (single phase: a rotation runs only when acknowledged). Verified by logging in with the new password. It rotates only; it issues no leases.", Requirements: dynamicSecretProviderRequirements(
			desktop,
			value("addr", "SSH endpoint", "The host's SSH host:port.", true),
			value("admin_user", "Administrator", "root, or an account allowed `sudo -n /usr/sbin/chpasswd` (set sudo).", true),
			credential("private_key_ref", "Administrator key reference", "The administrator's private key, PKCS#8 PEM.", true),
			value("host_key_fingerprint", "Host key pin", "The host key's SHA256 fingerprint, as ssh-keygen -lf prints it.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates, or names two accounts in rotation_accounts."),
		)},
		{Type: "windows", Label: "Windows local accounts", Purpose: "Rotates local account passwords on a Windows host serving OpenSSH, as a member of Administrators authenticating with a key, the host key pinned; the only command run is Windows PowerShell's Set-LocalUser, the account named in its encoded script and the password on stdin. Passwords mix upper and lower case letters and digits, as Windows' complexity rule needs. A role with rotation_accounts alternates between two accounts its owner provisioned (two-phase: the predecessor keeps working until retirement sets a password nobody holds). A role bound to one account changes its password in place (single phase: a rotation runs only when acknowledged). Verified by logging in with the new password. It rotates only; it issues no leases.", Requirements: dynamicSecretProviderRequirements(
			desktop,
			value("addr", "SSH endpoint", "The host's OpenSSH host:port.", true),
			value("admin_user", "Administrator", "A local account in Administrators, whose key is in administrators_authorized_keys.", true),
			credential("private_key_ref", "Administrator key reference", "The administrator's private key, PKCS#8 PEM.", true),
			value("host_key_fingerprint", "Host key pin", "The host key's SHA256 fingerprint, as ssh-keygen -lf prints it.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates (at most 20 characters), or names two accounts in rotation_accounts."),
		)},
		{Type: "iosxe", Label: "Cisco IOS-XE local accounts", Purpose: "Changes local account passwords on a Cisco IOS-XE device through its own command line over SSH, as an administrator at privilege 15 signing in with a password, the host key pinned: configure terminal, username <account> privilege <its current level> secret 0 <password>, end and write memory, so the account keeps its privilege level and the change survives a reload. A role bound to the account enable rotates the privileged-mode secret (enable secret). Each role's one account changes in place (single phase: a rotation runs only when acknowledged); a change the device does not prove is put back. Verified by signing in with the new password, or entering privileged mode with the new enable secret. Discovery lists the device's local accounts with their privilege level, never their hashes. It rotates only; it issues no leases. Built against a stand-in of the CLI; no device proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("addr", "SSH endpoint", "The device's SSH host:port.", true),
			value("admin_user", "Administrator", "A local account at privilege 15 that signs in with a password and may configure accounts; never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("host_key_fingerprint", "Host key pin", "The device's SSH host key SHA256 fingerprint, as ssh-keygen -lf prints it.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates, or to enable for the privileged-mode secret."),
		)},
		{Type: "junos", Label: "Juniper Junos local accounts", Purpose: "Changes local account passwords on a Juniper Junos device through its own command line over SSH, as an administrator in a class allowed to configure system login, signing in with a password, the host key pinned: configure private, set system login user <account> authentication plain-text-password (the password typed at the prompt, never on the command line) and commit and-quit, so the account keeps its login class. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); a change the device does not prove is put back. Verified by signing in with the new password. Discovery lists the device's local accounts with their login class, never their hashes. It rotates only; it issues no leases. Built against a stand-in of the CLI; no device proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("addr", "SSH endpoint", "The device's SSH host:port.", true),
			value("admin_user", "Administrator", "A local account whose class may configure system login (super-user) and signs in with a password; never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("host_key_fingerprint", "Host key pin", "The device's SSH host key SHA256 fingerprint, as ssh-keygen -lf prints it.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates."),
		)},
		{Type: "eos", Label: "Arista EOS local accounts", Purpose: "Changes local account passwords on an Arista EOS switch through eAPI (JSON-RPC runCmds over HTTPS, the switch's certificate pinned), as an administrator at privilege 15 with exec authorization signing in with a password: configure, username <account> privilege <its level> role <its role> secret 0 <password>, end and copy running-config startup-config, so the account keeps its privilege and role and the change survives a reload. A role bound to the account enable rotates the enable password. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); a change the switch does not prove is put back. Verified by running a command as the account with the new password, or entering privileged mode with the new enable password. Discovery lists the switch's local accounts with their privilege and role, never their hashes. It rotates only; it issues no leases. Built against a stand-in of eAPI; no switch proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "eAPI", "The switch's https://host[:port] (management api http-commands).", true),
			credential("tls_ca_ref", "Certificate pin", "The switch's certificate, or the CA that issued it, PEM.", true),
			value("tls_server_name", "Certificate name", "Optional name the certificate is checked against, when it differs from the endpoint's host.", false),
			value("admin_user", "Administrator", "A local account at privilege 15 with exec authorization; never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates, or to enable for the enable password."),
		)},
		{Type: "fortigate", Label: "FortiGate administrators", Purpose: "Changes FortiGate administrator passwords through the REST API over HTTPS (the firewall's certificate pinned), as a REST API administrator with a token: PUT /api/v2/cmdb/system/admin/<name> with the new password, which FortiOS saves at once. Each role's one administrator changes in place (single phase: a rotation runs only when acknowledged); a change the firewall does not prove is put back. Verified by signing in at /logincheck with the new password and logging out. Discovery lists the administrators with their access profiles, never their hashes. It rotates only; it issues no leases. Built against a stand-in of the REST API; no firewall proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "REST API", "The firewall's https://host[:port].", true),
			credential("tls_ca_ref", "Certificate pin", "The firewall's certificate, or the CA that issued it, PEM.", true),
			value("tls_server_name", "Certificate name", "Optional name the certificate is checked against, when it differs from the endpoint's host.", false),
			value("admin_user", "REST API administrator", "The REST API administrator whose token is api_key_ref (an access profile that may write admin settings); never a rotated account.", true),
			credential("api_key_ref", "API token reference", "The REST API administrator's token.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the administrator it rotates."),
		)},
		{Type: "bigip", Label: "F5 BIG-IP users", Purpose: "Changes BIG-IP user passwords through iControl REST over HTTPS (the device's certificate pinned), as an administrator signing in for a token at /mgmt/shared/authn/login: PATCH /mgmt/tm/auth/user/<name> with the new password, then POST /mgmt/tm/sys/config save; the token is deleted after each call. Each role's one user changes in place (single phase: a rotation runs only when acknowledged); a change the device does not prove is put back. Verified by signing in with the new password for a token, which is then deleted. Discovery lists the users with their partition roles, never their hashes. root is not an iControl REST user and is not rotated here. It rotates only; it issues no leases. Built against a stand-in of iControl REST; no device proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "iControl REST", "The device's https://host[:port] management address.", true),
			credential("tls_ca_ref", "Certificate pin", "The device's certificate, or the CA that issued it, PEM.", true),
			value("tls_server_name", "Certificate name", "Optional name the certificate is checked against, when it differs from the endpoint's host.", false),
			value("admin_user", "Administrator", "A user with the Administrator (or User Manager) role on all partitions; never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the user it rotates (never root)."),
		)},
		{Type: "redfish", Label: "Server management controller accounts (Redfish)", Purpose: "Changes local account passwords on a server management controller through Redfish's AccountService over HTTPS (the controller's certificate pinned), HPE iLO first and any conforming controller after: the administrator opens a Redfish session, finds the bound account's ManagerAccount by UserName and PATCHes its Password (with the account's ETag when the controller sends one), then logs the session out. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); the change is proved by opening a new session with the new password, and a change the controller does not prove is put back. Discovery lists the controller's accounts with their RoleId, never a password. It rotates only; it issues no leases. Built against a stand-in of the Redfish service; no controller proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Redfish service", "The controller's https://host[:port].", true),
			credential("tls_ca_ref", "Certificate pin", "The controller's certificate, or the CA that issued it, PEM.", true),
			value("tls_server_name", "Certificate name", "Optional name the certificate is checked against, when it differs from the endpoint's host.", false),
			value("admin_user", "Administrator", "An account whose role may configure users (Administrator); never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the account UserName it rotates."),
		)},
		{Type: "esxi", Label: "VMware ESXi local accounts", Purpose: "Changes local account passwords on a VMware ESXi host through the vSphere Web Services API (SOAP at /sdk over HTTPS, the host's certificate pinned): an administrator signs in, changes the bound account with HostLocalAccountManager.UpdateUser and signs out. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); the change is proved by signing in as the account with the new password, and a change the host does not prove is put back. vpxuser and dcui, which vCenter and the console manage, are never rotated. Discovery lists the local users with the roles their permissions grant, never a password. It rotates only; it issues no leases. Built against a stand-in of the API; no host proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Host", "The host's https://host[:port]; the API is its /sdk.", true),
			credential("tls_ca_ref", "Certificate pin", "The host's certificate, or the CA that issued it, PEM.", true),
			value("tls_server_name", "Certificate name", "Optional name the certificate is checked against, when it differs from the endpoint's host.", false),
			value("admin_user", "Administrator", "A local account with the Administrator role on the host (root); never a rotated account.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the local account it rotates (never vpxuser or dcui)."),
		)},
		{Type: "vcenter-sso", Label: "vCenter single sign-on users", Purpose: "Changes vCenter Server's local single sign-on users' passwords the documented way: SSH to the appliance as root with a key (root's login shell set to bash, its host key pinned) and run dir-cli password reset as the SSO administrator, whose password is typed at dir-cli's prompt and never on a command line; the new password is dir-cli's --new argument, single-quoted, with shell history off. Each role's one user changes in place (single phase: a rotation runs only when acknowledged); the change is proved by opening a vSphere Automation API session (POST /api/session, the appliance's certificate pinned) as the user, and a change the appliance does not prove is put back. Discovery lists the SSO Administrators group. It rotates only; it issues no leases. Built against a stand-in of the appliance; no vCenter proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Appliance", "The appliance's https://host[:port] (the REST session proof).", true),
			credential("tls_ca_ref", "Certificate pin", "The appliance's certificate, or the CA that issued it, PEM.", true),
			value("addr", "Appliance SSH", "The appliance's SSH host:port.", true),
			value("host_key_fingerprint", "SSH host key pin", "The appliance's SSH host key SHA256 fingerprint.", true),
			value("admin_user", "Shell account", "The appliance account whose bash shell runs dir-cli (root).", true),
			credential("private_key_ref", "Shell key reference", "That account's SSH private key, PKCS#8 PEM.", true),
			value("sso_admin", "SSO administrator", "The SSO administrator's user@domain (administrator@vsphere.local).", true),
			credential("password_ref", "SSO administrator password reference", "The SSO administrator's password.", true),
			value("allow_static_rotation", "Static rotation", "Required: this provider only rotates.", true),
			roles("Each allowed role maps to the SSO user (without its domain) it rotates."),
		)},
		{Type: "okta-user", Label: "Okta administrator accounts", Purpose: "Sets an Okta administrator's (a break-glass super administrator's) password with an API token: a partial update of the user's credentials.password, which needs no old password. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); the change is proved by one sign-in through the Authentication API (SUCCESS, or an MFA step after the right password; a pending transaction is cancelled), never retried, so a wrong password costs one lockout attempt. It rotates only; it issues no leases. Built against a stand-in of the Okta API; no Okta proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Okta org", "HTTPS URL of the Okta org.", true),
			credential("api_key_ref", "API token reference", "An API token (SSWS) of an administrator allowed to set this account's password (Super Administrator for a super administrator).", true),
			value("allow_static_rotation", "Static rotation", "Required: the provider rotates only.", true),
			roles("Each allowed role maps to the account's Okta login (user@domain)."),
		)},
		{Type: "entra-user", Label: "Microsoft Entra ID administrator accounts", Purpose: "Sets an Entra ID administrator's (a break-glass Global Administrator's) password through Microsoft Graph with an application's client-credentials token: a PATCH of the user's passwordProfile. Each role's one account changes in place (single phase: a rotation runs only when acknowledged); the change is proved by one resource-owner password sign-in, read by its error code (a wrong password is 50126; an MFA or conditional-access step after the right password proves it; a tenant that refuses the flow cannot prove it), never retried. It rotates only; it issues no leases. Built against a stand-in of Graph and the identity platform; no Entra proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Microsoft Graph", "https://graph.microsoft.com.", true),
			value("authority_host", "Identity platform", "https://login.microsoftonline.com.", true),
			value("azure_tenant_id", "Directory", "The directory (tenant) ID.", true),
			value("client_id", "Application", "The application (client) ID; it needs User-PasswordProfile.ReadWrite.All and the Privileged Authentication Administrator role to reset an administrator's password.", true),
			credential("client_secret_ref", "Client secret reference", "The application's client secret.", true),
			value("allow_static_rotation", "Static rotation", "Required: the provider rotates only.", true),
			roles("Each allowed role maps to the account's user principal name."),
		)},
		{Type: "google-workspace-user", Label: "Google Workspace administrator accounts", Purpose: "Sets a Google Workspace super administrator's (a break-glass account's) password through the Admin SDK Directory API, as a service account with domain-wide delegation impersonating another super administrator: a PATCH of the user's password. Each role's one account changes in place (single phase: a rotation runs only when acknowledged). Google offers no non-interactive password check, so a change is not proved there (verification reports not available). It rotates only; it issues no leases. Built against a stand-in of the Admin SDK and token endpoint; no Google proof yet.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Admin SDK", "https://admin.googleapis.com.", true),
			value("authority_host", "Token endpoint", "https://oauth2.googleapis.com/token.", true),
			value("service_account", "Service account", "The service account's email; it needs domain-wide delegation for https://www.googleapis.com/auth/admin.directory.user.", true),
			credential("private_key_ref", "Service account key reference", "The service account's private key, PEM.", true),
			value("admin_user", "Impersonated administrator", "The super administrator the service account acts as; never a rotated account.", true),
			value("allow_static_rotation", "Static rotation", "Required: the provider rotates only.", true),
			roles("Each allowed role maps to the account's primary email."),
		)},
		{Type: "mssql", Label: "SQL Server logins", Purpose: "Creates a SQL Server login with a generated password and a user in the configured database that joins the role's database roles, and at revocation disables the login, ends its open sessions and drops the user and login; SQL Server then refuses its login.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator DSN reference", "sqlserver:// DSN of a login allowed to manage logins and users, end sessions (ALTER ANY CONNECTION) and add role members in the database.", true),
			value("database", "Database", "The database leased logins get a user and role memberships in.", true),
			value("username_prefix", "Login name prefix", "Optional prefix of leased logins (default trstctl); revocation only ever drops principals with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to database roles, comma separated, for example "db_datareader".`),
		)},
		{Type: "azure-sql", Label: "Azure SQL contained users", Purpose: "Creates a contained database user with a generated password that joins the role's database roles, and at revocation ends its open sessions and drops it; the database then refuses its login. Proven against SQL Server's contained database users; no Azure proof yet.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator DSN reference", "sqlserver:// DSN of a user in the database allowed to manage users, add role members and end sessions.", true),
			value("database", "Database", "The (contained) database the leased users live in.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it and the lease digest suffix the provider gives them.", false),
			roles(`Each allowed role maps to database roles, comma separated, for example "db_datareader".`),
		)},
	}
	for i := range providers {
		providers[i].Authority, providers[i].Revocation = dynamicSecretProviderAuthority(providers[i].Type)
	}
	return providers
}

// dynamicSecretProviderAuthority states what a provider's leased credential may
// do, and whether the provider can end it before its native expiry
// ("confirmed") or it lapses only then ("ttl_only") (A239).
func dynamicSecretProviderAuthority(providerType string) (authority, revocation string) {
	switch providerType {
	case "postgresql":
		return "CONNECT on the configured database and USAGE on its schema, with SELECT on its tables for a read role, or SELECT, INSERT, UPDATE and DELETE for a readwrite role (its role_access, or a role named as its class)", "confirmed"
	case "mysql":
		return "SELECT on the configured database for a read role, or SELECT, INSERT, UPDATE and DELETE for a readwrite role (its role_access, or a role named as its class), from the configured account host only", "confirmed"
	case "mongodb":
		return "read on the configured database for a read role, or readWrite for a readwrite role (its role_access, or a role named as its class)", "confirmed"
	case "aws-sts", "aws-iam":
		return "the assumed IAM role's policies for the session's lifetime", "ttl_only"
	case "gcp-iam":
		return "the service account's IAM bindings, through a key deleted at revocation", "confirmed"
	case "azure-entra":
		return "the application's permissions, through a client secret removed at revocation; access tokens already issued last until their own expiry", "confirmed"
	case "kubernetes":
		return "the Role or ClusterRole bound to a temporary ServiceAccount, through a token that stops working when its Secret is deleted", "confirmed"
	case "redis":
		return "the role's literal key prefixes and explicitly listed commands", "confirmed"
	case "ldap":
		return "generic LDAP leases get membership of the role's group; active_directory mode retains an existing vaulted account's memberships and resets its password only, without revoking existing sessions or Kerberos tickets", "confirmed"
	case "totp":
		return "the configured seed's current one-time code, accepted until the end of its time step (and through any skew window the verifier allows)", "ttl_only"
	case "oauth-client-credentials":
		return "an access token carrying only the role's scopes, accepted by resource servers until it is revoked at the authorization server or expires", "confirmed"
	case "clickhouse":
		return "the grants of the ClickHouse role the lease role is bound to, until the user is dropped or its VALID UNTIL passes", "confirmed"
	case "elasticsearch":
		return "the role's index privileges on its index patterns, through an API key invalidated at revocation or expiring with the provider's maximum lifetime", "confirmed"
	case "rabbitmq":
		return "the role's configure, write and read permissions on the named queues and exchanges in one virtual host, until the user is deleted and its connections closed", "confirmed"
	case "tailscale":
		return "one registration of a device with the role's ACL tags, until the auth key is deleted or expires; devices already registered keep their tags until removed", "confirmed"
	case "mongodb-atlas":
		return "the role's built-in roles on the named databases of one Atlas project, until the user is deleted or Atlas removes it at its deleteAfterDate", "confirmed"
	case "kafka":
		return "the role's ACL operations on its topics, consumer groups and transactional IDs, until the ACLs and the SCRAM credential are deleted", "confirmed"
	case "oracle":
		return "the privileges of the Oracle roles the lease role is bound to, until the user is locked, its sessions killed and the user dropped", "confirmed"
	case "hana":
		return "the privileges of the HANA roles the lease role is bound to, until the user is deactivated, its sessions disconnected and the user dropped", "confirmed"
	case "cassandra":
		return "the permissions of the Cassandra roles the lease role is bound to, until the role is dropped (a connection already open keeps them until the node's role and permission caches expire, 2 s by default)", "confirmed"
	case "couchbase":
		return "the role's Couchbase roles on the named buckets, until the user is deleted", "confirmed"
	case "milvus":
		return "the privileges of the Milvus roles the lease role is bound to, until the user is dropped", "confirmed"
	case "github-app":
		return "the role's repository permissions on the named repositories, through an installation token ended at revocation or by GitHub an hour after minting", "confirmed"
	case "snowflake":
		return "the role's Snowflake roles, through a key-pair service user disabled and dropped at revocation, or expired by Snowflake after the maximum lifetime in whole days", "confirmed"
	case "aws-elasticache", "aws-memorydb":
		return "the role's literal key prefixes and explicit commands, through an RBAC user in one user group or ACL, until the user is deleted", "confirmed"
	case "ibm-api-connect":
		return "the subscriptions (plans and products) of the consumer app the role is bound to, until the credential is deleted", "confirmed"
	case "auth0":
		return "the bound application's own grants, through its rotated client secret; the previous secret stops working when the next is issued", "confirmed"
	case "datadog":
		return "an organization API key, or a service account's application key restricted to the role's scopes, until the key is deleted", "confirmed"
	case "openai":
		return "a member service account of the bound project, through its API key, until the service account is deleted", "confirmed"
	case "okta":
		return "the bound app's own grants, through its client secret; the old secret works until retirement deletes it", "confirmed"
	case "databricks":
		return "the bound service principal's own permissions, through its OAuth secret; the old secret works until retirement deletes it", "confirmed"
	case "openrouter":
		return "model usage on the account up to the role's credit limit, through an API key, until the key is deleted", "confirmed"
	case "fireworks":
		return "the bound user's own permissions on the account, through an API key, until the key is deleted", "confirmed"
	case "litellm":
		return "calls to the role's models through the proxy, through a virtual key, until the key is deleted", "confirmed"
	case "supabase":
		return "the project's secret-key access (it bypasses row-level security), through a secret API key, until the key is deleted", "confirmed"
	case "convex":
		return "the bound deployment's deploy-key actions, through a deploy key, until the key is deleted", "confirmed"
	case "dbt":
		return "the role's one permission set (on its project, or every project), through a service token, until the token is deleted", "confirmed"
	case "cloudflare":
		return "the template token's policies and condition, through a copy of it, until the copy is deleted", "confirmed"
	case "cloudflare-r2":
		return "the template token's R2 policies on the account's buckets, through an S3 key pair, until its token is deleted", "confirmed"
	case "unix":
		return "the local account's own rights on the host (its groups, files and sudo rules), through its password", "confirmed"
	case "windows":
		return "the local account's own rights on the Windows host (its groups and files), through its password", "confirmed"
	case "iosxe":
		return "the device account's own privilege level (or privileged mode, for the enable secret), through its password", "confirmed"
	case "junos":
		return "the device account's own login class, through its password", "confirmed"
	case "eos":
		return "the switch account's own privilege and role (or privileged mode, for the enable password), through its password", "confirmed"
	case "fortigate":
		return "the administrator's own access profile, through its password", "confirmed"
	case "bigip":
		return "the user's own partition roles, through its password", "confirmed"
	case "redfish":
		return "the controller account's own Redfish role, through its password", "confirmed"
	case "esxi":
		return "the host account's own permissions (its roles on the host's inventory), through its password", "confirmed"
	case "vcenter-sso":
		return "the SSO user's own vCenter roles and group memberships, through its password", "confirmed"
	case "okta-user", "entra-user", "google-workspace-user":
		return "the administrator account's own roles in the identity provider, through its password (and its own MFA)", "confirmed"
	case "mssql":
		return "membership of the role's database roles in one database, until the login is disabled, its sessions ended and the login dropped", "confirmed"
	case "azure-sql":
		return "membership of the role's database roles in one contained database, until the user's sessions are ended and the user dropped", "confirmed"
	}
	return "", ""
}

func dynamicSecretProviderLabel(providerType string) string {
	for _, supported := range dynamicSecretSupportedProviders() {
		if supported.Type == providerType {
			return supported.Label
		}
	}
	return providerType
}

func dynamicSecretConfiguredProviderFrom(provider dynsecret.Provider) dynamicSecretConfiguredProvider {
	configured := dynamicSecretConfiguredProvider{
		ID: provider.Name(), Type: provider.Name(), Label: provider.Name(), Ready: true,
		ConfigurationRevision: "embedded:" + provider.Name(),
	}
	if identity, ok := provider.(dynamicSecretProviderReviewIdentity); ok {
		configured.Type = strings.TrimSpace(identity.DynamicSecretProviderType())
		configured.Label = dynamicSecretProviderLabel(configured.Type)
		// The decoy role is not an ordinary role: only the decoy endpoint mints
		// it, so the catalog and the Vault role list never offer it (Q6).
		configured.AllowedRoles = slices.DeleteFunc(append([]string(nil), identity.DynamicSecretAllowedRoles()...),
			func(role string) bool { return role == dynsecret.DecoyRole })
		sort.Strings(configured.AllowedRoles)
		configured.ConfigurationRevision = strings.TrimSpace(identity.DynamicSecretConfigurationRevision())
		configured.Ready = configured.Type != "" && configured.ConfigurationRevision != "" && len(configured.AllowedRoles) > 0
	}
	if bounded, ok := provider.(dynamicSecretMaximumTTL); ok {
		configured.MaximumTTLSeconds = int64(bounded.MaximumTTL() / time.Second)
	}
	_, configured.Revocation = dynamicSecretProviderAuthority(configured.Type)
	if stated, ok := provider.(interface{ DynamicSecretRevocation() string }); ok && stated.DynamicSecretRevocation() != "" {
		configured.Revocation = stated.DynamicSecretRevocation()
	}
	return configured
}

func (s *secretsService) configuredDynamicSecretProviders(tenantID string) []dynamicSecretConfiguredProvider {
	providers := s.dynamicProviders(tenantID)
	out := make([]dynamicSecretConfiguredProvider, 0, len(providers))
	for _, provider := range providers {
		if hidden, ok := provider.(interface{ DynamicSecretHoneyOnly() bool }); ok && hidden.DynamicSecretHoneyOnly() {
			continue
		}
		out = append(out, dynamicSecretConfiguredProviderFrom(provider))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *secretsService) isHoneyOnlyProvider(tenantID, providerID string) bool {
	for _, provider := range s.dynamicProviders(tenantID) {
		if provider.Name() != providerID {
			continue
		}
		hidden, ok := provider.(interface{ DynamicSecretHoneyOnly() bool })
		return ok && hidden.DynamicSecretHoneyOnly()
	}
	return false
}

func (s *secretsService) configuredDynamicSecretProvider(tenantID, id string) (dynamicSecretConfiguredProvider, bool) {
	for _, provider := range s.configuredDynamicSecretProviders(tenantID) {
		if provider.ID == id {
			return provider, true
		}
	}
	return dynamicSecretConfiguredProvider{}, false
}

func normalizeDynamicLeaseIssueRequest(req dynamicLeaseIssueRequest) (dynamicLeaseIssueRequest, error) {
	req.Provider = strings.TrimSpace(req.Provider)
	req.Role = strings.TrimSpace(req.Role)
	req.PreviewFingerprint = strings.TrimSpace(req.PreviewFingerprint)
	if req.Provider == "" || req.Role == "" {
		return dynamicLeaseIssueRequest{}, errStatus(http.StatusBadRequest, "provider and role are required")
	}
	if req.Role == dynsecret.DecoyRole {
		// A decoy login exists only with its watch: mint it through
		// POST /api/v1/secrets/honeytokens/databases (Q6).
		return dynamicLeaseIssueRequest{}, errStatus(http.StatusUnprocessableEntity, "decoy logins are minted only through the decoy endpoint")
	}
	if req.TTLSeconds <= 0 {
		return dynamicLeaseIssueRequest{}, errStatus(http.StatusBadRequest, "ttl_seconds must be positive")
	}
	return req, nil
}

func validateDynamicLeaseProviderRequest(provider dynamicSecretConfiguredProvider, req dynamicLeaseIssueRequest) error {
	if !provider.Ready {
		return errStatus(http.StatusServiceUnavailable, "dynamic secret provider is not ready; repair its startup configuration and restart")
	}
	if len(provider.AllowedRoles) > 0 && !slices.Contains(provider.AllowedRoles, req.Role) {
		return errStatus(http.StatusUnprocessableEntity, "role is not allowed by the configured dynamic secret provider")
	}
	if provider.MaximumTTLSeconds > 0 && int64(req.TTLSeconds) > provider.MaximumTTLSeconds {
		return errStatus(http.StatusUnprocessableEntity, "ttl_seconds exceeds the configured provider maximum")
	}
	if provider.Type == "kubernetes" && req.TTLSeconds < 600 {
		return errStatus(http.StatusUnprocessableEntity, "Kubernetes token leases require at least 600 seconds")
	}
	if (provider.Type == "aws-iam" || provider.Type == "aws-sts") && req.TTLSeconds < 900 {
		return errStatus(http.StatusUnprocessableEntity, "AWS STS sessions require at least 900 seconds")
	}
	return nil
}

func (a *API) dynamicSecretPreviewFingerprint(tenantID, principal string, provider dynamicSecretConfiguredProvider, req dynamicLeaseIssueRequest) (string, error) {
	macFn := a.ephemeralAPIKeyCommandMAC()
	if macFn == nil {
		return "", errors.New("api: server-keyed dynamic-secret preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain                string `json:"domain"`
		TenantID              string `json:"tenant_id"`
		Principal             string `json:"principal"`
		Operation             string `json:"operation"`
		ProviderID            string `json:"provider_id"`
		ProviderType          string `json:"provider_type"`
		ConfigurationRevision string `json:"configuration_revision"`
		Role                  string `json:"role"`
		TTLSeconds            int    `json:"ttl_seconds"`
	}{
		Domain: dynamicSecretReviewDomain, TenantID: tenantID, Principal: principal,
		Operation: "issue_dynamic_secret_lease", ProviderID: provider.ID, ProviderType: provider.Type,
		ConfigurationRevision: provider.ConfigurationRevision, Role: req.Role, TTLSeconds: req.TTLSeconds,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := macFn([]byte(dynamicSecretReviewDomain), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: dynamic-secret preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

func (a *API) listDynamicSecretProviders(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	configured := a.secrets.configuredDynamicSecretProviders(tenantID)
	blockers := []string{}
	if len(configured) == 0 {
		blockers = append(blockers, "No dynamic-secret provider is attached to this tenant. Add one startup configuration entry, then restart and review again.")
	}
	a.writeJSON(w, http.StatusOK, dynamicSecretProviderCatalogResponse{
		Capability: "F65", ConfigurationMode: "startup_static", ConfigurationChangesRestart: true,
		SecretDelivery: "file_or_secret_reference", SupportedProviders: dynamicSecretSupportedProviders(),
		ConfiguredProviders: configured, Blockers: blockers,
		DocumentationPath: "/docs/features/secrets#dynamic-secrets-f65-and-pki-as-a-secrets-engine-f67",
		DataHandling:      "The catalog returns provider IDs, types, allowed role names, TTL ceilings, and requirement names only. Endpoint values, provider-native role bindings, credential references, and credential bytes never enter this response or browser state.",
	})
}

// previewDynamicSecretLease validates the exact configured provider identity,
// role, and TTL without constructing a backend, resolving a credential reference,
// appending an event, recording idempotency, enqueueing outbox work, or calling a
// provider.
func (a *API) previewDynamicSecretLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	var req dynamicLeaseIssueRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.PreviewFingerprint = ""
	req, err = normalizeDynamicLeaseIssueRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	provider, found := a.secrets.configuredDynamicSecretProvider(tenantID, req.Provider)
	if !found {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "dynamic secret provider is not configured for this tenant"))
		return
	}
	if err := validateDynamicLeaseProviderRequest(provider, req); err != nil {
		a.writeError(w, err)
		return
	}
	fingerprint, err := a.dynamicSecretPreviewFingerprint(tenantID, principal, provider, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	recoverySteps := []string{
		"Before issuance, cancel and leave the provider and trstctl unchanged.",
		"After an interrupted issue response, retry the unchanged request with the same Idempotency-Key to recover the original result without creating a second provider credential.",
		"Revoke the lease from its metadata receipt; the durable worker keeps retrying provider revocation after a restart.",
	}
	verificationSteps := []string{
		"Use the reveal-once credential directly against the reviewed provider and role.",
		"Read the lease metadata and confirm provider, role, active state, and expiry without replaying the credential.",
		"Revoke the lease, then prove the same credential no longer authenticates to the provider.",
	}
	externalEffect := "the bounded dynamic-secret worker asks " + provider.Label + " to create one scoped credential for role " + req.Role
	if provider.Type == "aws-sts" || provider.Type == "aws-iam" {
		externalEffect = "the bounded dynamic-secret worker submits one STS AssumeRole request for the configured IAM role ARN"
		recoverySteps = []string{
			"Before issuance, cancel and leave AWS and trstctl unchanged.",
			"If the response was interrupted after a saved STS result, retry the unchanged request with the same Idempotency-Key to recover it.",
			"If AWS accepted AssumeRole but its response was lost, the result is indeterminate; trstctl refuses to submit that operation again. Inspect AWS CloudTrail and issue a new lease only after reconciliation.",
			"Revoke closes the trstctl lease. The AWS session can remain valid until native_expires_at; rotate the dependent workload promptly.",
		}
		verificationSteps = []string{
			"Use the reveal-once access key ID, secret access key, and session token with an AWS stock client against the reviewed role.",
			"Read the lease metadata and compare native_expires_at with the STS credential expiration.",
			"After revoke, confirm the trstctl lease is closed and treat the AWS session as valid until native_expires_at; verify rejection after native expiry with an AWS stock client.",
		}
	}
	a.writeJSON(w, http.StatusOK, dynamicLeasePreviewResponse{
		Capability: "F65", Operation: "issue_dynamic_secret_lease", Ready: true, EffectFree: true,
		ProviderID: provider.ID, ProviderType: provider.Type, ProviderLabel: provider.Label, Role: req.Role,
		RequestedTTLSeconds: int64(req.TTLSeconds), EffectiveTTLSeconds: int64(req.TTLSeconds),
		MaximumTTLSeconds: provider.MaximumTTLSeconds, ConfigurationRevision: provider.ConfigurationRevision,
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint, Blockers: []string{},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"append one tenant-scoped pending lease event and project its metadata",
			"seal one provider command into the durable outbox before provider contact",
			"protect the reveal-once response for exact Idempotency-Key recovery",
		},
		ExecuteExternalEffects: []string{externalEffect},
		RecoverySteps:          recoverySteps,
		VerificationSteps:      verificationSteps,
		CLIArgv:                []string{"trstctl", "secrets", "leases", "preview", "-f", "dynamic-lease.json"},
		DataHandling:           "Preview never resolves or receives provider credentials. Issue returns the generated credential once; only sealed recovery state and non-secret lease/provider handles remain. Never place the generated credential in URLs, logs, screenshots, or browser storage.",
	})
}
