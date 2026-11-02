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
	// is ttl_only, A239).
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
	providers := []dynamicSecretSupportedProvider{
		{Type: "postgresql", Label: "PostgreSQL", Purpose: "Creates and drops a scoped PostgreSQL login role.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin DSN reference", "Credential reference containing the least-privilege administrative DSN.", true),
			value("database", "Database", "Optional database placed in the generated connection result.", false),
			value("schema", "Schema", "Optional schema granted to the generated role.", false),
		)},
		{Type: "mysql", Label: "MySQL / MariaDB", Purpose: "Creates and drops a scoped MySQL account.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin DSN reference", "Credential reference containing the least-privilege administrative DSN.", true),
			value("addr", "Client address", "Host and port applications use for the generated account.", true),
			value("database", "Database", "Database granted to the generated account.", true),
			value("account_host", "Account host", "Required MySQL client host or network matcher; never defaults to %.", true),
			value("allow_wildcard_account_host", "Wildcard account host opt-in", "Required to use % or _ in account_host; review the matched client range before enabling.", false),
		)},
		{Type: "mongodb", Label: "MongoDB", Purpose: "Creates and drops a scoped MongoDB database user.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Admin URI reference", "Credential reference containing the least-privilege administrative MongoDB URI.", true),
			value("database", "Database", "Database in which the generated user is created.", true),
		)},
		{Type: "aws-sts", Label: "AWS STS", Purpose: "Assumes a bounded IAM role and returns an expiring AWS session. Early lease revocation remains pending until AWS session expiry.", Requirements: dynamicSecretAWSRequirements(
			value("endpoint", "STS endpoint", "HTTPS AWS STS Query API endpoint.", true),
			value("region", "AWS region", "Region used to sign STS requests.", true),
			value("access_key_id", "Caller access key ID", "Identifier of the identity allowed to call STS AssumeRole.", true),
			credential("secret_access_key_ref", "Caller secret access key reference", "AWS caller secret reference, resolved only during issuance.", true),
			credential("session_token_ref", "Caller session token reference", "Required when the caller itself uses temporary AWS credentials.", false),
			roles("Each allowed role maps to one full IAM role ARN trusted to allow sts:AssumeRole."),
		)},
		{Type: "aws-iam", Label: "AWS STS (legacy aws-iam name)", Purpose: "Compatibility name for the same expiring AssumeRole session issuer; IAM user access keys are not created.", Requirements: dynamicSecretAWSRequirements(
			value("endpoint", "STS endpoint", "HTTPS AWS STS Query API endpoint.", true),
			value("region", "AWS region", "Region used to sign STS requests.", true),
			value("access_key_id", "Caller access key ID", "Identifier of the identity allowed to call STS AssumeRole.", true),
			credential("secret_access_key_ref", "Caller secret access key reference", "AWS caller secret reference, resolved only during issuance.", true),
			credential("session_token_ref", "Caller session token reference", "Required when the caller itself uses temporary AWS credentials.", false),
			roles("Each allowed role maps to one full IAM role ARN trusted to allow sts:AssumeRole."),
		)},
		{Type: "gcp-iam", Label: "Google Cloud IAM", Purpose: "Creates and deletes a service-account key with a stable retry identity.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "IAM endpoint", "HTTPS Google IAM API endpoint.", true),
			value("project", "Project", "Google Cloud project that owns the service account.", true),
			value("service_account", "Service account", "Email of the narrowly scoped service account.", true),
			credential("bearer_token_ref", "Bearer token reference", "Short-lived Google access-token reference.", true),
		)},
		{Type: "azure-entra", Label: "Azure Entra", Purpose: "Creates and deletes an application credential in Microsoft Graph.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Graph endpoint", "HTTPS Microsoft Graph endpoint.", true),
			value("application_object_id", "Application object ID", "Object ID of the application receiving the temporary credential.", true),
			value("application_client_id", "Application client ID", "Client ID returned with the generated credential.", true),
			value("azure_tenant_id", "Azure tenant ID", "Entra tenant containing the application.", true),
			credential("bearer_token_ref", "Bearer token reference", "Short-lived Microsoft Graph token reference.", true),
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
		{Type: "ldap", Label: "LDAP directory", Purpose: "Creates a directory entry whose password the directory sets and hashes, in the role's group, and deletes it at revocation; the directory then refuses its bind.", Requirements: dynamicSecretProviderRequirements(
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
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it.", false),
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
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it.", false),
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
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it.", false),
			roles(`Each allowed role maps to "<operations> on <resources>" clauses separated by ";", for example "read,describe on topic:orders; read on group:orders-app"; a name ending in * is a prefix.`),
		)},
		{Type: "couchbase", Label: "Couchbase users", Purpose: "Creates a local Couchbase user with a generated password and only its role's roles on the named buckets through the management REST API, and deletes it at revocation; Couchbase then refuses its next request.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "Management REST API", "HTTPS URL of the cluster's management REST API (port 18091).", true),
			value("admin_user", "Administrator", "A user allowed to create and delete local users (Full Admin or Security Admin).", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever deletes users with it.", false),
			roles(`Each allowed role maps to "<roles> on <buckets>", for example "bucket_full_access on orders" (the Community Edition's data role) or "data_reader,query_select on orders".`),
		)},
		{Type: "milvus", Label: "Milvus users", Purpose: "Creates a Milvus user with a generated password and only its role's Milvus roles through the RESTful API, and drops it at revocation; Milvus then refuses its next request.", Requirements: dynamicSecretProviderRequirements(
			value("endpoint", "RESTful API", "HTTPS URL of the Milvus proxy's RESTful API (port 19530).", true),
			value("admin_user", "Administrator", "A Milvus user allowed to create and drop users and grant roles, such as root.", true),
			credential("password_ref", "Administrator password reference", "The administrator's password.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it.", false),
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
		{Type: "mssql", Label: "SQL Server logins", Purpose: "Creates a SQL Server login with a generated password and a user in the configured database that joins the role's database roles, and at revocation disables the login, ends its open sessions and drops the user and login; SQL Server then refuses its login.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator DSN reference", "sqlserver:// DSN of a login allowed to manage logins and users, end sessions (ALTER ANY CONNECTION) and add role members in the database.", true),
			value("database", "Database", "The database leased logins get a user and role memberships in.", true),
			value("username_prefix", "Login name prefix", "Optional prefix of leased logins (default trstctl); revocation only ever drops principals with it.", false),
			roles(`Each allowed role maps to database roles, comma separated, for example "db_datareader".`),
		)},
		{Type: "azure-sql", Label: "Azure SQL contained users", Purpose: "Creates a contained database user with a generated password that joins the role's database roles, and at revocation ends its open sessions and drops it; the database then refuses its login. Proven against SQL Server's contained database users; no Azure proof yet.", Requirements: dynamicSecretProviderRequirements(
			credential("admin_dsn_ref", "Administrator DSN reference", "sqlserver:// DSN of a user in the database allowed to manage users, add role members and end sessions.", true),
			value("database", "Database", "The (contained) database the leased users live in.", true),
			value("username_prefix", "User name prefix", "Optional prefix of leased users (default trstctl); revocation only ever drops users with it.", false),
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
		return "CONNECT on the configured database and USAGE on its schema, with SELECT on its tables for a role whose name contains \"read\", else SELECT, INSERT, UPDATE and DELETE", "confirmed"
	case "mysql":
		return "SELECT on the configured database for a role whose name contains \"read\", else SELECT, INSERT, UPDATE and DELETE, from the configured account host only", "confirmed"
	case "mongodb":
		return "read on the configured database for a role whose name contains \"read\", else readWrite", "confirmed"
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
		return "membership of the role's directory group", "confirmed"
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
	case "couchbase":
		return "the role's Couchbase roles on the named buckets, until the user is deleted", "confirmed"
	case "milvus":
		return "the privileges of the Milvus roles the lease role is bound to, until the user is dropped", "confirmed"
	case "github-app":
		return "the role's repository permissions on the named repositories, through an installation token ended at revocation or by GitHub an hour after minting", "confirmed"
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
