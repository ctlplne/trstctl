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
	Type         string                             `json:"type"`
	Label        string                             `json:"label"`
	Purpose      string                             `json:"purpose"`
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
	return []dynamicSecretSupportedProvider{
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
	}
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
		configured.AllowedRoles = append([]string(nil), identity.DynamicSecretAllowedRoles()...)
		sort.Strings(configured.AllowedRoles)
		configured.ConfigurationRevision = strings.TrimSpace(identity.DynamicSecretConfigurationRevision())
		configured.Ready = configured.Type != "" && configured.ConfigurationRevision != "" && len(configured.AllowedRoles) > 0
	}
	if bounded, ok := provider.(dynamicSecretMaximumTTL); ok {
		configured.MaximumTTLSeconds = int64(bounded.MaximumTTL() / time.Second)
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
