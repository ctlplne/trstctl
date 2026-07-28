// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

// SecretIntegrationsConfig is the operator-owned, tenant-bound configuration for
// dynamic-secret issuers and outbound secret-sync targets.  It deliberately holds
// references to credentials, never credential bytes.  A reference is resolved at
// delivery time so authority-bearing material is not retained by the process-wide
// registry.
type SecretIntegrationsConfig struct {
	DynamicProviders []DynamicSecretProviderConfig `json:"dynamic_providers,omitempty"`
	SyncTargets      []SecretSyncTargetConfig      `json:"sync_targets,omitempty"`
}

// DynamicSecretProviderConfig configures one named provider for exactly one
// tenant. Type is one of the eight built-ins. Fields not used by that type must be
// left empty; validation rejects incomplete entries before the server starts.
type DynamicSecretProviderConfig struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`
	Type     string `json:"type"`

	Endpoint          string `json:"endpoint,omitempty"`
	AdminDSNRef       string `json:"admin_dsn_ref,omitempty"`
	Database          string `json:"database,omitempty"`
	Schema            string `json:"schema,omitempty"`
	Addr              string `json:"addr,omitempty"`
	AccountHost       string `json:"account_host,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Region            string `json:"region,omitempty"`
	AccessKeyID       string `json:"access_key_id,omitempty"`
	Project           string `json:"project,omitempty"`
	ServiceAccount    string `json:"service_account,omitempty"`
	ApplicationObject string `json:"application_object_id,omitempty"`
	ApplicationClient string `json:"application_client_id,omitempty"`
	AzureTenant       string `json:"azure_tenant_id,omitempty"`
	DB                int    `json:"db,omitempty"`
	UsernamePrefix    string `json:"username_prefix,omitempty"`

	PasswordRef     string   `json:"password_ref,omitempty"`
	SecretAccessRef string   `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef string   `json:"session_token_ref,omitempty"`
	BearerTokenRef  string   `json:"bearer_token_ref,omitempty"`
	AllowedRoles    []string `json:"allowed_roles"`
	// RoleBindings maps an allowed role to its provider-native authority. AWS
	// values are managed-policy ARNs; Kubernetes values are Role/name or
	// ClusterRole/name. Fixed-authority providers may omit it.
	RoleBindings          map[string]string `json:"role_bindings,omitempty"`
	MaxTTL                string            `json:"max_ttl,omitempty"`
	AllowPrivate          bool              `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback bool              `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs    []string          `json:"private_egress_cidrs,omitempty"`
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

	TokenRef        string `json:"token_ref,omitempty"`
	SecretAccessRef string `json:"secret_access_key_ref,omitempty"`
	SessionTokenRef string `json:"session_token_ref,omitempty"`
	// AWSWorkloadIdentity explicitly opts this target into tenant-authored
	// short-lived AWS STS credentials. It is false by default. When true, static
	// AWS access-key fields are forbidden and the bounded secret-sync outbox
	// worker is the only component allowed to use WorkloadIdentityEndpoint.
	AWSWorkloadIdentity                   bool     `json:"aws_workload_identity,omitempty"`
	GCPWorkloadIdentity                   bool     `json:"gcp_workload_identity,omitempty"`
	WorkloadIdentityEndpoint              string   `json:"workload_identity_endpoint,omitempty"`
	WorkloadIdentityImpersonationEndpoint string   `json:"workload_identity_impersonation_endpoint,omitempty"`
	AllowPrivate                          bool     `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback                 bool     `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs                    []string `json:"private_egress_cidrs,omitempty"`
}

var dynamicSecretTypes = map[string]struct{}{
	"postgresql": {}, "mysql": {}, "mongodb": {}, "aws-iam": {},
	"gcp-iam": {}, "azure-entra": {}, "kubernetes": {}, "redis": {},
}

var secretSyncTypes = map[string]struct{}{
	"aws-secrets-manager": {}, "gcp-secret-manager": {}, "azure-key-vault": {},
	"github-actions": {}, "gitlab-ci": {}, "vercel": {},
	"generic-ci-json": {}, "kubernetes-secrets": {},
	"terraform-cloud-opentofu": {}, "vault-kv-v2": {},
}

// ValidateSecretIntegrations is exported for config-focused tests and embedders.
// Config.Validate calls the package-local twin from config.go's validator list.
func ValidateSecretIntegrations(cfg SecretIntegrationsConfig, secretsEnabled bool) error {
	return errors.Join(validateSecretIntegrations(cfg, secretsEnabled)...)
}

func validateSecretIntegrations(cfg SecretIntegrationsConfig, secretsEnabled bool) []error {
	var errs []error
	if !secretsEnabled && (len(cfg.DynamicProviders) > 0 || len(cfg.SyncTargets) > 0) {
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
	return errs
}

func validateDynamicProvider(where string, c DynamicSecretProviderConfig) []error {
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
	switch c.Type {
	case "postgresql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
	case "mysql":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		require(c.Database, "database")
		require(c.Addr, "addr")
	case "mongodb":
		ref(c.AdminDSNRef, "admin_dsn_ref", false)
		require(c.Database, "database")
	case "redis":
		require(c.Addr, "addr")
		ref(c.PasswordRef, "password_ref", true)
	case "kubernetes":
		require(c.Endpoint, "endpoint")
		require(c.Namespace, "namespace")
		ref(c.BearerTokenRef, "bearer_token_ref", false)
		for _, role := range normalizedStrings(c.AllowedRoles) {
			binding := strings.TrimSpace(c.RoleBindings[role])
			if !strings.HasPrefix(binding, "Role/") && !strings.HasPrefix(binding, "ClusterRole/") {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be Role/name or ClusterRole/name", where, role))
			}
		}
	case "aws-iam":
		require(c.Endpoint, "endpoint")
		require(c.Region, "region")
		require(c.AccessKeyID, "access_key_id")
		ref(c.SecretAccessRef, "secret_access_key_ref", false)
		ref(c.SessionTokenRef, "session_token_ref", true)
		for _, role := range normalizedStrings(c.AllowedRoles) {
			if !strings.HasPrefix(strings.TrimSpace(c.RoleBindings[role]), "arn:") {
				errs = append(errs, fmt.Errorf("%s role_bindings[%q] must be a managed-policy ARN", where, role))
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
		ref(c.TokenRef, "token_ref", false)
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
		if _, err := netip.ParsePrefix(raw); err != nil {
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
