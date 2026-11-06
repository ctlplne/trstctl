// SPDX-License-Identifier: BUSL-1.1
package azureiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var envName = regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var armPath = regexp.MustCompile(`^/[A-Za-z0-9_.()/-]{1,1000}$`)

func DecodeConfig(raw []byte) (Config, error) {
	var cfg Config
	if len(raw) > 64<<10 {
		return cfg, errors.New("azure inventory configuration exceeds bound")
	}
	if err := bearerhttp.DecodeJSON(raw, &cfg); err != nil {
		return cfg, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return cfg, errors.New("invalid Azure configuration object")
	}
	allowed := map[string]bool{"azure_tenant_id": true, "subscription_id": true, "service_principal_ids": true, "graph_token_file_ref": true, "arm_token_file_ref": true, "graph_endpoint": true, "arm_endpoint": true, "read_beta_signins": true, "activity_lookback_days": true, "managed_identity_resources": true, "ca_pem": true, "allow_private_endpoint": true, "private_egress_cidrs": true}
	for name := range fields {
		if !allowed[name] {
			return cfg, errors.New("unknown or alternate-case Azure inventory field")
		}
	}
	if !uuid.MatchString(cfg.TenantID) || !uuid.MatchString(cfg.SubscriptionID) || !envName.MatchString(cfg.GraphTokenFileRef) || !envName.MatchString(cfg.ARMTokenFileRef) || cfg.GraphTokenFileRef == cfg.ARMTokenFileRef || len(cfg.PrincipalIDs) < 1 || len(cfg.PrincipalIDs) > 64 {
		return cfg, errors.New("azure inventory requires tenant/subscription UUIDs, distinct approved Graph/ARM file references and 1..64 principal UUIDs")
	}
	seen := map[string]bool{}
	for _, id := range cfg.PrincipalIDs {
		if !uuid.MatchString(id) || seen[id] {
			return cfg, errors.New("invalid or duplicate Azure principal UUID")
		}
		seen[id] = true
	}
	if cfg.ActivityLookbackDays < 0 || cfg.ActivityLookbackDays > 30 || cfg.ReadBetaSignins != (cfg.ActivityLookbackDays > 0) || len(cfg.CAPEM) > 64<<10 || len(cfg.PrivateEgressCIDRs) > 32 || len(cfg.ManagedIdentityResources) > 64 {
		return cfg, errors.New("azure activity, trust or resource bound exceeded; beta activity requires explicit opt-in and 1..30 days")
	}
	for id, path := range cfg.ManagedIdentityResources {
		if !seen[id] || !managedResource(path, cfg.SubscriptionID) {
			return cfg, errors.New("managed identity resource must bind a selected principal in this subscription")
		}
	}
	if len(cfg.PrivateEgressCIDRs) > 0 && !cfg.AllowPrivateEndpoint {
		return cfg, errors.New("private CIDRs require explicit private endpoint opt-in")
	}
	for _, raw := range cfg.PrivateEgressCIDRs {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			return cfg, err
		}
	}
	cfg = Defaults(cfg)
	for _, endpoint := range Endpoints(cfg) {
		if _, err := bearerhttp.New(bearerhttp.Config{Endpoint: endpoint, AllowInsecureLoopback: cfg.AllowPrivateEndpoint, UseToken: func(context.Context, func([]byte) error) error { return errors.New("validation only") }}); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}
func Defaults(cfg Config) Config {
	if cfg.GraphEndpoint == "" {
		cfg.GraphEndpoint = "https://graph.microsoft.com"
	}
	if cfg.ARMEndpoint == "" {
		cfg.ARMEndpoint = "https://management.azure.com"
	}
	return cfg
}
func Endpoints(cfg Config) []string {
	cfg = Defaults(cfg)
	return []string{cfg.GraphEndpoint, cfg.ARMEndpoint}
}
func Fingerprint(v Inventory) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}
func SourceFingerprint(cfg Config) (string, error) {
	raw, err := json.Marshal(Defaults(cfg))
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}
func DecodeInventory(raw []byte) (Inventory, error) {
	var v Inventory
	if len(raw) > 512<<10 {
		return v, errors.New("azure inventory record exceeds bound")
	}
	if err := bearerhttp.DecodeJSON(raw, &v); err != nil {
		return v, err
	}
	if err := validateInventory(v); err != nil {
		return v, err
	}
	return v, nil
}
func validateInventory(v Inventory) error {
	if v.Version != 1 || v.Provider != "azure-entra" || !uuid.MatchString(v.TenantID) || !uuid.MatchString(v.SubscriptionID) || !uuid.MatchString(v.Identity.ID) || !uuid.MatchString(v.Identity.AppID) || (v.Identity.Type != "Application" && v.Identity.Type != "ManagedIdentity") || v.SourceOrigin == "" || len(v.SourceFingerprint) != 64 || v.CollectedAt.IsZero() {
		return errors.New("invalid typed Azure workload identity")
	}
	if err := validateCredentials(v.Identity.Keys, v.Identity.Passwords, v.CollectedAt); err != nil {
		return err
	}
	if len(v.AppRoles) > 2000 || len(v.RBAC) > 2000 || len(v.Federation) > 100 {
		return errors.New("azure binding record exceeds bound")
	}
	for _, r := range v.AppRoles {
		if (len(r.ID) < 1 || len(r.ID) > 256) || r.PrincipalID != v.Identity.ID || !uuid.MatchString(r.ResourceID) || !uuid.MatchString(r.RoleID) {
			return errors.New("native app-role principal identity mismatch")
		}
	}
	for _, r := range v.RBAC {
		if r.Properties.PrincipalID != v.Identity.ID || !validScope(r.Properties.Scope, v.SubscriptionID) || !roleDefinition(r.Properties.RoleDefinitionID) || !armPath.MatchString(r.ID) || len(r.Permissions) > 100 {
			return errors.New("native Azure RBAC identity mismatch")
		}
	}
	for _, f := range v.Federation {
		if (len(f.ID) < 1 || len(f.ID) > 2048) || len(f.Name) > 256 || len(f.Issuer) > 2048 || len(f.Subject) > 2048 || len(f.Audiences) > 10 {
			return errors.New("invalid bounded Azure federation")
		}
	}
	return nil
}
func prefixes(cfg Config) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range cfg.PrivateEgressCIDRs {
		if p, err := netsec.ParseEgressAllowPrefix(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}
func validScope(scope, subscription string) bool {
	return !strings.Contains(scope, "..") && !strings.Contains(scope, "//") && armPath.MatchString(scope) && (scope == "/subscriptions/"+subscription || strings.HasPrefix(scope, "/subscriptions/"+subscription+"/") || scope == "/" || strings.HasPrefix(scope, "/providers/Microsoft.Management/managementGroups/"))
}
func roleDefinition(path string) bool {
	p := strings.Split(path, "/")
	n := len(p)
	return armPath.MatchString(path) && n >= 5 && p[n-4] == "providers" && p[n-3] == "Microsoft.Authorization" && p[n-2] == "roleDefinitions" && uuid.MatchString(p[n-1]) && !strings.Contains(path, "//") && !strings.Contains(path, "..")
}
func managedResource(path, subscription string) bool {
	p := strings.Split(path, "/")
	return armPath.MatchString(path) && len(p) == 9 && p[1] == "subscriptions" && p[2] == subscription && p[3] == "resourceGroups" && p[4] != "" && p[5] == "providers" && p[6] == "Microsoft.ManagedIdentity" && p[7] == "userAssignedIdentities" && p[8] != "" && !strings.Contains(path, "..")
}
