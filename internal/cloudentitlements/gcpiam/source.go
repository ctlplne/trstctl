// SPDX-License-Identifier: BUSL-1.1
package gcpiam

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

var projectName = regexp.MustCompile(`^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$`)
var accountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,126}@[a-z0-9][a-z0-9.-]{0,190}\.gserviceaccount\.com$`)
var envName = regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var roleName = regexp.MustCompile(`^(?:roles/[A-Za-z0-9_.]{1,128}|(?:projects/[a-z0-9-]{1,30}|organizations/[0-9]{1,20})/roles/[A-Za-z0-9_.]{1,64})$`)

func DecodeConfig(raw []byte) (Config, error) {
	var cfg Config
	if len(raw) > 64<<10 {
		return cfg, errors.New("GCP inventory configuration exceeds bound")
	}
	if err := bearerhttp.DecodeJSON(raw, &cfg); err != nil {
		return cfg, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return cfg, errors.New("invalid GCP inventory object")
	}
	allowed := map[string]bool{"project": true, "service_accounts": true, "token_file_ref": true, "iam_endpoint": true, "resource_manager_endpoint": true, "logging_endpoint": true, "activity_lookback_days": true, "ca_pem": true, "allow_private_endpoint": true, "private_egress_cidrs": true}
	for name := range fields {
		if !allowed[name] {
			return cfg, errors.New("unknown or alternate-case GCP inventory field")
		}
	}
	if !projectName.MatchString(cfg.Project) || !envName.MatchString(cfg.TokenFileRef) || len(cfg.ServiceAccounts) == 0 || len(cfg.ServiceAccounts) > 64 {
		return cfg, errors.New("GCP inventory requires a project, approved token-file env reference and 1..64 selected accounts")
	}
	seen := map[string]bool{}
	for _, email := range cfg.ServiceAccounts {
		if !accountName.MatchString(email) || seen[email] {
			return cfg, errors.New("invalid or duplicate GCP service-account email")
		}
		seen[email] = true
	}
	if cfg.ActivityLookbackDays < 0 || cfg.ActivityLookbackDays > 90 || len(cfg.CAPEM) > 64<<10 || len(cfg.PrivateEgressCIDRs) > 32 {
		return cfg, errors.New("GCP inventory trust, activity or egress bound exceeded")
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
	if cfg.IAMEndpoint == "" {
		cfg.IAMEndpoint = "https://iam.googleapis.com"
	}
	if cfg.ResourceManagerEndpoint == "" {
		cfg.ResourceManagerEndpoint = "https://cloudresourcemanager.googleapis.com"
	}
	if cfg.LoggingEndpoint == "" {
		cfg.LoggingEndpoint = "https://logging.googleapis.com"
	}
	return cfg
}
func Endpoints(cfg Config) []string {
	cfg = Defaults(cfg)
	out := []string{cfg.IAMEndpoint, cfg.ResourceManagerEndpoint}
	if cfg.ActivityLookbackDays > 0 {
		out = append(out, cfg.LoggingEndpoint)
	}
	return out
}
func Fingerprint(value Inventory) (string, error) {
	raw, err := json.Marshal(value)
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
		return v, errors.New("GCP inventory record exceeds bound")
	}
	if err := bearerhttp.DecodeJSON(raw, &v); err != nil {
		return v, err
	}
	if v.Version != 1 || v.Provider != "gcp-iam" || !accountName.MatchString(v.Identity.Email) || !digits(v.Identity.NativeID) || v.SourceOrigin == "" || v.CollectedAt.IsZero() || len(v.SourceFingerprint) != 64 || !projectName.MatchString(v.Identity.Project) {
		return v, errors.New("invalid typed GCP inventory")
	}
	if err := validateKeys(v.Keys, v.Identity.Project, v.Identity.Email, v.Identity.NativeID, v.CollectedAt); err != nil {
		return v, err
	}
	if len(v.PolicyBindings) > 2000 {
		return v, errors.New("GCP binding record exceeds bound")
	}
	for _, binding := range v.PolicyBindings {
		if binding.Scope != "projects/"+v.Identity.Project || !roleName.MatchString(binding.Role) || len(binding.Permissions) > 10000 {
			return v, errors.New("invalid GCP project role binding record")
		}
	}
	return v, nil
}
func digits(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) < 0
}
func prefixes(cfg Config) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cfg.PrivateEgressCIDRs))
	for _, raw := range cfg.PrivateEgressCIDRs {
		if p, err := netsec.ParseEgressAllowPrefix(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}
