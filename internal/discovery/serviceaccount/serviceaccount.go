// Package serviceaccount normalizes metadata-only Active Directory and cloud
// service-account inventory into discovery findings. It never accepts password,
// token, private-key, or key-file bodies; callers provide public identifiers,
// owner/scope metadata, and credential references only.
package serviceaccount

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// SourceKind is the served discovery source kind for CAP-NHI-03.
	SourceKind = "service_account"
	// FindingKind is the read-model kind emitted for service-account inventory.
	FindingKind = "service_account"
	// MaxAccounts caps one served source config so a single run cannot exhaust the
	// discovery worker lane.
	MaxAccounts = 10000
)

var requiredSurfaces = []string{"ad", "cloud"}

// Config is the source configuration persisted for service-account discovery.
// Accounts are metadata-only references exported from AD/LDAP, Entra ID, IAM, or
// cloud identity inventories.
type Config struct {
	Accounts []Account `json:"accounts"`
}

// Account is one discovered service account. AccountID, Provider, Directory, and
// Principal are public identity references; CredentialRefs may name where
// credentials live but must never carry credential bodies.
type Account struct {
	Surface        string   `json:"surface"`
	Provider       string   `json:"provider"`
	Directory      string   `json:"directory,omitempty"`
	AccountID      string   `json:"account_id"`
	Principal      string   `json:"principal"`
	DisplayName    string   `json:"display_name,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	Enabled        *bool    `json:"enabled,omitempty"`
	Privileged     bool     `json:"privileged,omitempty"`
	LastUsed       string   `json:"last_used,omitempty"`
	CreatedAt      string   `json:"created_at,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	CredentialRefs []string `json:"credential_refs,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// Surfaces returns the CAP-NHI-03 denominator in stable order.
func Surfaces() []string {
	return append([]string(nil), requiredSurfaces...)
}

// Findings decodes, validates, and normalizes a source config into service-account
// findings. It requires at least one AD/on-prem account and one cloud account, so a
// served source cannot claim AD/cloud category coverage from only one side.
func Findings(raw json.RawMessage) ([]Finding, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode service-account discovery config: %w", err)
	}
	if len(cfg.Accounts) == 0 {
		return nil, errors.New("service-account discovery requires accounts")
	}
	if len(cfg.Accounts) > MaxAccounts {
		return nil, fmt.Errorf("service-account discovery source has %d accounts; maximum is %d", len(cfg.Accounts), MaxAccounts)
	}

	out := make([]Finding, 0, len(cfg.Accounts))
	seenSurfaces := map[string]bool{}
	for i, acct := range cfg.Accounts {
		finding, surface, err := normalizeAccount(acct)
		if err != nil {
			return nil, fmt.Errorf("service account %d: %w", i, err)
		}
		seenSurfaces[surface] = true
		out = append(out, finding)
	}
	for _, surface := range requiredSurfaces {
		if !seenSurfaces[surface] {
			return nil, fmt.Errorf("service-account discovery requires at least one %s account", surface)
		}
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeAccount(acct Account) (Finding, string, error) {
	surface := normalizeSurface(acct.Surface)
	if !isRequiredSurface(surface) {
		return Finding{}, "", fmt.Errorf("surface %q must be one of %s", acct.Surface, strings.Join(requiredSurfaces, ", "))
	}
	provider := strings.TrimSpace(acct.Provider)
	accountID := strings.TrimSpace(acct.AccountID)
	principal := strings.TrimSpace(acct.Principal)
	if provider == "" || accountID == "" || principal == "" {
		return Finding{}, "", errors.New("provider, account_id, and principal are required")
	}
	directory := strings.TrimSpace(acct.Directory)
	provenance := SourceKind + ":" + surface + ":" + provider + ":" + nonempty(directory, "_") + ":" + accountID
	meta := map[string]any{
		"capability":      "CAP-NHI-03",
		"surface":         surface,
		"provider":        provider,
		"directory":       directory,
		"account_id":      accountID,
		"principal":       principal,
		"display_name":    strings.TrimSpace(acct.DisplayName),
		"owner":           strings.TrimSpace(acct.Owner),
		"environment":     strings.TrimSpace(acct.Environment),
		"enabled":         acct.Enabled,
		"privileged":      acct.Privileged,
		"last_used":       strings.TrimSpace(acct.LastUsed),
		"created_at":      strings.TrimSpace(acct.CreatedAt),
		"groups":          cleaned(acct.Groups),
		"roles":           cleaned(acct.Roles),
		"credential_refs": cleaned(acct.CredentialRefs),
		"tags":            cleaned(acct.Tags),
	}
	return Finding{
		Ref:         principal,
		Provenance:  provenance,
		Fingerprint: provenance,
		RiskScore:   riskScore(acct),
		Metadata:    meta,
	}, surface, nil
}

func normalizeSurface(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "_")
	switch s {
	case "active_directory", "ldap", "on_prem", "on_premise", "on_premises":
		return "ad"
	case "cloud_iam", "iam":
		return "cloud"
	default:
		return s
	}
}

func isRequiredSurface(surface string) bool {
	for _, allowed := range requiredSurfaces {
		if surface == allowed {
			return true
		}
	}
	return false
}

func cleaned(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func riskScore(acct Account) int {
	score := 30
	if strings.TrimSpace(acct.Owner) == "" {
		score += 20
	}
	if acct.Privileged {
		score += 25
	}
	if len(cleaned(acct.CredentialRefs)) > 1 {
		score += 10
	}
	if len(cleaned(acct.Groups))+len(cleaned(acct.Roles)) > 5 {
		score += 10
	}
	if acct.Enabled != nil && !*acct.Enabled {
		score -= 10
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
