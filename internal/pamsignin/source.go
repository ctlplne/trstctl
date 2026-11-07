// SPDX-License-Identifier: BUSL-1.1

package pamsignin

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// SourceKind is the discovery source kind that watches a dynamic-secret
// provider's managed accounts for sign-ins outside trstctl (A274).
const SourceKind = "pam_signin"

// Config is a pam_signin source's configuration: the provider whose target's
// sign-ins its runs read, and how far back each run reads (overlapping runs
// refresh a finding, never repeat it).
type Config struct {
	ProviderID      string `json:"provider_id"`
	LookbackSeconds int    `json:"lookback_seconds,omitempty"`
}

var providerID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ParseConfig reads and checks a source's configuration; unknown fields are
// refused.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, errors.New("pam_signin: the configuration is provider_id and an optional lookback_seconds")
	}
	return cfg, cfg.Validate()
}

// Validate checks the configuration.
func (c Config) Validate() error {
	if !providerID.MatchString(c.ProviderID) {
		return errors.New("pam_signin: provider_id names one of the tenant's dynamic-secret providers")
	}
	if c.LookbackSeconds != 0 && (c.LookbackSeconds < 300 || c.LookbackSeconds > 7*24*3600) {
		return errors.New("pam_signin: lookback_seconds is 300 to 604800")
	}
	return nil
}

// Finding is a bypass as a compromised-credential finding (F31).
type Finding struct {
	Ref, Provenance, Fingerprint string
	RiskScore                    int
	Metadata                     map[string]any
}

// BypassRisk is a bypass finding's risk score: a managed account's
// credential used outside every path trstctl controls.
const BypassRisk = 90

// BypassFinding is the finding for a sign-in nothing explained.
func BypassFinding(providerID, providerType, collector string, s SignIn) Finding {
	at := s.At.UTC().Format(time.RFC3339)
	ref := "pam:" + providerID + "/" + s.Account
	signIn := map[string]any{"at": at, "method": s.Method, "ref": s.Ref}
	if !s.Earliest.IsZero() && s.Earliest.Before(s.At) {
		signIn["earliest"] = s.Earliest.UTC().Format(time.RFC3339)
	}
	if s.KeyID != "" {
		signIn["key_id"] = s.KeyID
	}
	return Finding{
		Ref:         ref,
		Provenance:  SourceKind + ":" + providerID + ":" + collector,
		Fingerprint: Fingerprint(providerID, s),
		RiskScore:   BypassRisk,
		Metadata: map[string]any{
			"principal":          s.Account,
			"credential_ref":     ref,
			"credential_kind":    "managed_account",
			"provider":           providerID,
			"provider_type":      providerType,
			"detector":           SourceKind + ":" + collector,
			"observed_at":        at,
			"reason":             "signed in outside trstctl: no session, check-out, rotation or health check explains it",
			"compromise_reasons": []string{"bypass_sign_in"},
			"confidence":         "high",
			"evidence_refs":      []string{"signin:" + strings.TrimPrefix(Fingerprint(providerID, s), "sha256:")},
			"ip":                 s.Source,
			"action":             "sign_in:" + s.Method,
			"sign_in":            signIn,
			"owasp_category":     "NHI2",
			"capability":         "CAP-ITDR-02",
		},
	}
}
