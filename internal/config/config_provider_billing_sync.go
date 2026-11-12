// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ProviderBillingSync configures where the Provider plane pushes each
// customer's closed, signed usage periods (MSP-2): the operator's billing or
// PSA systems. A customer is pushed to a target only after a Provider operator
// maps it to its company there; the deployment config names the targets, the
// Provider plane owns the mappings.
type ProviderBillingSync struct {
	Targets []ProviderBillingTarget `json:"targets,omitempty"`
}

// ProviderBillingTarget is one external billing system. Type "json" is the
// generic signed JSON push of the billing-sync core; vendor PSA types arrive
// with their own connectors. Credentials are references resolved for each
// delivery, never values in config.
type ProviderBillingTarget struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint"`
	// TokenRef is an optional bearer token reference; SigningKeyRef the HMAC
	// key reference every push is signed with (X-Trstctl-Signature).
	TokenRef      string `json:"token_ref,omitempty"`
	SigningKeyRef string `json:"signing_key_ref,omitempty"`
	// Cadence is the usage period pushed: "monthly" (the default) or "daily",
	// in whole UTC calendar periods.
	Cadence               string   `json:"cadence,omitempty"`
	AllowPrivateEndpoint  bool     `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// BillingTargetIDPattern is a target ID: lowercase, digits and dashes.
var BillingTargetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ProviderBillingTargetTypes are the target types this build can push to.
var ProviderBillingTargetTypes = map[string]struct{}{"json": {}}

// EffectiveCadence is the target's cadence, monthly when unset.
func (t ProviderBillingTarget) EffectiveCadence() string {
	if c := strings.TrimSpace(t.Cadence); c != "" {
		return c
	}
	return "monthly"
}

// Target returns the configured target with this ID.
func (b ProviderBillingSync) Target(id string) (ProviderBillingTarget, bool) {
	for _, t := range b.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return ProviderBillingTarget{}, false
}

func validateProviderBillingSync(b ProviderBillingSync) []error {
	var errs []error
	seen := map[string]bool{}
	for i, t := range b.Targets {
		where := fmt.Sprintf("provider.billing_sync.targets[%d]", i)
		if !BillingTargetIDPattern.MatchString(t.ID) {
			errs = append(errs, fmt.Errorf("%s.id must be 1-63 lowercase letters, digits or dashes", where))
		} else if seen[t.ID] {
			errs = append(errs, fmt.Errorf("%s.id %q is listed twice", where, t.ID))
		}
		seen[t.ID] = true
		if _, ok := ProviderBillingTargetTypes[t.Type]; !ok {
			errs = append(errs, fmt.Errorf("%s.type %q is not a billing target type this build pushes to (json)", where, t.Type))
		}
		if len(t.Name) > 128 {
			errs = append(errs, fmt.Errorf("%s.name is longer than 128 characters", where))
		}
		u, err := url.Parse(strings.TrimSpace(t.Endpoint))
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
			errs = append(errs, fmt.Errorf("%s.endpoint must be an absolute https URL", where))
		case u.Scheme == "http" && !t.AllowInsecureLoopback:
			errs = append(errs, fmt.Errorf("%s.endpoint must use https (http only with allow_insecure_loopback for a loopback test receiver)", where))
		case u.User != nil:
			errs = append(errs, fmt.Errorf("%s.endpoint must not carry credentials; use token_ref", where))
		}
		if strings.TrimSpace(t.SigningKeyRef) == "" {
			errs = append(errs, fmt.Errorf("%s.signing_key_ref is required: every push is HMAC-signed so the receiver can refuse a changed or replayed period", where))
		} else if err := validateCredentialRef(t.SigningKeyRef); err != nil {
			errs = append(errs, fmt.Errorf("%s.signing_key_ref: %w", where, err))
		}
		if strings.TrimSpace(t.TokenRef) != "" {
			if err := validateCredentialRef(t.TokenRef); err != nil {
				errs = append(errs, fmt.Errorf("%s.token_ref: %w", where, err))
			}
		}
		switch t.EffectiveCadence() {
		case "monthly", "daily":
		default:
			errs = append(errs, fmt.Errorf("%s.cadence must be monthly or daily", where))
		}
		if t.AllowPrivateEndpoint && len(t.PrivateEgressCIDRs) == 0 {
			errs = append(errs, errors.New(where+".private_egress_cidrs must name the approved private destinations when allow_private_endpoint is set"))
		}
	}
	return errs
}
