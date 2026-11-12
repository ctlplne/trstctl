// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
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
	// ConnectWise configures a "connectwise" target (MSP-3): each customer's
	// figures land as additions of its company's one active agreement of
	// AgreementType. Endpoint is the site's REST root,
	// https://{host}/{codebase}/apis/3.0.
	ConnectWise *ConnectWiseBillingTarget `json:"connectwise,omitempty"`
}

// ConnectWiseBillingTarget is a ConnectWise PSA site the Provider pushes
// usage to.
type ConnectWiseBillingTarget struct {
	// CompanyID is the PSA login company the API member belongs to (the
	// first part of its Basic credentials), not a customer's company.
	CompanyID string `json:"company_id"`
	// ClientID is the integration's clientId: it identifies the
	// integration to ConnectWise; it does not authenticate.
	ClientID string `json:"client_id"`
	// PublicKeyRef and PrivateKeyRef name the API member's keys (file: or
	// env:), resolved for each delivery.
	PublicKeyRef  string `json:"public_key_ref"`
	PrivateKeyRef string `json:"private_key_ref"`
	// AgreementType names the agreement type each mapped company has one
	// active agreement of.
	AgreementType string `json:"agreement_type"`
	// Products maps a meter (certificates_current, agents, secrets_stored)
	// to the catalog identifier of its addition. A meter without a product
	// is not pushed.
	Products map[string]string `json:"products"`
}

// BillingSyncMeters are the meters a period push carries.
var BillingSyncMeters = []string{"agents", "certificates_current", "secrets_stored"}

var (
	connectWiseCompanyPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	connectWiseClientPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// connectWiseConditionValue is what may sit inside a quoted conditions
	// value: the published grammar shows no escaping.
	connectWiseConditionValue = regexp.MustCompile(`^[A-Za-z0-9 _.,:;/()&@#+-]{1,100}$`)
)

// BillingTargetIDPattern is a target ID: lowercase, digits and dashes.
var BillingTargetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ProviderBillingTargetTypes are the target types this build can push to.
var ProviderBillingTargetTypes = map[string]struct{}{"json": {}, "connectwise": {}}

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
			errs = append(errs, fmt.Errorf("%s.type %q is not a billing target type this build pushes to (json, connectwise)", where, t.Type))
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
		switch t.Type {
		case "json":
			errs = append(errs, validateJSONBillingTarget(where, t)...)
		case "connectwise":
			errs = append(errs, validateConnectWiseBillingTarget(where, t)...)
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

func validateJSONBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) == "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref is required: every push is HMAC-signed so the receiver can refuse a changed or replayed period", where))
	} else if err := validateDeploymentCredentialRef(t.SigningKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref: %w", where, err))
	}
	if strings.TrimSpace(t.TokenRef) != "" {
		if err := validateDeploymentCredentialRef(t.TokenRef); err != nil {
			errs = append(errs, fmt.Errorf("%s.token_ref: %w", where, err))
		}
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	return errs
}

func validateConnectWiseBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a connectwise target authenticates with its API member's keys", where))
	}
	cw := t.ConnectWise
	if cw == nil {
		return append(errs, fmt.Errorf("%s.connectwise is required for a connectwise target", where))
	}
	where += ".connectwise"
	if !connectWiseCompanyPattern.MatchString(cw.CompanyID) {
		errs = append(errs, fmt.Errorf("%s.company_id must be the PSA login company (1-64 letters, digits, dots, dashes or underscores)", where))
	}
	if !connectWiseClientPattern.MatchString(cw.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the integration's clientId GUID", where))
	}
	for _, ref := range []struct{ name, value string }{{"public_key_ref", cw.PublicKeyRef}, {"private_key_ref", cw.PrivateKeyRef}} {
		if err := validateDeploymentCredentialRef(ref.value); err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", where, ref.name, err))
		}
	}
	if !connectWiseConditionValue.MatchString(cw.AgreementType) {
		errs = append(errs, fmt.Errorf("%s.agreement_type must be 1-100 letters, digits, spaces or common punctuation without quotes", where))
	}
	if len(cw.Products) == 0 {
		errs = append(errs, fmt.Errorf("%s.products must map at least one meter (%s) to a catalog product", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(cw.Products)) {
		product := cw.Products[meter]
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.products names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if !connectWiseConditionValue.MatchString(product) {
			errs = append(errs, fmt.Errorf("%s.products.%s must be a catalog identifier of 1-100 letters, digits, spaces or common punctuation without quotes", where, meter))
		}
	}
	return errs
}

// validateDeploymentCredentialRef checks a deployment-level credential
// reference: a billing target belongs to the Provider, not to a tenant, so
// it reads a file or an environment variable, never a tenant's secret store.
func validateDeploymentCredentialRef(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "file:"):
		path := strings.TrimSpace(strings.TrimPrefix(raw, "file:"))
		if path == "" || !filepath.IsAbs(path) {
			return errors.New("file reference must contain an absolute path")
		}
		return nil
	case strings.HasPrefix(raw, "env:") && strings.TrimSpace(strings.TrimPrefix(raw, "env:")) != "":
		return nil
	default:
		return errors.New("must use file:/absolute/path or env:NAME")
	}
}
