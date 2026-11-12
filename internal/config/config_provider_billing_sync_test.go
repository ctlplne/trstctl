// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// MSP-2: a billing target needs a clean unique ID, a type this build pushes
// to, an absolute https endpoint without embedded credentials (http only for
// a loopback test receiver), an HMAC signing key reference, optional bearer
// reference, a monthly or daily cadence, and named CIDRs for a private
// endpoint. Every valid shape is accepted.
func TestProviderBillingSyncTargetsMSP2(t *testing.T) {
	valid := ProviderBillingTarget{ID: "psa-main", Type: "json", Endpoint: "https://billing.example.test/usage", // #nosec G101 -- file: and env: references to test-only values (CWE-798)
		SigningKeyRef: "file:/run/secrets/billing-hmac", TokenRef: "env:TRSTCTL_BILLING_TOKEN"}
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}); len(errs) != 0 {
		t.Fatalf("valid target refused: %v", errs)
	}
	if valid.EffectiveCadence() != "monthly" {
		t.Fatalf("default cadence = %q", valid.EffectiveCadence())
	}
	loopback := valid
	loopback.Endpoint, loopback.AllowInsecureLoopback, loopback.Cadence = "http://127.0.0.1:9000/usage", true, "daily"
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{loopback}}); len(errs) != 0 {
		t.Fatalf("loopback test receiver refused: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"upper-case id":       {func(t *ProviderBillingTarget) { t.ID = "PSA" }, ".id"},
		"empty id":            {func(t *ProviderBillingTarget) { t.ID = "" }, ".id"},
		"unknown type":        {func(t *ProviderBillingTarget) { t.Type = "csv-upload" }, ".type"},
		"relative endpoint":   {func(t *ProviderBillingTarget) { t.Endpoint = "/usage" }, ".endpoint"},
		"plain http":          {func(t *ProviderBillingTarget) { t.Endpoint = "http://billing.example.test/usage" }, ".endpoint"},
		"credentials in url":  {func(t *ProviderBillingTarget) { t.Endpoint = "https://user:pw@billing.example.test/usage" }, ".endpoint"},
		"no signing key":      {func(t *ProviderBillingTarget) { t.SigningKeyRef = "" }, ".signing_key_ref"},
		"inline signing key":  {func(t *ProviderBillingTarget) { t.SigningKeyRef = "hunter2" }, ".signing_key_ref"},
		"inline token":        {func(t *ProviderBillingTarget) { t.TokenRef = "abc123" }, ".token_ref"},
		"tenant secret token": {func(t *ProviderBillingTarget) { t.TokenRef = "secret://integrations/billing" }, ".token_ref"},
		"weekly cadence":      {func(t *ProviderBillingTarget) { t.Cadence = "weekly" }, ".cadence"},
		"private without cidrs": {func(t *ProviderBillingTarget) {
			t.AllowPrivateEndpoint = true
		}, "private_egress_cidrs"},
		"long name": {func(t *ProviderBillingTarget) { t.Name = strings.Repeat("n", 129) }, ".name"},
	} {
		target := valid
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, errs, tc.want)
		}
	}
	dup := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid, valid}})
	if len(dup) == 0 || !strings.Contains(dup[0].Error(), "listed twice") {
		t.Fatalf("duplicate id: %v", dup)
	}
	if got, ok := (ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}).Target("psa-main"); !ok || got.Endpoint != valid.Endpoint {
		t.Fatalf("Target lookup = %+v %v", got, ok)
	}
}

// MSP-3: a connectwise target names the PSA login company, the integration's
// clientId GUID, both API member keys as deployment references, the agreement
// type and at least one meter's catalog product; a value that would need
// escaping inside a conditions query is refused, and json-only fields are
// refused on it (and its block on a json target).
func TestProviderBillingSyncConnectWiseTargetMSP3(t *testing.T) {
	valid := ProviderBillingTarget{ID: "cw", Type: "connectwise", Endpoint: "https://api-na.myconnectwise.net/v4_6_release/apis/3.0",
		ConnectWise: &ConnectWiseBillingTarget{CompanyID: "trstctl_msp", ClientID: "6c1a3e1e-58e3-4d1b-9f0e-3b8f5a0c2d71",
			PublicKeyRef: "env:TRSTCTL_CW_PUBLIC", PrivateKeyRef: "file:/run/secrets/cw-private", // #nosec G101 -- env: and file: references to test-only values (CWE-798)
			AgreementType: "Managed PKI", Products: map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}}}
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}); len(errs) != 0 {
		t.Fatalf("valid connectwise target refused: %v", errs)
	}
	clone := func() ProviderBillingTarget {
		c := valid
		cw := *valid.ConnectWise
		cw.Products = map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}
		c.ConnectWise = &cw
		return c
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":             {func(t *ProviderBillingTarget) { t.ConnectWise = nil }, ".connectwise is required"},
		"signing key":          {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"bearer":               {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"login company":        {func(t *ProviderBillingTarget) { t.ConnectWise.CompanyID = "a b" }, ".company_id"},
		"client id":            {func(t *ProviderBillingTarget) { t.ConnectWise.ClientID = "not-a-guid" }, ".client_id"},
		"inline public key":    {func(t *ProviderBillingTarget) { t.ConnectWise.PublicKeyRef = "abc123" }, ".public_key_ref"},
		"tenant private key":   {func(t *ProviderBillingTarget) { t.ConnectWise.PrivateKeyRef = "secret://cw/private" }, ".private_key_ref"},
		"quoted agreement":     {func(t *ProviderBillingTarget) { t.ConnectWise.AgreementType = `PKI" or name="x` }, ".agreement_type"},
		"no products":          {func(t *ProviderBillingTarget) { t.ConnectWise.Products = nil }, ".products must map"},
		"unknown meter":        {func(t *ProviderBillingTarget) { t.ConnectWise.Products["certificates_issued"] = "X" }, "not a pushed meter"},
		"quoted product":       {func(t *ProviderBillingTarget) { t.ConnectWise.Products["agents"] = `A"B` }, ".products.agents"},
		"block on a json type": {func(t *ProviderBillingTarget) { t.Type, t.SigningKeyRef = "json", "env:X" }, "connectwise targets only"},
	} {
		target := clone()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}
