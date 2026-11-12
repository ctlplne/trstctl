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
	valid := ProviderBillingTarget{ID: "psa-main", Type: "json", Endpoint: "https://billing.example.test/usage",
		SigningKeyRef: "file:/run/secrets/billing-hmac", TokenRef: "secret://integrations/billing"}
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
		"upper-case id":      {func(t *ProviderBillingTarget) { t.ID = "PSA" }, ".id"},
		"empty id":           {func(t *ProviderBillingTarget) { t.ID = "" }, ".id"},
		"unknown type":       {func(t *ProviderBillingTarget) { t.Type = "connectwise" }, ".type"},
		"relative endpoint":  {func(t *ProviderBillingTarget) { t.Endpoint = "/usage" }, ".endpoint"},
		"plain http":         {func(t *ProviderBillingTarget) { t.Endpoint = "http://billing.example.test/usage" }, ".endpoint"},
		"credentials in url": {func(t *ProviderBillingTarget) { t.Endpoint = "https://user:pw@billing.example.test/usage" }, ".endpoint"},
		"no signing key":     {func(t *ProviderBillingTarget) { t.SigningKeyRef = "" }, ".signing_key_ref"},
		"inline signing key": {func(t *ProviderBillingTarget) { t.SigningKeyRef = "hunter2" }, ".signing_key_ref"},
		"inline token":       {func(t *ProviderBillingTarget) { t.TokenRef = "abc123" }, ".token_ref"},
		"weekly cadence":     {func(t *ProviderBillingTarget) { t.Cadence = "weekly" }, ".cadence"},
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
