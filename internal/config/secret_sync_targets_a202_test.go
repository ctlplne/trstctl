// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A202: the signed webhook needs its endpoint and signing key reference;
// Parameter Store its region, access key and secret reference, and a clean
// path prefix; Netlify its account and token. Each valid form is accepted.
func TestSecretSyncTargetsSignedWebhookParameterStoreAndNetlify(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	base := func(typ string) SecretSyncTargetConfig {
		return SecretSyncTargetConfig{TenantID: tenant, ID: "t-" + typ, Type: typ, Endpoint: "https://receiver.example.test"}
	}
	valid := []SecretSyncTargetConfig{}
	webhook := base("webhook")
	webhook.SigningKeyRef = "file:/run/secrets/webhook-key"
	webhook.BodyTemplate = `{"v":"${value}"}`
	valid = append(valid, webhook)
	params := base("aws-parameter-store")
	params.Region, params.AccessKeyID, params.SecretAccessRef, params.PathPrefix = "us-east-1", "AKIAEXAMPLE", "file:/run/secrets/aws", "apps/payments"
	valid = append(valid, params)
	netlify := base("netlify")
	netlify.AccountID, netlify.TokenRef, netlify.SiteID = "team-1", "secret://integrations/netlify", "site-1"
	valid = append(valid, netlify)
	for _, target := range valid {
		if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{target}}, true); err != nil {
			t.Fatalf("%s: %v", target.Type, err)
		}
	}
	for _, c := range []struct {
		mutate func(*SecretSyncTargetConfig)
		target SecretSyncTargetConfig
		want   string
	}{
		{func(c *SecretSyncTargetConfig) { c.SigningKeyRef = "" }, webhook, "signing_key_ref"},
		{func(c *SecretSyncTargetConfig) { c.Endpoint = "" }, webhook, "endpoint is required"},
		{func(c *SecretSyncTargetConfig) { c.SigningKeyRef = "inline-key" }, webhook, "signing_key_ref"},
		{func(c *SecretSyncTargetConfig) { c.Region = "" }, params, "region is required"},
		{func(c *SecretSyncTargetConfig) { c.SecretAccessRef = "" }, params, "secret_access_key_ref"},
		{func(c *SecretSyncTargetConfig) { c.PathPrefix = "apps/../x" }, params, "path_prefix"},
		{func(c *SecretSyncTargetConfig) { c.AccountID = "" }, netlify, "account_id is required"},
		{func(c *SecretSyncTargetConfig) { c.TokenRef = "" }, netlify, "token_ref"},
	} {
		target := c.target
		c.mutate(&target)
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{target}}, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v, want an error naming %q", target.Type, err, c.want)
		}
	}
}
