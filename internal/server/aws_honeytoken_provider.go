// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const awsHoneyProviderPrefix = "honey.aws."

// AWSHoneyAccountRegistry is an operator-owned, tenant-bound account map. It
// contains reference strings and public topology only, never caller secrets.
type AWSHoneyAccountRegistry map[string]map[string]*awsHoneyProvider

func (r AWSHoneyAccountRegistry) ForTenant(tenantID string) []dynsecret.Provider {
	providers := make([]dynsecret.Provider, 0, len(r[tenantID]))
	for _, provider := range r[tenantID] {
		providers = append(providers, provider)
	}
	return providers
}

func (r AWSHoneyAccountRegistry) Account(tenantID, id string) *awsHoneyProvider {
	return r[tenantID][id]
}

func (r AWSHoneyAccountRegistry) PublicForTenant(tenantID string) []api.AWSHoneyAccount {
	out := make([]api.AWSHoneyAccount, 0, len(r[tenantID]))
	for _, provider := range r[tenantID] {
		out = append(out, api.AWSHoneyAccount{
			ID: provider.cfg.ID, AccountID: provider.cfg.AccountID,
			Regions:             append([]string(nil), provider.cfg.Regions...),
			MaxTTLSeconds:       int64(provider.maxTTL / time.Second),
			PollIntervalSeconds: int64(provider.interval / time.Second),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type awsHoneyProvider struct {
	cfg      config.AWSHoneyAccountConfig
	maxTTL   time.Duration
	interval time.Duration
	resolver integrationCredentialResolver
	guard    *egress.Guard
}

func (p *awsHoneyProvider) Name() string { return awsHoneyProviderPrefix + p.cfg.ID }

func (p *awsHoneyProvider) hasRegion(region string) bool {
	return slices.Contains(p.cfg.Regions, region)
}

func (p *awsHoneyProvider) DynamicSecretProviderType() string { return "aws-honeytoken" }

func (p *awsHoneyProvider) DynamicSecretHoneyOnly() bool { return true }

func (p *awsHoneyProvider) DynamicSecretAllowedRoles() []string { return []string{"decoy"} }

func (p *awsHoneyProvider) MaximumTTL() time.Duration { return p.maxTTL }

func (p *awsHoneyProvider) ownerTag(decoyID string) string {
	return crypto.SHA256Hex([]byte(p.cfg.TenantID + "\x00" + p.cfg.ID + "\x00" + decoyID))
}

type awsHoneyCaller struct {
	AccessKeyID     string           `json:"access_key_id"`
	SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
	SessionToken    secret.JSONBytes `json:"session_token"`
	ExpiresAt       time.Time        `json:"expires_at"`
}

func (c *awsHoneyCaller) wipe() {
	secret.Wipe(c.SecretAccessKey)
	secret.Wipe(c.SessionToken)
	*c = awsHoneyCaller{}
}

func (p *awsHoneyProvider) loadCaller(ctx context.Context, ref string) (awsHoneyCaller, error) {
	locked, err := p.resolver.resolve(ctx, p.cfg.TenantID, ref)
	if err != nil {
		return awsHoneyCaller{}, err
	}
	defer locked.Destroy()
	var caller awsHoneyCaller
	if err := json.Unmarshal(locked.Bytes(), &caller); err != nil {
		caller.wipe()
		return awsHoneyCaller{}, errors.New("aws honeytoken: invalid caller credentials file")
	}
	if caller.AccessKeyID == "" || len(caller.SecretAccessKey) == 0 || len(caller.SessionToken) == 0 || time.Until(caller.ExpiresAt) < time.Minute {
		caller.wipe()
		return awsHoneyCaller{}, errors.New("aws honeytoken: caller session must have key, token, and at least one minute remaining")
	}
	return caller, nil
}

func (p *awsHoneyProvider) openIAM(ctx context.Context, decoyID string) (*dynsecret.AWSHoneyBackend, error) {
	caller, err := p.loadCaller(ctx, p.cfg.IAMCredentialsRef)
	if err != nil {
		return nil, err
	}
	defer caller.wipe()
	endpoint := p.cfg.IAMEndpoint
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback, p.cfg.PrivateEgressCIDRs, p.guard)
	if err != nil {
		return nil, err
	}
	prefix := p.cfg.UsernamePrefix
	if prefix == "" {
		prefix = "trstctl-honey"
	}
	return dynsecret.NewAWSHoneyBackend(dynsecret.AWSHoneyConfig{
		Endpoint: endpoint, HTTPClient: client, Region: "us-east-1", AccountID: p.cfg.AccountID,
		AccessKeyID: caller.AccessKeyID, SecretAccessKey: caller.SecretAccessKey,
		SessionToken: caller.SessionToken, UsernamePrefix: prefix, OwnerTag: p.ownerTag(decoyID),
	})
}

func (p *awsHoneyProvider) openCloudTrail(ctx context.Context, region string) (*dynsecret.AWSHoneyCloudTrail, error) {
	if !p.hasRegion(region) {
		return nil, errors.New("aws honeytoken: CloudTrail region is outside this account attachment")
	}
	caller, err := p.loadCaller(ctx, p.cfg.CloudTrailCredentialsRef)
	if err != nil {
		return nil, err
	}
	defer caller.wipe()
	endpoint := p.cfg.CloudTrailEndpoints[region]
	if endpoint == "" {
		endpoint = "https://cloudtrail." + region + ".amazonaws.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback, p.cfg.PrivateEgressCIDRs, p.guard)
	if err != nil {
		return nil, err
	}
	return dynsecret.NewAWSHoneyCloudTrail(dynsecret.AWSHoneyCloudTrailConfig{
		Endpoint: endpoint, HTTPClient: client, Region: region,
		AccountID: p.cfg.AccountID, AccessKeyID: caller.AccessKeyID,
		SecretAccessKey: caller.SecretAccessKey, SessionToken: caller.SessionToken,
	})
}

func (p *awsHoneyProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	if req.Role != "decoy" || req.LeaseID == "" || req.TTL <= 0 || req.TTL > p.maxTTL {
		return dynsecret.Credential{}, errors.New("aws honeytoken: exact decoy role, lease ID, and bounded TTL are required")
	}
	backend, err := p.openIAM(ctx, req.LeaseID)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	defer backend.Close()
	ref, value, err := backend.Create(ctx, req.LeaseID)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	return dynsecret.Credential{BackendRef: ref, Secret: value, Metadata: map[string]string{"provider_type": "aws-honeytoken", "role": "decoy"}}, nil
}

func (p *awsHoneyProvider) Revoke(ctx context.Context, ref string) error {
	accountID, decoyID, _, ownerTag, ok := dynsecret.AWSHoneyReference(ref)
	if !ok || accountID != p.cfg.AccountID || ownerTag != p.ownerTag(decoyID) {
		return errors.New("aws honeytoken: foreign or corrupted backend reference")
	}
	backend, err := p.openIAM(ctx, decoyID)
	if err != nil {
		return err
	}
	defer backend.Close()
	return backend.Retire(ctx, ref)
}

func awsHoneyAccountsFromConfig(entries []config.AWSHoneyAccountConfig, st *store.Store, kek seal.KeyWrapper, guard *egress.Guard, tenantCrypto tenantseal.Access) (AWSHoneyAccountRegistry, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{HoneyAWSAccounts: entries}, true); err != nil {
		return nil, err
	}
	registry := AWSHoneyAccountRegistry{}
	resolver := integrationCredentialResolver{store: st, kek: kek, crypto: tenantCrypto}
	for _, entry := range entries {
		if registry[entry.TenantID] == nil {
			registry[entry.TenantID] = map[string]*awsHoneyProvider{}
		}
		if _, exists := registry[entry.TenantID][entry.ID]; exists {
			return nil, fmt.Errorf("aws honeytoken: duplicate account %s/%s", entry.TenantID, entry.ID)
		}
		maxTTL, _ := entry.MaxTTLDuration()
		interval, _ := entry.PollIntervalDuration()
		// Validate all configured endpoints through the same SSRF guard used at
		// delivery. DNS is resolved again for each actual request.
		endpoints := []string{entry.IAMEndpoint}
		for _, region := range entry.Regions {
			endpoint := entry.CloudTrailEndpoints[region]
			if endpoint == "" {
				endpoint = "https://cloudtrail." + region + ".amazonaws.com"
			}
			endpoints = append(endpoints, endpoint)
		}
		for _, endpoint := range endpoints {
			if strings.TrimSpace(endpoint) == "" {
				endpoint = "https://iam.amazonaws.com"
			}
			if _, err := secretIntegrationHTTPClient(endpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
				return nil, fmt.Errorf("aws honeytoken: account %s endpoint: %w", entry.ID, err)
			}
		}
		registry[entry.TenantID][entry.ID] = &awsHoneyProvider{cfg: entry, maxTTL: maxTTL, interval: interval, resolver: resolver, guard: guard}
	}
	return registry, nil
}
