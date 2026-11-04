// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/discovery/cloudkms"
	"trstctl.com/trstctl/internal/discovery/cloudkms/awskms"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// executeCloudKMSKeyDiscoveryRun reads every configured account and Region's
// KMS keys (X4) and records one finding per key with its type, size, usage,
// state and automatic-rotation status; a key KMS could rotate but is not
// rotating is flagged unrotated. The reads are KMS's read-only List, Describe
// and GetKeyRotationStatus calls with the source's own credential references,
// and the findings are the source's tenant's alone.
func (d *issuanceDispatcher) executeCloudKMSKeyDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	var cfg cloudCertificateDiscoveryConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, "failed", fmt.Sprintf("decode %s config: %v", cloudkms.SourceKind, err), nil
	}
	if len(cfg.Providers) == 0 {
		return netscan.Report{}, "failed", cloudkms.SourceKind + " discovery requires at least one provider", nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(cfg.Providers)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(cfg.Providers)}
	var failures []string
	for i, p := range cfg.Providers {
		keys, host, err := readAWSKMSKeys(ctx, p, d.egress)
		if err != nil {
			rep.Failed++
			failures = append(failures, fmt.Sprintf("provider %d: %v", i+1, err))
			continue
		}
		region := strings.TrimSpace(p.Region)
		for _, k := range keys {
			meta := map[string]any{
				"provider": cloudkms.ProviderAWSKMS, "region": region, "key_id": k.KeyID, "arn": k.ARN,
				"key_spec": k.KeySpec, "key_type": k.Algorithm, "key_usage": k.KeyUsage, "key_state": k.KeyState,
				"key_manager": k.KeyManager, "origin": k.Origin, "enabled": k.Enabled, "multi_region": k.MultiRegion,
				"rotation": k.Rotation.Status, "unrotated": k.Unrotated(),
			}
			if k.Bits > 0 {
				meta["key_bits"] = k.Bits
			}
			if !k.Created.IsZero() {
				meta["created_at"] = k.Created
			}
			if k.Rotation.PeriodDays > 0 {
				meta["rotation_period_days"] = k.Rotation.PeriodDays
			}
			if k.Rotation.NextRotation != nil {
				meta["next_rotation_at"] = *k.Rotation.NextRotation
			}
			if k.Rotation.Error != "" {
				meta["rotation_error"] = k.Rotation.Error
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				return rep, "", "", err
			}
			risk := 20
			if k.Unrotated() {
				risk = 60
			}
			ref := k.ARN
			if ref == "" {
				ref = cloudkms.ProviderAWSKMS + ":" + region + ":" + k.KeyID
			}
			if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
				RunID: run.ID, SourceID: src.ID, Kind: cloudkms.FindingKind, Ref: ref,
				Provenance:  cloudkms.ProviderAWSKMS + ":" + host,
				Fingerprint: cloudkms.ProviderAWSKMS + ":" + ref,
				RiskScore:   risk, Metadata: raw,
			}); err != nil {
				return rep, "", "", err
			}
			rep.Discovered++
		}
	}
	switch {
	case rep.Failed > 0 && rep.Discovered > 0:
		return rep, "partial", "some cloud KMS providers failed: " + strings.Join(failures, "; "), nil
	case rep.Failed > 0:
		return rep, "failed", "every cloud KMS provider failed: " + strings.Join(failures, "; "), nil
	}
	return rep, "succeeded", "", nil
}

// readAWSKMSKeys reads one provider's keys with its own credentials; with the
// air-gap guard enforcing, only an operator-allowed endpoint is reached.
func readAWSKMSKeys(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard) ([]awskms.Key, string, error) {
	if strings.TrimSpace(p.Provider) != cloudkms.ProviderAWSKMS {
		return nil, "", fmt.Errorf("unsupported %s provider %q", cloudkms.SourceKind, p.Provider)
	}
	region := strings.TrimSpace(p.Region)
	if region == "" {
		return nil, "", fmt.Errorf("aws-kms requires a region")
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://kms." + region + ".amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("aws-kms endpoint is not a URL")
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, "", err
	}
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	accessKeyID, err := resolveDiscoveryCredentialRef(ctx, p.AccessKeyIDRef)
	if err != nil {
		return nil, "", fmt.Errorf("resolve access_key_id_ref: %w", err)
	}
	secretAccessKey, err := resolveDiscoveryCredentialRef(ctx, p.SecretAccessKeyRef)
	if err != nil {
		return nil, "", fmt.Errorf("resolve secret_access_key_ref: %w", err)
	}
	sessionToken, err := resolveOptionalDiscoveryCredentialRef(ctx, p.SessionTokenRef)
	if err != nil {
		return nil, "", fmt.Errorf("resolve session_token_ref: %w", err)
	}
	reader, err := awskms.New(awskms.Config{Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
		SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client})
	if err != nil {
		return nil, "", err
	}
	keys, err := reader.Keys(ctx)
	return keys, u.Host, err
}
