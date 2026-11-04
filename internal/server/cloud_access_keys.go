// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudkeys"
	"trstctl.com/trstctl/internal/discovery/cloudkeys/awsiamkeys"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// executeCloudAccessKeyDiscoveryRun reads every configured account's IAM
// user access keys (M3) and records one finding per key with its age, status
// and last use; an active key unused for 90 days is flagged stale. The reads
// are the read-only IAM List/Get operations with the source's own credential
// references, and the findings are the source's tenant's alone.
func (d *issuanceDispatcher) executeCloudAccessKeyDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	var cfg cloudCertificateDiscoveryConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, "failed", fmt.Sprintf("decode %s config: %v", cloudkeys.SourceKind, err), nil
	}
	if len(cfg.Providers) == 0 {
		return netscan.Report{}, "failed", cloudkeys.SourceKind + " discovery requires at least one provider", nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(cfg.Providers)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(cfg.Providers)}
	var failures []string
	for i, p := range cfg.Providers {
		keys, host, err := readAWSAccessKeys(ctx, p, d.egress)
		if err != nil {
			rep.Failed++
			failures = append(failures, fmt.Sprintf("provider %d: %v", i+1, err))
			continue
		}
		now := time.Now().UTC()
		if d.accessKeyNow != nil {
			now = d.accessKeyNow().UTC()
		}
		for _, k := range keys {
			meta := map[string]any{
				"provider": cloudkeys.ProviderAWSIAM, "user": k.User, "access_key_id": k.AccessKeyID, "status": k.Status,
				"created_at": k.Created, "age_days": wholeDays(now.Sub(k.Created)),
				"unused_days": wholeDays(k.Unused(now)), "stale": k.Stale(now),
			}
			if k.LastUsed != nil {
				meta["last_used_at"], meta["last_used_service"], meta["last_used_region"] = *k.LastUsed, k.LastUsedService, k.LastUsedRegion
			} else {
				meta["never_used"] = true
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				return rep, "", "", err
			}
			risk := 30
			if k.Stale(now) {
				risk = 80
			}
			if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
				RunID: run.ID, SourceID: src.ID, Kind: cloudkeys.FindingKind,
				Ref:         cloudkeys.ProviderAWSIAM + ":" + k.User + ":" + k.AccessKeyID,
				Provenance:  cloudkeys.ProviderAWSIAM + ":" + host,
				Fingerprint: cloudkeys.ProviderAWSIAM + ":" + k.AccessKeyID,
				RiskScore:   risk, Metadata: raw,
			}); err != nil {
				return rep, "", "", err
			}
			rep.Discovered++
		}
	}
	switch {
	case rep.Failed > 0 && rep.Discovered > 0:
		return rep, "partial", "some cloud access-key providers failed: " + strings.Join(failures, "; "), nil
	case rep.Failed > 0:
		return rep, "failed", "every cloud access-key provider failed: " + strings.Join(failures, "; "), nil
	}
	return rep, "succeeded", "", nil
}

// readAWSAccessKeys reads one provider's keys with its own credentials; with
// the air-gap guard enforcing, only an operator-allowed endpoint is reached.
func readAWSAccessKeys(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard) ([]awsiamkeys.Key, string, error) {
	if strings.TrimSpace(p.Provider) != cloudkeys.ProviderAWSIAM {
		return nil, "", fmt.Errorf("unsupported %s provider %q", cloudkeys.SourceKind, p.Provider)
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("aws-iam endpoint is not a URL")
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, "", err
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
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	reader, err := awsiamkeys.New(awsiamkeys.Config{Endpoint: endpoint, AccessKeyID: accessKeyID,
		SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client})
	if err != nil {
		return nil, "", err
	}
	keys, err := reader.Keys(ctx)
	return keys, u.Host, err
}

func wholeDays(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Floor(d.Hours() / 24))
}
