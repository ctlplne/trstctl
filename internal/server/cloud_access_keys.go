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
	"trstctl.com/trstctl/internal/discovery/cloudkeys/azureappsecrets"
	"trstctl.com/trstctl/internal/discovery/cloudkeys/gcpsakeys"
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
	now := time.Now().UTC()
	if d.accessKeyNow != nil {
		now = d.accessKeyNow().UTC()
	}
	for i, p := range cfg.Providers {
		read, err := readCloudAccessKeys(ctx, p, d.egress, now)
		keys, host, lastUseErr := read.keys, read.host, read.lastUseErr
		if err != nil {
			rep.Failed++
			failures = append(failures, fmt.Sprintf("provider %d: %v", i+1, err))
			continue
		}
		if lastUseErr != nil {
			// The keys are recorded; their last use is unknown, never "never used".
			failures = append(failures, fmt.Sprintf("provider %d: %v", i+1, lastUseErr))
		}
		for _, k := range keys {
			meta := map[string]any{
				"provider": k.provider, "user": k.owner, "access_key_id": k.keyID, "status": k.status,
				"created_at": k.created, "age_days": wholeDays(now.Sub(k.created)), "stale": k.stale,
			}
			for key, value := range k.extra {
				meta[key] = value
			}
			switch {
			case !k.lastUseKnown:
				meta["last_use_unknown"] = true
			case k.lastUsed != nil:
				meta["last_used_at"] = *k.lastUsed
				meta["unused_days"] = wholeDays(k.unused)
			default:
				meta["never_used"] = true
				meta["unused_days"] = wholeDays(k.unused)
			}
			if k.expires != nil {
				meta["expires_at"] = *k.expires
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				return rep, "", "", err
			}
			risk := 30
			if k.stale {
				risk = 80
			}
			if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
				RunID: run.ID, SourceID: src.ID, Kind: cloudkeys.FindingKind,
				Ref:         k.provider + ":" + k.owner + ":" + k.keyID,
				Provenance:  k.provider + ":" + host,
				Fingerprint: k.provider + ":" + k.keyID,
				RiskScore:   risk, Metadata: raw,
			}); err != nil {
				return rep, "", "", err
			}
			rep.Discovered++
		}
	}
	switch {
	case rep.Failed == 0 && len(failures) > 0:
		return rep, "partial", "some keys' last use could not be read: " + strings.Join(failures, "; "), nil
	case rep.Failed > 0 && rep.Discovered > 0:
		return rep, "partial", "some cloud access-key providers failed: " + strings.Join(failures, "; "), nil
	case rep.Failed > 0:
		return rep, "failed", "every cloud access-key provider failed: " + strings.Join(failures, "; "), nil
	}
	return rep, "succeeded", "", nil
}

// cloudAccessKey is one provider's key as a finding records it.
type cloudAccessKey struct {
	provider, owner, keyID, status string
	created                        time.Time
	expires, lastUsed              *time.Time
	lastUseKnown, stale            bool
	unused                         time.Duration
	extra                          map[string]any
}

// cloudAccessKeyRead is one provider's read: its keys, the host they came
// from, and why their last use could not be read, if it could not.
type cloudAccessKeyRead struct {
	keys       []cloudAccessKey
	host       string
	lastUseErr error
}

// readCloudAccessKeys reads one provider's keys with its own credentials.
func readCloudAccessKeys(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard, now time.Time) (cloudAccessKeyRead, error) {
	switch strings.TrimSpace(p.Provider) {
	case cloudkeys.ProviderAWSIAM:
		keys, host, err := readAWSAccessKeys(ctx, p, guard)
		out := make([]cloudAccessKey, 0, len(keys))
		for _, k := range keys {
			out = append(out, cloudAccessKey{provider: cloudkeys.ProviderAWSIAM, owner: k.User, keyID: k.AccessKeyID, status: k.Status,
				created: k.Created, lastUsed: k.LastUsed, lastUseKnown: true, stale: k.Stale(now), unused: k.Unused(now),
				extra: map[string]any{"last_used_service": k.LastUsedService, "last_used_region": k.LastUsedRegion, "user_arn": k.UserARN}})
		}
		return cloudAccessKeyRead{keys: out, host: host}, err
	case cloudkeys.ProviderGCPIAM:
		return readGCPServiceAccountKeys(ctx, p, guard, now)
	case cloudkeys.ProviderAzureEntra:
		return readAzureAppSecrets(ctx, p, guard, now)
	default:
		return cloudAccessKeyRead{}, fmt.Errorf("unsupported %s provider %q", cloudkeys.SourceKind, p.Provider)
	}
}

// readGCPServiceAccountKeys reads one project's user-managed service-account
// keys and their last authentication (M3-L1).
func readGCPServiceAccountKeys(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard, now time.Time) (cloudAccessKeyRead, error) {
	if strings.TrimSpace(p.Project) == "" {
		return cloudAccessKeyRead{}, fmt.Errorf("gcp-iam needs project")
	}
	endpoint := firstNonEmpty(strings.TrimSpace(p.Endpoint), "https://iam.googleapis.com")
	activity := firstNonEmpty(strings.TrimSpace(p.ActivityEndpoint), "https://policyanalyzer.googleapis.com")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return cloudAccessKeyRead{}, fmt.Errorf("gcp-iam endpoint is not a URL")
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	activityClient, err := cloudHTTPClient(activity, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
		activityClient.Transport = guard.WrapTransport(activityClient.Transport)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return cloudAccessKeyRead{}, fmt.Errorf("resolve token_ref: %w", err)
	}
	reader, err := gcpsakeys.New(gcpsakeys.Config{Endpoint: endpoint, ActivityEndpoint: activity, Project: p.Project,
		Token: []byte(token), HTTPClient: client, ActivityHTTPClient: activityClient})
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	defer reader.Close()
	res, err := reader.Keys(ctx)
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	out := make([]cloudAccessKey, 0, len(res.Keys))
	for _, k := range res.Keys {
		out = append(out, cloudAccessKey{provider: cloudkeys.ProviderGCPIAM, owner: k.ServiceAccount, keyID: k.KeyID, status: k.Status(now),
			created: k.Created, expires: k.Expires, lastUsed: k.LastAuthenticated, lastUseKnown: k.LastUseKnown,
			stale: k.Stale(now), unused: k.Unused(now), extra: map[string]any{"project": p.Project}})
	}
	return cloudAccessKeyRead{keys: out, host: u.Host, lastUseErr: res.LastUseError}, nil
}

// readAzureAppSecrets reads one Microsoft Entra tenant's app-registration
// client secrets and their last sign-in (M3-L2).
func readAzureAppSecrets(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard, now time.Time) (cloudAccessKeyRead, error) {
	endpoint := firstNonEmpty(strings.TrimSpace(p.Endpoint), "https://graph.microsoft.com")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return cloudAccessKeyRead{}, fmt.Errorf("azure-entra endpoint is not a URL")
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return cloudAccessKeyRead{}, fmt.Errorf("resolve token_ref: %w", err)
	}
	reader, err := azureappsecrets.New(azureappsecrets.Config{Endpoint: endpoint, Token: []byte(token), HTTPClient: client})
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	defer reader.Close()
	res, err := reader.Secrets(ctx)
	if err != nil {
		return cloudAccessKeyRead{}, err
	}
	out := make([]cloudAccessKey, 0, len(res.Secrets))
	for _, s := range res.Secrets {
		out = append(out, cloudAccessKey{provider: cloudkeys.ProviderAzureEntra, owner: s.Application, keyID: s.KeyID, status: s.Status(now),
			created: s.Created, expires: s.Expires, lastUsed: s.LastSignIn, lastUseKnown: s.LastUseKnown,
			stale: s.Stale(now), unused: s.Unused(now), extra: map[string]any{"app_id": s.AppID, "app_object_id": s.ObjectID, "secret_name": s.Name}})
	}
	return cloudAccessKeyRead{keys: out, host: u.Host, lastUseErr: res.LastUseError}, nil
}

// readAWSAccessKeys reads one provider's keys with its own credentials; with
// the air-gap guard enforcing, only an operator-allowed endpoint is reached.
func readAWSAccessKeys(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard) ([]awsiamkeys.Key, string, error) {
	reader, host, err := awsIAMReader(ctx, p, guard)
	if err != nil {
		return nil, "", err
	}
	keys, err := reader.Keys(ctx)
	return keys, host, err
}

// awsIAMReader opens one aws-iam provider's IAM connection with its own
// credentials, through the egress guard: discovery reads keys with it, and a
// key replacement (M3-L4) sets one Inactive.
func awsIAMReader(ctx context.Context, p cloudCertificateProviderConfig, guard *egress.Guard) (*awsiamkeys.Reader, string, error) {
	if strings.TrimSpace(p.Provider) != cloudkeys.ProviderAWSIAM {
		return nil, "", fmt.Errorf("unsupported %s provider %q", cloudkeys.SourceKind, p.Provider)
	}
	endpoint, host, err := awsIAMEndpoint(p)
	if err != nil {
		return nil, "", err
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
	return reader, host, nil
}

// awsIAMEndpoint is an aws-iam connection's endpoint and the host its
// findings name in their provenance.
func awsIAMEndpoint(p cloudCertificateProviderConfig) (string, string, error) {
	return cloudkeys.AWSIAMEndpoint(p.Endpoint)
}

func wholeDays(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Floor(d.Hours() / 24))
}
