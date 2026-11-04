// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/discovery/lbtls"
	"trstctl.com/trstctl/internal/discovery/lbtls/awselb"
	"trstctl.com/trstctl/internal/discovery/lbtls/bigip"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type loadBalancerTLSDiscoveryConfig struct {
	Providers []loadBalancerTLSProviderConfig `json:"providers"`
}

// loadBalancerTLSProviderConfig is one account and Region (aws-elbv2) or one
// BIG-IP (f5-bigip, endpoint = its management base URL) with credential
// references only.
type loadBalancerTLSProviderConfig struct {
	Provider             string   `json:"provider"`
	Region               string   `json:"region"`
	Endpoint             string   `json:"endpoint"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
	AccessKeyIDRef       string   `json:"access_key_id_ref"`
	SecretAccessKeyRef   string   `json:"secret_access_key_ref"`
	SessionTokenRef      string   `json:"session_token_ref"`
	TokenRef             string   `json:"token_ref"`
	UsernameRef          string   `json:"username_ref"`
	PasswordRef          string   `json:"password_ref"`
}

// executeLoadBalancerTLSDiscoveryRun reads every configured provider's TLS
// listeners (X4) and records, per listener, one finding with the policy it
// enforces and the versions it allows, and one crypto-inventory finding at
// the oldest version it allows — so a listener whose policy allows TLS 1.0 is
// one weak TLSv1.0 finding. Each listener's inventory fact is reconciled, so
// a tightened policy replaces the old fact. The reads are read-only, with the
// source's own credential references, and the findings are the source's
// tenant's alone.
func (d *issuanceDispatcher) executeLoadBalancerTLSDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	var cfg loadBalancerTLSDiscoveryConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, "failed", fmt.Sprintf("decode %s config: %v", lbtls.SourceKind, err), nil
	}
	if len(cfg.Providers) == 0 {
		return netscan.Report{}, "failed", lbtls.SourceKind + " discovery requires at least one provider", nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(cfg.Providers)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(cfg.Providers)}
	var failures []string
	sink := &eventedCBOMSink{store: d.store, log: d.log, tenantID: tenantID}
	policy := cbom.DefaultPolicy()
	for i, p := range cfg.Providers {
		listeners, host, err := readLoadBalancerListeners(ctx, p, d.egress)
		if err != nil {
			rep.Failed++
			failures = append(failures, fmt.Sprintf("provider %d: %v", i+1, err))
			continue
		}
		provider := strings.TrimSpace(p.Provider)
		for _, l := range listeners {
			ref := l.Ref
			if provider == lbtls.ProviderF5BIGIP {
				ref = provider + "://" + host + l.Ref
			}
			lowest := l.Lowest()
			meta := map[string]any{
				"provider": provider, "load_balancer": l.LoadBalancer, "listener": l.Ref, "port": l.Port,
				"protocol": l.Protocol, "policy": l.Policy, "protocols": l.Protocols, "lowest_protocol": lowest,
				"allows_tls10": l.Allows("TLSv1.0"), "allows_tls11": l.Allows("TLSv1.1"), "ciphers": boundedStrings(l.Ciphers, 100),
			}
			if provider == lbtls.ProviderAWSELBv2 {
				meta["region"] = strings.TrimSpace(p.Region)
			} else {
				meta["host"] = host
			}
			risk := 10
			switch {
			case l.Allows("SSLv3") || l.Allows("TLSv1.0"):
				risk = 70
			case l.Allows("TLSv1.1"):
				risk = 50
			}
			var weak *cbom.Finding
			if lowest != "" {
				f := cbom.Finding{Kind: cbom.AssetHostConfig, Location: ref, Protocol: lowest, Library: provider}.Classified(policy)
				meta["strength"], meta["out_of_policy"] = string(f.Class.Strength), f.Class.OutOfPolicy
				weak = &f
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				return rep, "", "", err
			}
			if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
				RunID: run.ID, SourceID: src.ID, Kind: lbtls.FindingKind, Ref: ref,
				Provenance:  provider + ":" + host,
				Fingerprint: provider + ":" + ref + ":" + l.Policy,
				RiskScore:   risk, Metadata: raw,
			}); err != nil {
				return rep, "", "", err
			}
			if weak != nil {
				if err := sink.Record(ctx, *weak); err != nil {
					return rep, "", "", err
				}
			}
			if err := sink.Reconcile(ctx, "host-config", ref); err != nil {
				return rep, "", "", err
			}
			rep.Discovered++
		}
	}
	switch {
	case rep.Failed > 0 && rep.Discovered > 0:
		return rep, "partial", "some load-balancer TLS providers failed: " + strings.Join(failures, "; "), nil
	case rep.Failed > 0:
		return rep, "failed", "every load-balancer TLS provider failed: " + strings.Join(failures, "; "), nil
	}
	return rep, "succeeded", "", nil
}

// readLoadBalancerListeners reads one provider's listeners with its own
// credentials; with the air-gap guard enforcing, only an operator-allowed
// endpoint is reached.
func readLoadBalancerListeners(ctx context.Context, p loadBalancerTLSProviderConfig, guard *egress.Guard) ([]lbtls.Listener, string, error) {
	provider := strings.TrimSpace(p.Provider)
	endpoint := strings.TrimSpace(p.Endpoint)
	region := strings.TrimSpace(p.Region)
	switch provider {
	case lbtls.ProviderAWSELBv2:
		if region == "" {
			return nil, "", fmt.Errorf("aws-elbv2 requires a region")
		}
		if endpoint == "" {
			endpoint = "https://elasticloadbalancing." + region + ".amazonaws.com"
		}
	case lbtls.ProviderF5BIGIP:
		if endpoint == "" {
			return nil, "", fmt.Errorf("f5-bigip requires its management endpoint")
		}
	default:
		return nil, "", fmt.Errorf("unsupported %s provider %q", lbtls.SourceKind, p.Provider)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("%s endpoint is not a URL", provider)
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, "", err
	}
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	if provider == lbtls.ProviderF5BIGIP {
		cfg := bigip.Config{BaseURL: endpoint, HTTPClient: client}
		if strings.TrimSpace(p.TokenRef) != "" {
			if cfg.Token, err = resolveDiscoveryCredentialRef(ctx, p.TokenRef); err != nil {
				return nil, "", fmt.Errorf("resolve token_ref: %w", err)
			}
		} else {
			if cfg.Username, err = resolveDiscoveryCredentialRef(ctx, p.UsernameRef); err != nil {
				return nil, "", fmt.Errorf("resolve username_ref: %w", err)
			}
			if cfg.Password, err = resolveDiscoveryCredentialRef(ctx, p.PasswordRef); err != nil {
				return nil, "", fmt.Errorf("resolve password_ref: %w", err)
			}
		}
		reader, err := bigip.New(cfg)
		if err != nil {
			return nil, "", err
		}
		listeners, err := reader.Listeners(ctx)
		return listeners, u.Host, err
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
	reader, err := awselb.New(awselb.Config{Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
		SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client})
	if err != nil {
		return nil, "", err
	}
	listeners, err := reader.Listeners(ctx)
	return listeners, u.Host, err
}

func boundedStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
