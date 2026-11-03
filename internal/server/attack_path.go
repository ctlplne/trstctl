// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Provider-native attack-path validation (A167): the control-plane executor.
//
// The validation row names a cloud_network_path source and the exposed
// endpoints the exposure posture chose. The control plane resolves the
// source's read-only credentials, asks the cloud for the network configuration
// on the path to each endpoint's public addresses, and records one verdict per
// address: open, blocked by a named route table, network ACL or security
// group, not in the account, or unknown with the reason. It sends nothing to
// the endpoints themselves: the only network contact is the provider's API and
// the name lookup that turns an endpoint's host into its addresses.

// maxAttackPathAddresses bounds the addresses one endpoint's name expands to.
const maxAttackPathAddresses = 4

// attackPathResolver is the name lookup the executor uses; tests replace it.
var attackPathResolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type attackPathReader interface {
	Path(ctx context.Context, ip netip.Addr) (netpath.Config, bool, error)
}

func (d *issuanceDispatcher) handleAttackPathValidate(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.orch == nil {
		return errors.New("server: attack-path validation is not configured")
	}
	var intent orchestrator.AttackPathIntent
	if err := json.Unmarshal(m.Payload, &intent); err != nil || strings.TrimSpace(intent.RunID) == "" || strings.TrimSpace(intent.SourceID) == "" ||
		len(intent.Endpoints) == 0 || len(intent.Endpoints) > orchestrator.MaxAttackPathEndpoints {
		return orchestrator.DefiniteNoEffect(errors.New("server: attack-path validation row is malformed"))
	}
	source, err := d.store.GetDiscoverySource(ctx, m.TenantID, intent.SourceID)
	if err != nil {
		return err
	}
	if source.Kind != orchestrator.AttackPathSourceKind {
		return d.orch.FailAttackPathValidation(ctx, m.TenantID, m.IdempotencyKey, intent, "the source is no longer a cloud_network_path source")
	}
	readers, err := attackPathReaders(ctx, source.Config)
	if err != nil {
		return d.orch.FailAttackPathValidation(ctx, m.TenantID, m.IdempotencyKey, intent, err.Error())
	}
	observed := make([]orchestrator.AttackPathObservation, 0, len(intent.Endpoints))
	for _, endpoint := range intent.Endpoints {
		observed = append(observed, validateAttackPathEndpoint(ctx, readers, endpoint)...)
	}
	return d.orch.RecordAttackPathValidation(ctx, m.TenantID, m.IdempotencyKey, intent, observed, time.Now().UTC())
}

// attackPathReaders builds one read-only reader per configured provider. A
// source that cannot be read at all fails the run with the reason rather than
// judging any endpoint on it.
func attackPathReaders(ctx context.Context, raw json.RawMessage) ([]attackPathReader, error) {
	var cfg cloudCertificateDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode cloud_network_path config: %w", err)
	}
	if len(cfg.Providers) == 0 {
		return nil, errors.New("cloud_network_path requires at least one provider")
	}
	readers := make([]attackPathReader, 0, len(cfg.Providers))
	for i, p := range cfg.Providers {
		if strings.TrimSpace(p.Provider) != "aws-ec2" {
			return nil, fmt.Errorf("provider %d: unsupported cloud_network_path provider %q", i+1, p.Provider)
		}
		region := strings.TrimSpace(p.Region)
		if region == "" {
			return nil, fmt.Errorf("provider %d: aws-ec2 region is required", i+1)
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		if endpoint == "" {
			endpoint = "https://ec2." + region + ".amazonaws.com"
		}
		client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, fmt.Errorf("provider %d: %w", i+1, err)
		}
		accessKeyID, err := resolveDiscoveryCredentialRef(ctx, p.AccessKeyIDRef)
		if err != nil {
			return nil, fmt.Errorf("provider %d: resolve access_key_id_ref: %w", i+1, err)
		}
		secretAccessKey, err := resolveDiscoveryCredentialRef(ctx, p.SecretAccessKeyRef)
		if err != nil {
			return nil, fmt.Errorf("provider %d: resolve secret_access_key_ref: %w", i+1, err)
		}
		sessionToken, err := resolveOptionalDiscoveryCredentialRef(ctx, p.SessionTokenRef)
		if err != nil {
			return nil, fmt.Errorf("provider %d: resolve session_token_ref: %w", i+1, err)
		}
		reader, err := awsnetpath.New(awsnetpath.Config{Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
			SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client})
		if err != nil {
			return nil, fmt.Errorf("provider %d: %w", i+1, err)
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

// validateAttackPathEndpoint judges every public address the endpoint's host
// names. The first provider that holds an address decides it.
func validateAttackPathEndpoint(ctx context.Context, readers []attackPathReader, endpoint orchestrator.AttackPathEndpoint) []orchestrator.AttackPathObservation {
	host, portText, err := net.SplitHostPort(endpoint.Address)
	port, perr := strconv.Atoi(portText)
	if err != nil || perr != nil || port <= 0 || port > 65535 {
		return []orchestrator.AttackPathObservation{attackPathUnknown(endpoint, endpoint.Address, "the endpoint has no host and port")}
	}
	addrs, err := attackPathAddresses(ctx, host)
	if err != nil {
		return []orchestrator.AttackPathObservation{attackPathUnknown(endpoint, endpoint.Address, err.Error())}
	}
	out := make([]orchestrator.AttackPathObservation, 0, len(addrs))
	for _, ip := range addrs {
		address := net.JoinHostPort(ip.String(), portText)
		obs := orchestrator.AttackPathObservation{Endpoint: endpoint}
		obs.Endpoint.Address = address
		result := netpath.Result{Verdict: netpath.NotInAccount, Reason: "no network interface in the configured accounts holds this address"}
		for _, reader := range readers {
			cfg, found, err := reader.Path(ctx, ip)
			if err != nil {
				result = netpath.Result{Verdict: netpath.Unknown, Reason: "the provider could not be read: " + err.Error()}
				break
			}
			if found {
				result = netpath.Evaluate(ip, port, cfg)
				break
			}
		}
		obs.Open = result.Verdict == netpath.Open
		obs.Metadata = attackPathMetadata(result)
		out = append(out, obs)
	}
	return out
}

// attackPathAddresses turns the endpoint's host into its public addresses. A
// literal address is used as written; a name is resolved, bounded, and its
// non-public answers dropped, because a cloud's internet path never leads to
// them.
func attackPathAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if netsec.BlockedIP(ip.AsSlice()) {
			return nil, errors.New("the endpoint's address is not public")
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	answers, err := attackPathResolver(lookup, host)
	if err != nil {
		return nil, fmt.Errorf("the endpoint's name could not be resolved: %s", host)
	}
	var out []netip.Addr
	for _, ip := range answers {
		if netsec.BlockedIP(ip.AsSlice()) {
			continue
		}
		out = append(out, ip.Unmap())
		if len(out) == maxAttackPathAddresses {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the endpoint's name resolves to no public address: %s", host)
	}
	return out, nil
}

func attackPathUnknown(endpoint orchestrator.AttackPathEndpoint, address, reason string) orchestrator.AttackPathObservation {
	obs := orchestrator.AttackPathObservation{Endpoint: endpoint}
	obs.Endpoint.Address = address
	obs.Metadata = attackPathMetadata(netpath.Result{Verdict: netpath.Unknown, Reason: reason})
	return obs
}

func attackPathMetadata(result netpath.Result) map[string]any {
	meta := map[string]any{"status": string(result.Verdict), "reason": result.Reason}
	if result.BlockedBy != "" {
		meta["blocked_by"] = string(result.BlockedBy)
	}
	if result.Resource != "" {
		meta["resource"] = result.Resource
	}
	if result.Rule != "" {
		meta["rule"] = result.Rule
	}
	if len(result.Path) > 0 {
		meta["path"] = result.Path
	}
	return meta
}

// executeCloudNetworkPathDiscoveryRun answers an ordinary run of a
// cloud_network_path source: the source has no estate of its own to sweep, so
// a dry run checks that its providers can be built and a full run points at
// the exposure posture, where the endpoints to validate are chosen.
func (d *issuanceDispatcher) executeCloudNetworkPathDiscoveryRun(ctx context.Context, _ string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	readers, err := attackPathReaders(ctx, src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(readers)}, "succeeded", "", nil
	}
	return netscan.Report{}, "failed", "a cloud_network_path source validates the endpoints the exposure posture names: use Posture → Exposure → Validate paths in the cloud (POST /api/v1/nhi/posture/exposure/attack-paths)", nil
}
