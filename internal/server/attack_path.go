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
	"trstctl.com/trstctl/internal/discovery/netpath/azurenetpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath"
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
// address: open, blocked at a named resource (an AWS route table, network ACL,
// security group, load balancer listener or NAT gateway; a Google Cloud route,
// firewall rule or network; an Azure network security group, route table or
// public IP), not in the account, or unknown with the reason — including a
// path that leaves through a transit gateway, an inspection endpoint or an
// appliance whose own rules decide (A167-L2). It sends nothing to
// the endpoints themselves: the only network contact is the provider's API and
// the name lookup that turns an endpoint's host into its addresses.

// maxAttackPathAddresses bounds the addresses one endpoint's name expands to.
const maxAttackPathAddresses = 4

// attackPathResolver is the name lookup the executor uses; tests replace it.
var attackPathResolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// attackPathReader judges one public address and port in one provider
// account. found is false when the account holds no such address.
type attackPathReader interface {
	Judge(ctx context.Context, ip netip.Addr, port int) (netpath.Result, bool, error)
}

// awsAttackPathReader judges with the EC2 configuration on the path.
type awsAttackPathReader struct{ reader *awsnetpath.Reader }

func (a awsAttackPathReader) Judge(ctx context.Context, ip netip.Addr, port int) (netpath.Result, bool, error) {
	cfg, found, err := a.reader.Path(ctx, ip)
	if err != nil || !found {
		return netpath.Result{}, found, err
	}
	return netpath.Evaluate(ip, port, cfg), true, nil
}

// closeAttackPathReaders wipes the credentials readers hold.
func closeAttackPathReaders(readers []attackPathReader) {
	for _, reader := range readers {
		if closer, ok := reader.(interface{ Close() }); ok {
			closer.Close()
		}
	}
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
	defer closeAttackPathReaders(readers)
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
		reader, err := attackPathReaderFor(ctx, p)
		if err != nil {
			// The readers already built hold credentials; wipe them.
			closeAttackPathReaders(readers)
			return nil, fmt.Errorf("provider %d: %w", i+1, err)
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

// attackPathReaderFor builds the reader for one configured provider.
func attackPathReaderFor(ctx context.Context, p cloudCertificateProviderConfig) (attackPathReader, error) {
	switch strings.TrimSpace(p.Provider) {
	case "aws-ec2":
		return awsAttackPathReaderFor(ctx, p)
	case "gcp-compute":
		// A167-L1: a project's firewall rules and routes.
		return gcpAttackPathReader(ctx, p)
	case "azure-network":
		// A167-L1: a subscription's network security groups and routes.
		return azureAttackPathReader(ctx, p)
	default:
		return nil, fmt.Errorf("unsupported cloud_network_path provider %q", p.Provider)
	}
}

// awsAttackPathReaderFor builds an EC2 reader for one account and Region.
func awsAttackPathReaderFor(ctx context.Context, p cloudCertificateProviderConfig) (attackPathReader, error) {
	region := strings.TrimSpace(p.Region)
	if region == "" {
		return nil, errors.New("aws-ec2 region is required")
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://ec2." + region + ".amazonaws.com"
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, err
	}
	accessKeyID, err := resolveDiscoveryCredentialRef(ctx, p.AccessKeyIDRef)
	if err != nil {
		return nil, fmt.Errorf("resolve access_key_id_ref: %w", err)
	}
	secretAccessKey, err := resolveDiscoveryCredentialRef(ctx, p.SecretAccessKeyRef)
	if err != nil {
		return nil, fmt.Errorf("resolve secret_access_key_ref: %w", err)
	}
	sessionToken, err := resolveOptionalDiscoveryCredentialRef(ctx, p.SessionTokenRef)
	if err != nil {
		return nil, fmt.Errorf("resolve session_token_ref: %w", err)
	}
	// A167-L2: load balancers are read from Elastic Load Balancing, through
	// a client whose endpoint passes the same egress checks.
	elbEndpoint := strings.TrimSpace(p.ELBEndpoint)
	if elbEndpoint == "" {
		elbEndpoint = "https://elasticloadbalancing." + region + ".amazonaws.com"
	}
	elbClient, err := cloudHTTPClient(elbEndpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, fmt.Errorf("elb_endpoint: %w", err)
	}
	reader, err := awsnetpath.New(awsnetpath.Config{Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
		SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client,
		ELBEndpoint: elbEndpoint, ELBHTTPClient: elbClient})
	if err != nil {
		return nil, err
	}
	return awsAttackPathReader{reader: reader}, nil
}

// gcpAttackPathReader builds a Compute Engine reader for one project.
func gcpAttackPathReader(ctx context.Context, p cloudCertificateProviderConfig) (attackPathReader, error) {
	project := strings.TrimSpace(p.Project)
	if project == "" {
		return nil, errors.New("gcp-compute project is required")
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://compute.googleapis.com"
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, err
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("resolve token_ref: %w", err)
	}
	return gcpnetpath.New(gcpnetpath.Config{Project: project, Endpoint: endpoint, Token: []byte(token), HTTPClient: client})
}

// azureAttackPathReader builds a Resource Manager reader for one
// subscription.
func azureAttackPathReader(ctx context.Context, p cloudCertificateProviderConfig) (attackPathReader, error) {
	subscription := strings.TrimSpace(p.SubscriptionID)
	if subscription == "" {
		return nil, errors.New("azure-network subscription_id is required")
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://management.azure.com"
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return nil, err
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("resolve token_ref: %w", err)
	}
	return azurenetpath.New(azurenetpath.Config{SubscriptionID: subscription, Endpoint: endpoint, Token: []byte(token), HTTPClient: client})
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
			judged, found, err := reader.Judge(ctx, ip, port)
			if err != nil {
				result = netpath.Result{Verdict: netpath.Unknown, Reason: "the provider could not be read: " + err.Error()}
				break
			}
			if found {
				result = judged
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
// cloud_network_path source. The source has no estate of its own to sweep: a
// dry run checks that its providers can be built, and a full run — an
// operator's or the scheduler's (A167-L4) — re-validates every endpoint the
// exposure posture names, bounded as a manual validation is, and records each
// address's verdict under the run.
func (d *issuanceDispatcher) executeCloudNetworkPathDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	readers, err := attackPathReaders(ctx, src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	defer closeAttackPathReaders(readers)
	if run.DryRun {
		return netscan.Report{Targets: len(readers)}, "succeeded", "", nil
	}
	if d.attackPathEndpoints == nil {
		return netscan.Report{}, "failed", "attack-path validation is not served by this control plane", nil
	}
	// Endpoints past the bound are left to the next run, which takes the
	// longest unchecked first; the run counts what it judged.
	endpoints, _, err := d.attackPathEndpoints(ctx, tenantID)
	if err != nil {
		return netscan.Report{}, "", "", err
	}
	report := netscan.Report{}
	at := time.Now().UTC()
	for _, endpoint := range endpoints {
		for _, obs := range validateAttackPathEndpoint(ctx, readers, endpoint) {
			finding, err := orchestrator.AttackPathFinding(run.ID, src.ID, obs, at)
			if err != nil {
				return netscan.Report{}, "", "", err
			}
			if _, err := d.orch.RecordDiscoveryFindingWithEventID(ctx, tenantID,
				orchestrator.DiscoveryRelayEventID(tenantID, run.ID, "attack-path-finding:"+finding.Ref), finding); err != nil {
				return netscan.Report{}, "", "", err
			}
			report.Targets++
			if obs.Open {
				report.Discovered++
			}
		}
	}
	// Each address's verdict is its finding; the run counts them.
	return report, "succeeded", "", nil
}
