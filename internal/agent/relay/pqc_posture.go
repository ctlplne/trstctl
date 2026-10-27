// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

const (
	KindPQCPosture         = "pqc.posture"
	KindPQCPostureRollback = "pqc.posture.rollback"
)

// PQCPostureIntent is the public, reference-only posture job. The control plane
// pins its outbox row to one enrolled agent and an immutable target revision.
// With no Vantage that agent is the Envoy's host and opens only its
// co-resident loopback management endpoint; with Vantage "network" it is the
// network relay the target names, driving a remote Envoy that declares vantage
// network (A104). Either way the predecessor stays in that agent's encrypted
// local store, so rollback returns to the same agent. TenantID is deliberately
// absent: the authenticated agent and encrypted local store own it.
type PQCPostureIntent struct {
	RunID             string               `json:"run_id"`
	AssetID           string               `json:"asset_id"`
	FindingKind       string               `json:"finding_kind"`
	TargetID          string               `json:"target_id"`
	TargetRevision    string               `json:"target_revision"`
	Target            string               `json:"target"`
	Connector         string               `json:"connector"`
	TargetConfig      json.RawMessage      `json:"target_config"`
	Desired           connector.TLSPosture `json:"desired"`
	RequiredAgentID   string               `json:"required_agent_id"`
	RollbackOnFailure bool                 `json:"rollback_on_failure"`
	VerifyAddress     string               `json:"verify_address"`
	VerifyServerName  string               `json:"verify_server_name"`
	Vantage           string               `json:"vantage,omitempty"`
}

// PQCPostureReport is the agent's bounded public receiver readback. Its digest
// is carried inside the detached job signature; no tenant-supplied text is
// treated as evidence without exact intent and receipt validation on ingest.
type PQCPostureReport struct {
	Operation string                      `json:"operation"`
	Receipt   connector.TLSPostureReceipt `json:"receipt"`
	Served    PQCPostureServed            `json:"served"`
}

// PQCPostureServed is a direct local TLS handshake independent of the Envoy
// management readback. It names the wire result and public leaf fingerprint.
type PQCPostureServed struct {
	Address          string `json:"address"`
	ServerName       string `json:"server_name"`
	TLSVersion       uint16 `json:"tls_version"`
	CipherSuite      uint16 `json:"cipher_suite"`
	KeyExchangeGroup string `json:"key_exchange_group,omitempty"`
	LeafFingerprint  string `json:"leaf_fingerprint"`
}

func (r PQCPostureReport) Digest() string {
	encoded, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return transport.SweepDigest(append([]byte("trstctl-pqc-posture-report/v1\n"), encoded...))
}

func ValidatePQCPostureReport(intent PQCPostureIntent, report PQCPostureReport, digest, kind string) error {
	if err := ValidatePQCPostureIntent(intent); err != nil {
		return err
	}
	if kind != KindPQCPosture && kind != KindPQCPostureRollback {
		return errors.New("relay: unknown PQC posture job kind")
	}
	if report.Operation != kind || report.Digest() != digest {
		return errors.New("relay: PQC posture readback is not bound to the signed job receipt")
	}
	r := report.Receipt
	if r.RunID != intent.RunID || r.FindingID != intent.AssetID || r.FindingKind != intent.FindingKind ||
		r.TargetID != intent.TargetID || r.TargetRevision != intent.TargetRevision || r.Connector != "envoy" {
		return errors.New("relay: PQC posture readback names a different target")
	}
	if err := connector.ValidateObservedTLSPosture(r.Previous); err != nil {
		return err
	}
	if err := connector.ValidateObservedTLSPosture(r.Observed); err != nil {
		return err
	}
	if kind == KindPQCPosture && !connector.EqualTLSPosture(r.Observed, intent.Desired) {
		return errors.New("relay: PQC posture receiver does not serve the requested policy")
	}
	if kind == KindPQCPostureRollback && !connector.EqualTLSPosture(r.Previous, intent.Desired) {
		return errors.New("relay: PQC posture rollback did not start from the applied policy")
	}
	if report.Served.Address != intent.VerifyAddress || report.Served.ServerName != intent.VerifyServerName ||
		report.Served.LeafFingerprint == "" || report.Served.CipherSuite == 0 || report.Served.TLSVersion == 0 {
		return errors.New("relay: PQC posture report has no bound served-listener handshake")
	}
	if kind == KindPQCPosture && (report.Served.TLSVersion != tlsprobe.TLSVersion13 ||
		report.Served.KeyExchangeGroup != "X25519MLKEM768") {
		return errors.New("relay: PQC posture report lacks a TLS 1.3 hybrid wire handshake")
	}
	return nil
}

// ValidatePQCPostureIntent is shared by API admission, claim projection, and
// the agent executor so all three reject a missing or misplaced listener
// binding: a host intent's listener and management endpoint are loopback on
// that host; a network intent's target must declare vantage network.
func ValidatePQCPostureIntent(intent PQCPostureIntent) error {
	if intent.Connector != "envoy" || intent.RunID == "" || intent.AssetID == "" || intent.FindingKind == "" ||
		intent.TargetID == "" || intent.TargetRevision == "" || intent.Target == "" || intent.RequiredAgentID == "" ||
		len(intent.TargetConfig) == 0 || intent.VerifyAddress == "" {
		return errors.New("relay: PQC posture intent lacks exact Envoy target binding")
	}
	network, err := pqcPostureNetworkVantage(intent.Vantage)
	if err != nil {
		return err
	}
	if network {
		if err := validateNetworkPQCListener(intent.VerifyAddress, intent.VerifyServerName); err != nil {
			return err
		}
	} else {
		host, _, err := net.SplitHostPort(intent.VerifyAddress)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("relay: PQC served-state probe requires a literal loopback listener")
		}
	}
	for _, value := range []string{intent.RunID, intent.AssetID, intent.FindingKind, intent.TargetID,
		intent.TargetRevision, intent.Target, intent.RequiredAgentID, intent.VerifyAddress, intent.VerifyServerName} {
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("relay: PQC posture intent contains control characters")
		}
	}
	var target pqcEnvoyTarget
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil || target.SecretName == "" {
		return errors.New("relay: PQC Envoy target configuration is incomplete")
	}
	declared := strings.EqualFold(strings.TrimSpace(target.Vantage), connector.VantageNetworkDeclaration)
	if declared != network {
		return errors.New("relay: PQC posture intent vantage differs from the target's declared executor")
	}
	if err := validatePQCPostureManagementEndpoint(network, target.Endpoint); err != nil {
		return err
	}
	return connector.ValidateTLSPosture(intent.Desired)
}

// pqcEnvoyTarget is the part of an Envoy target's reference-only config a
// posture job reads: the management origin, the SDS secret name, and the
// executor the target declares (A61).
type pqcEnvoyTarget struct {
	Endpoint   string `json:"endpoint"`
	SecretName string `json:"secret_name"`
	Vantage    string `json:"vantage"`
}

func pqcPostureNetworkVantage(vantage string) (bool, error) {
	switch vantage {
	case "":
		return false, nil
	case connector.VantageNetworkDeclaration:
		return true, nil
	default:
		return false, errors.New("relay: PQC posture intent names an unknown vantage")
	}
}

func validatePQCPostureManagementEndpoint(network bool, raw string) error {
	if network {
		return validateNetworkPQCEnvoyEndpoint(raw)
	}
	return validatePQCEnvoyEndpoint(raw)
}

// A remote Envoy's management surface is reached from the relay's segment, so
// it need not be loopback. It must still be one http(s) origin with a host and
// an explicit port and nothing that can move the connector off the reviewed
// resource (user info, path, query, fragment); redirects are refused by the
// bounded client as on the host path.
func validateNetworkPQCEnvoyEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.Opaque != "" || u.Path != "" || strings.ContainsAny(raw, "?#") {
		return errors.New("relay: a network PQC Envoy management URL must be one http(s) origin")
	}
	port, err := strconv.Atoi(u.Port())
	if strings.TrimSpace(u.Hostname()) == "" || err != nil || port < 1 || port > 65535 {
		return errors.New("relay: a network PQC Envoy management URL needs a host and an explicit port")
	}
	return nil
}

// A relay's served-state probe connects to the target's listener from the
// relay's segment: any host and port it can reach, named for SNI.
func validateNetworkPQCListener(address, serverName string) error {
	host, rawPort, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(rawPort)
	if err != nil || strings.TrimSpace(host) == "" || portErr != nil || port < 1 || port > 65535 {
		return errors.New("relay: a network PQC served-state probe needs a host:port listener")
	}
	if strings.TrimSpace(serverName) == "" {
		return errors.New("relay: a network PQC served-state probe needs verify_server_name")
	}
	return nil
}

// A posture change is a privileged local management write. Require one exact
// literal loopback origin, with no path or URL components that can redirect
// the connector away from the reviewed Envoy resource.
func validatePQCEnvoyEndpoint(raw string) error {
	if err := validateCoResidentEnvoyEndpoint(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("relay: PQC Envoy management URL must be one loopback origin")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return errors.New("relay: PQC Envoy management URL requires a literal loopback host and port")
	}
	return nil
}

func hostPQCPostureRegistry(intent PQCPostureIntent, client *http.Client) (*connector.Registry, error) {
	var target pqcEnvoyTarget
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
		return nil, errors.New("relay: PQC host target configuration is malformed")
	}
	network, err := pqcPostureNetworkVantage(intent.Vantage)
	if err != nil {
		return nil, err
	}
	if err := validatePQCPostureManagementEndpoint(network, target.Endpoint); err != nil {
		return nil, err
	}
	if target.SecretName == "" {
		return nil, errors.New("relay: PQC Envoy target has no SDS secret name")
	}
	if client == nil {
		return nil, errors.New("relay: PQC host management client is not configured")
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(&bounded) })
	registry.Register(envoy.New(target.Endpoint, target.SecretName))
	if err := registry.MarkTLSPostureCapable("envoy"); err != nil {
		return nil, err
	}
	return registry, nil
}

func executeHostPQCPosture(ctx context.Context, intent PQCPostureIntent, kind string, store *HostRollbackStore, client *http.Client, nativeProbe string) (PQCPostureReport, error) {
	if store == nil {
		return PQCPostureReport{}, errors.New("relay: PQC posture requires the machine-local predecessor store (--host-rollback-dir)")
	}
	if err := ValidatePQCPostureIntent(intent); err != nil {
		return PQCPostureReport{}, err
	}
	registry, err := hostPQCPostureRegistry(intent, client)
	if err != nil {
		return PQCPostureReport{}, err
	}
	mutation := connector.TLSPostureMutation{
		RunID: intent.RunID, FindingID: intent.AssetID, FindingKind: intent.FindingKind,
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		Connector: "envoy", Target: intent.Target, TargetConfig: intent.TargetConfig,
		Desired: intent.Desired, TenantID: store.tenantID,
	}
	if kind == KindPQCPosture {
		previous, err := store.PreparedPosture(intent.RunID, intent.TargetID, intent.TargetRevision, intent.Desired)
		if errors.Is(err, fs.ErrNotExist) {
			previous, err = registry.ReadTLSPosture(ctx, mutation)
			if err != nil {
				return PQCPostureReport{}, err
			}
			if err := store.PreparePosture(intent.RunID, intent.TargetID, intent.TargetRevision, previous, intent.Desired); err != nil {
				return PQCPostureReport{}, err
			}
		} else if err != nil {
			return PQCPostureReport{}, err
		}
		mutation.ExpectedPrevious = &previous
		receipt, err := registry.ApplyTLSPosture(ctx, mutation)
		if err != nil {
			return PQCPostureReport{}, err
		}
		if err := store.CommitPosture(intent.RunID, intent.TargetID, intent.TargetRevision, receipt.Observed); err != nil {
			return PQCPostureReport{}, err
		}
		served, err := probePQCServed(ctx, intent, true, nativeProbe)
		if err != nil {
			if intent.RollbackOnFailure {
				restoreErr := store.RestorePosture(intent.RunID, intent.TargetID, intent.TargetRevision, func(prior, applied connector.TLSPosture) error {
					mutation.Desired, mutation.ExpectedPrevious = prior, &applied
					_, restoreErr := registry.RestoreTLSPosture(ctx, mutation)
					if restoreErr != nil {
						return restoreErr
					}
					_, restoreErr = probePQCServed(ctx, intent, false, nativeProbe)
					return restoreErr
				})
				if restoreErr != nil {
					return PQCPostureReport{}, errors.Join(err, fmt.Errorf("relay: automatic PQC predecessor restore failed: %w", restoreErr))
				}
			}
			return PQCPostureReport{}, err
		}
		return PQCPostureReport{Operation: kind, Receipt: receipt, Served: served}, nil
	}
	if kind != KindPQCPostureRollback {
		return PQCPostureReport{}, fmt.Errorf("relay: unsupported PQC posture operation %q", kind)
	}
	var result connector.TLSPostureReceipt
	var served PQCPostureServed
	err = store.RestorePosture(intent.RunID, intent.TargetID, intent.TargetRevision, func(previous, desired connector.TLSPosture) error {
		mutation.Desired = previous
		mutation.ExpectedPrevious = &desired
		var restoreErr error
		result, restoreErr = registry.RestoreTLSPosture(ctx, mutation)
		if restoreErr != nil {
			return restoreErr
		}
		served, restoreErr = probePQCServed(ctx, intent, false, nativeProbe)
		return restoreErr
	})
	if err != nil {
		return PQCPostureReport{}, err
	}
	return PQCPostureReport{Operation: kind, Receipt: result, Served: served}, nil
}

func probePQCServed(ctx context.Context, intent PQCPostureIntent, hybrid bool, nativeProbe string) (PQCPostureServed, error) {
	options := []tlsprobe.Option{tlsprobe.WithServerName(intent.VerifyServerName)}
	if hybrid {
		options = append(options, tlsprobe.WithRequiredHybridGroup())
	}
	// The probe may fall back to the system OpenSSL, which dials outside the
	// agent (a dial control would turn the fallback off), so the destination is
	// resolved and checked before either attempt.
	if err := egress().CheckHostPort(ctx, intent.VerifyAddress); err != nil {
		return PQCPostureServed{}, fmt.Errorf("relay: PQC listener handshake failed: %w", err)
	}
	result, err := tlsprobe.ProbeWithNativeFallback(ctx, nativeProbe, intent.VerifyAddress, options...)
	if err != nil {
		return PQCPostureServed{}, fmt.Errorf("relay: PQC listener handshake failed: %w", err)
	}
	if len(result.PeerCertificates) == 0 {
		return PQCPostureServed{}, errors.New("relay: PQC listener served no leaf")
	}
	return PQCPostureServed{
		Address: intent.VerifyAddress, ServerName: intent.VerifyServerName,
		TLSVersion: result.TLSVersion, CipherSuite: result.CipherSuite,
		KeyExchangeGroup: result.KeyExchangeGroup,
		LeafFingerprint:  crypto.SHA256Hex(result.PeerCertificates[0]),
	}, nil
}

func runHostPQCPosture(ctx context.Context, ch Channel, client *http.Client, store *HostRollbackStore, nativeProbe string, job Job) bool {
	var intent PQCPostureIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "PQC posture intent is malformed")
		return false
	}
	result, err := executeHostPQCPosture(ctx, intent, job.Kind, store, client, nativeProbe)
	if err != nil {
		// The signed public detail stays generic. The host-local diagnostic
		// log retains the native failure so its operator can repair the path.
		log.Printf("trstctl-agent: PQC posture job %d attempt %d failed: %v", job.JobID, job.Attempt, err)
		report(ctx, ch, job, OutcomeFailed, "PQC posture mutation or readback failed on assigned host")
		return false
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "PQC posture readback could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, transport.JobOutcomeVerified, string(encoded), result.Digest())
	return true
}
