// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This executor is reached only by the existing bounded discovery/outbox pool.
// Native IAM facts and imported coverage stay distinguishable in each finding.
func (d *issuanceDispatcher) executeCloudMachineEntitlementRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	cfg, err := assessment.DecodeSource(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	report := netscan.Report{Targets: len(cfg.Principals)}
	if run.DryRun {
		return report, "succeeded", "", nil
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	if err := d.egress.CheckURL(endpoint); err != nil {
		return report, "failed", err.Error(), nil
	}
	ref := strings.TrimPrefix(cfg.SessionFileRef, "env:")
	sessionPath, ok := os.LookupEnv(ref)
	if !ok || !filepath.IsAbs(sessionPath) {
		return report, "failed", "operator-approved STS session file path is not configured", nil
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.PrivateEgressCIDRs))
	for _, raw := range cfg.PrivateEgressCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return report, "failed", "invalid private egress prefix", nil
		}
		prefixes = append(prefixes, prefix)
	}
	reader, err := awsiam.New(awsiam.Config{Endpoint: endpoint, Region: cfg.Region, CAPEM: []byte(cfg.CAPEM), AllowInsecureLoopback: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes, UseCredentials: awsiam.SessionFile(sessionPath, time.Now)})
	if err != nil {
		return report, "failed", err.Error(), nil
	}
	capture, captureErr := reader.Collect(ctx, cfg.Principals)
	var failures []string
	if captureErr != nil {
		failures = append(failures, captureErr.Error())
		report.Failed = len(cfg.Principals) - len(capture.Identities)
	}
	now := capture.CollectedAt
	if d.cloudEntitlementNow != nil {
		now = d.cloudEntitlementNow().UTC()
	}
	for _, identity := range capture.Identities {
		value, err := assessment.Assess(identity, cfg.Input, now)
		if err != nil {
			report.Failed++
			failures = append(failures, err.Error())
			continue
		}
		value.SourceOrigin = endpoint
		value.SourceFingerprint, err = assessment.SourceFingerprint(cfg)
		if err != nil {
			return report, "", "", err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return report, "", "", err
		}
		fingerprint, err := assessment.Fingerprint(value)
		if err != nil {
			return report, "", "", err
		}
		if len(raw) > 512<<10 {
			return report, "failed", "cloud machine assessment exceeds event bound", nil
		}
		_, err = d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{RunID: run.ID, SourceID: src.ID, Kind: assessment.FindingKind, Ref: "aws-iam:" + identity.Principal.ARN, Provenance: "aws-iam:" + identity.Principal.AccountID, Fingerprint: fingerprint, RiskScore: value.RiskScore, Metadata: raw})
		if err != nil {
			return report, "", "", err
		}
		report.Discovered++
	}
	if report.Failed > 0 {
		state := "failed"
		if report.Discovered > 0 {
			state = "partial"
		}
		return report, state, strings.Join(failures, "; "), nil
	}
	return report, "succeeded", "", nil
}
