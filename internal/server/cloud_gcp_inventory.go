// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
	"trstctl.com/trstctl/internal/cloudentitlements/gcpiam"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (d *issuanceDispatcher) executeGCPMachineIdentityRun(ctx context.Context, tenantID string, source store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	cfg, err := gcpiam.DecodeConfig(source.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	report := netscan.Report{Targets: len(cfg.ServiceAccounts)}
	if run.DryRun {
		return report, "succeeded", "", nil
	}
	for _, endpoint := range gcpiam.Endpoints(cfg) {
		if err := d.egress.CheckURL(endpoint); err != nil {
			return report, "failed", err.Error(), nil
		}
	}
	name, ok := strings.CutPrefix(cfg.TokenFileRef, "env:")
	path, present := os.LookupEnv(name)
	if !ok || !present || !filepath.IsAbs(path) {
		return report, "failed", "operator-approved GCP reader token file is not configured", nil
	}
	values, captureErr := gcpiam.Collect(ctx, cfg, bearerhttp.FileToken(path), time.Now())
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return report, "", "", err
		}
		fingerprint, err := gcpiam.Fingerprint(value)
		if err != nil {
			return report, "", "", err
		}
		_, err = d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{RunID: run.ID, SourceID: source.ID, Kind: gcpiam.FindingKind, Ref: "gcp-iam:" + value.Identity.NativeID, Provenance: "gcp-iam:projects/" + cfg.Project, Fingerprint: fingerprint, RiskScore: value.RiskScore, Metadata: raw})
		if err != nil {
			return report, "", "", err
		}
		report.Discovered++
		incompleteRole := false
		for _, binding := range value.PolicyBindings {
			if binding.PermissionCoverage == "unavailable" {
				incompleteRole = true
			}
		}
		if incompleteRole || value.KeysCoverage == "unavailable" || value.TrustCoverage == "unavailable" || value.PolicyCoverage == "unavailable" || (cfg.ActivityLookbackDays > 0 && value.ActivityCoverage == "unavailable") {
			report.Failed++
		}
	}
	if captureErr != nil {
		report.Failed += len(cfg.ServiceAccounts) - len(values)
	}
	if report.Failed > 0 || captureErr != nil {
		state := "failed"
		if report.Discovered > 0 {
			state = "partial"
		}
		message := "some selected GCP metadata reads were unavailable; inspect finding coverage"
		if captureErr != nil && !errors.Is(captureErr, context.Canceled) {
			message = captureErr.Error()
		}
		return report, state, message, nil
	}
	return report, "succeeded", "", nil
}
