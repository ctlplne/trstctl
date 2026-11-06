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
	"trstctl.com/trstctl/internal/cloudentitlements/azureiam"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (d *issuanceDispatcher) executeAzureMachineIdentityRun(ctx context.Context, tenantID string, source store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	cfg, err := azureiam.DecodeConfig(source.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	report := netscan.Report{Targets: len(cfg.PrincipalIDs)}
	if run.DryRun {
		return report, "succeeded", "", nil
	}
	for _, endpoint := range azureiam.Endpoints(cfg) {
		if err := d.egress.CheckURL(endpoint); err != nil {
			return report, "failed", err.Error(), nil
		}
	}
	var borrows []bearerhttp.Borrow
	for _, ref := range []string{cfg.GraphTokenFileRef, cfg.ARMTokenFileRef} {
		name, ok := strings.CutPrefix(ref, "env:")
		path, present := os.LookupEnv(name)
		if !ok || !present || !filepath.IsAbs(path) {
			return report, "failed", "operator-approved Azure reader token file is not configured", nil
		}
		borrows = append(borrows, bearerhttp.FileToken(path))
	}
	values, captureErr := azureiam.Collect(ctx, cfg, borrows[0], borrows[1], time.Now())
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return report, "", "", err
		}
		fingerprint, err := azureiam.Fingerprint(value)
		if err != nil {
			return report, "", "", err
		}
		_, err = d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{RunID: run.ID, SourceID: source.ID, Kind: azureiam.FindingKind, Ref: "azure-entra:" + cfg.TenantID + ":" + value.Identity.ID, Provenance: "azure-entra:subscriptions/" + cfg.SubscriptionID, Fingerprint: fingerprint, RiskScore: value.RiskScore, Metadata: raw})
		if err != nil {
			return report, "", "", err
		}
		report.Discovered++
		incomplete := value.AppRoleCoverage == "unavailable" || value.FederationCoverage == "unavailable" || value.RBACCoverage == "unavailable" || (cfg.ReadBetaSignins && value.ActivityCoverage == "unavailable")
		for _, binding := range value.RBAC {
			incomplete = incomplete || binding.DefinitionCoverage == "unavailable"
		}
		for _, binding := range value.AppRoles {
			incomplete = incomplete || binding.Coverage == "unavailable"
		}
		if value.Identity.Type == "ManagedIdentity" {
			incomplete = incomplete || value.ManagedIdentityCoverage == "unavailable"
		}
		if incomplete {
			report.Failed++
		}
	}
	if captureErr != nil {
		report.Failed += len(cfg.PrincipalIDs) - len(values)
	}
	if report.Failed > 0 || captureErr != nil {
		state := "failed"
		if report.Discovered > 0 {
			state = "partial"
		}
		message := "some selected Azure metadata reads were unavailable; inspect finding coverage"
		if captureErr != nil && !errors.Is(captureErr, context.Canceled) {
			message = captureErr.Error()
		}
		return report, state, message, nil
	}
	return report, "succeeded", "", nil
}
