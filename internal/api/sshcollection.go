// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"net/http"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/sshcollection"
)

func (a *API) previewSSHCollection(ctx context.Context, tenantID string, raw []byte, preview *discoveryPlanPreviewResponse) error {
	cfg, err := sshcollection.DecodeConfig(raw)
	if err != nil {
		return errStatus(http.StatusBadRequest, err.Error())
	}
	command := cfg.Resolve()
	segment, err := a.store.GetDiscoverySegmentByName(ctx, tenantID, command.Segment)
	if err != nil {
		return errStatus(http.StatusBadRequest, "declare the SSH collection segment first")
	}
	if segment.Excluded {
		return errStatus(http.StatusBadRequest, "SSH collection segment is excluded")
	}
	if err := segmentscan.ValidateDeclaredSegment(command.ScopeIntent(), segment.Ranges); err != nil {
		return errStatus(http.StatusBadRequest, err.Error())
	}
	readiness, err := a.orch.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, command.RequiredAgentID, sshcollection.Destination)
	if err != nil {
		return err
	}
	preview.Ready = readiness.Ready
	preview.ConnectionOrigin = readiness.ConnectionOrigin
	preview.Protocol = sshcollection.SourceKind
	preview.BlockedReasons = []string{}
	if !readiness.Ready {
		preview.BlockedReasons = append(preview.BlockedReasons, readiness.BlockedReason)
	}
	if reason := discoveryLiteralAddressBlocker(command.ScopeIntent()); reason != "" {
		preview.Ready = false
		preview.BlockedReasons = append(preview.BlockedReasons, reason)
	}
	preview.Segment = command.Segment
	preview.NormalizedTargets = command.ScopeIntent().Targets
	preview.NormalizedTargetCount = len(command.Hosts)
	preview.Concurrency = 8
	preview.QueueDepth = 100
	preview.EstimatedUpperSeconds = 90
	return nil
}
