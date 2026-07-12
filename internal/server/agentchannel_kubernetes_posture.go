// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type boundIdempotentRunner interface {
	DoBound(context.Context, string, string, string, func(context.Context) ([]byte, error)) ([]byte, error)
}

// ReportKubernetesPosture accepts one fixed-shape, metadata-only controller
// report over the served agent mTLS channel. Tenant and controller identity come
// from the verified peer certificate, then one immutable event becomes the sole
// source for both PostgreSQL posture projections (AN-1/AN-2/AN-5).
func (a *agentService) ReportKubernetesPosture(ctx context.Context, req *transport.KubernetesPostureRequest) (*transport.KubernetesPostureResponse, error) {
	info, err := a.peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "Kubernetes posture report is required")
	}
	if a.log == nil || a.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "Kubernetes posture event projection is not configured")
	}
	idem, ok := a.idem.(boundIdempotentRunner)
	if !ok || idem == nil {
		return nil, status.Error(codes.FailedPrecondition, "Kubernetes posture idempotency is not configured")
	}

	report := projections.KubernetesControllerPostureReported{
		ReportID: req.ReportID, AgentID: agentRowID(info.TenantID, info.CommonName),
		ClusterID: req.ClusterID, ReconcileIntervalSeconds: req.ReconcileIntervalSeconds,
		CertificateSigning: transportKubernetesPostureSection(req.CertificateSigning),
		TrustBundles:       transportKubernetesPostureSection(req.TrustBundles),
	}
	sortKubernetesPostureResources(report.CertificateSigning.Resources)
	sortKubernetesPostureResources(report.TrustBundles.Resources)
	payload, err := projections.MarshalKubernetesPostureReport(report)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid Kubernetes posture report: %v", err)
	}
	binding := "sha256:" + crypto.SHA256Hex(payload)
	key := "agent-kubernetes-posture:" + report.AgentID + ":" + report.ReportID
	eventID := "k8s-posture-" + crypto.SHA256Hex([]byte(info.TenantID+"\x00"+report.AgentID+"\x00"+report.ReportID))
	encoded, err := idem.DoBound(ctx, info.TenantID, key, binding, func(ctx context.Context) ([]byte, error) {
		ev, err := a.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventKubernetesControllerPostureReported, TenantID: info.TenantID, Data: payload,
			Actor: &events.Actor{Subject: "agent:" + info.CommonName, Roles: []string{"agent"}},
		})
		if err != nil {
			return nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return nil, err
		}
		return json.Marshal(transport.KubernetesPostureResponse{
			TenantID: info.TenantID, ReportID: report.ReportID, RecordedAtUnix: ev.Time.Unix(),
		})
	})
	if err != nil {
		switch {
		case err == orchestrator.ErrIdempotencyConflict:
			return nil, status.Error(codes.AlreadyExists, "Kubernetes posture report id was already used for different metadata")
		case err == orchestrator.ErrInProgress:
			return nil, status.Error(codes.Aborted, "Kubernetes posture report is already being recorded")
		default:
			return nil, status.Errorf(codes.Internal, "record Kubernetes posture report: %v", err)
		}
	}
	var response transport.KubernetesPostureResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		return nil, status.Error(codes.Internal, "decode Kubernetes posture report receipt")
	}
	return &response, nil
}

func (b *bulkheadedAgentService) ReportKubernetesPosture(ctx context.Context, req *transport.KubernetesPostureRequest) (*transport.KubernetesPostureResponse, error) {
	next, ok := b.next.(transport.KubernetesPostureServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Kubernetes posture reporting is not implemented")
	}
	return runAgentBulkhead(ctx, b.pool, "kubernetes_posture", b.metrics, func(ctx context.Context) (*transport.KubernetesPostureResponse, error) {
		return next.ReportKubernetesPosture(ctx, req)
	})
}

func transportKubernetesPostureSection(section transport.KubernetesPostureSection) projections.KubernetesPostureSection {
	resources := make([]projections.KubernetesPostureResource, 0, len(section.Resources))
	for _, resource := range section.Resources {
		resources = append(resources, projections.KubernetesPostureResource{
			Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID,
			ResourceVersion: resource.ResourceVersion, State: resource.State,
			Reason: resource.Reason, PublicHash: resource.PublicHash,
		})
	}
	return projections.KubernetesPostureSection{Complete: section.Complete, FailureCode: section.FailureCode, Resources: resources}
}

func sortKubernetesPostureResources(resources []projections.KubernetesPostureResource) {
	sort.Slice(resources, func(i, j int) bool {
		left, right := resources[i], resources[j]
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.UID < right.UID
	})
}
