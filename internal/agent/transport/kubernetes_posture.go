// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KubernetesPostureResource carries Kubernetes identity/version/status metadata
// and a hash of public material. Its fixed shape intentionally has no raw payload,
// error-message, credential, CSR, certificate, or trust-bundle field.
type KubernetesPostureResource struct {
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	PublicHash      string `json:"public_hash,omitempty"`
}

type KubernetesPostureSection struct {
	Complete    bool                        `json:"complete"`
	FailureCode string                      `json:"failure_code,omitempty"`
	Resources   []KubernetesPostureResource `json:"resources"`
}

// KubernetesPostureRequest is one idempotent post-reconcile report. Tenant and
// controller identity are absent: the server derives both from verified mTLS.
type KubernetesPostureRequest struct {
	ReportID                 string                   `json:"report_id"`
	ClusterID                string                   `json:"cluster_id"`
	ReconcileIntervalSeconds int                      `json:"reconcile_interval_seconds"`
	CertificateSigning       KubernetesPostureSection `json:"certificate_signing_requests"`
	TrustBundles             KubernetesPostureSection `json:"trust_bundles"`
}

type KubernetesPostureResponse struct {
	TenantID       string `json:"tenant_id"`
	ReportID       string `json:"report_id"`
	RecordedAtUnix int64  `json:"recorded_at_unix"`
}

// KubernetesPostureServiceServer is an optional extension implemented by the
// shipped control plane. Keeping it separate preserves source compatibility for
// older embedders of AgentServiceServer; the registered method returns
// Unimplemented when an old server is used.
type KubernetesPostureServiceServer interface {
	ReportKubernetesPosture(context.Context, *KubernetesPostureRequest) (*KubernetesPostureResponse, error)
}

func kubernetesPostureHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KubernetesPostureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	extended, ok := srv.(KubernetesPostureServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Kubernetes posture reporting is not implemented")
	}
	if interceptor == nil {
		return extended.ReportKubernetesPosture(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodKubernetesPosture}
	handler := func(ctx context.Context, req any) (any, error) {
		return extended.ReportKubernetesPosture(ctx, req.(*KubernetesPostureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ReportKubernetesPosture sends one metadata-only controller report over the
// already authenticated agent mTLS connection.
func (c *AgentClient) ReportKubernetesPosture(ctx context.Context, req *KubernetesPostureRequest) (*KubernetesPostureResponse, error) {
	out := new(KubernetesPostureResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodKubernetesPosture, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}
