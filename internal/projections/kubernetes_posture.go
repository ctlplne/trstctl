// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const EventKubernetesControllerPostureReported = "kubernetes.controller.posture_reported"

const maxKubernetesPostureResources = 2000

// KubernetesPostureResource is the immutable, metadata-only observation of one
// Kubernetes object. PublicHash is a digest of public material; this event shape
// has no field capable of carrying a CSR, certificate, trust bundle, token, or key.
type KubernetesPostureResource struct {
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	PublicHash      string `json:"public_hash,omitempty"`
}

// KubernetesPostureSection is one independently honest controller surface. A
// failed/incomplete reconcile cannot be represented as a successful empty list.
type KubernetesPostureSection struct {
	Complete    bool                        `json:"complete"`
	FailureCode string                      `json:"failure_code,omitempty"`
	Resources   []KubernetesPostureResource `json:"resources"`
}

// KubernetesControllerPostureReported is emitted by the tenant-authenticated
// agent channel after a real controller reconcile. AgentID is derived from the
// verified client certificate by the server, never trusted from the request.
type KubernetesControllerPostureReported struct {
	ReportID                 string                   `json:"report_id"`
	AgentID                  string                   `json:"agent_id"`
	ClusterID                string                   `json:"cluster_id"`
	ReconcileIntervalSeconds int                      `json:"reconcile_interval_seconds"`
	CertificateSigning       KubernetesPostureSection `json:"certificate_signing_requests"`
	TrustBundles             KubernetesPostureSection `json:"trust_bundles"`
}

func (p *Projector) applyKubernetesPostureTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventKubernetesControllerPostureReported {
		return false, nil
	}
	var payload KubernetesControllerPostureReported
	decoder := json.NewDecoder(bytes.NewReader(e.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := validateKubernetesPostureReport(payload); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	for _, section := range []struct {
		capability string
		posture    KubernetesPostureSection
	}{
		{store.KubernetesPostureCertificateSigningRequests, payload.CertificateSigning},
		{store.KubernetesPostureTrustBundles, payload.TrustBundles},
	} {
		resources := make([]store.KubernetesPostureResource, 0, len(section.posture.Resources))
		for _, resource := range section.posture.Resources {
			resources = append(resources, store.KubernetesPostureResource{
				Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID,
				ResourceVersion: resource.ResourceVersion, State: resource.State,
				Reason: resource.Reason, PublicHash: resource.PublicHash,
			})
		}
		if err := p.store.ApplyKubernetesControllerPostureTx(ctx, tx, store.KubernetesControllerPosture{
			TenantID: e.TenantID, ControllerID: payload.AgentID, ClusterID: payload.ClusterID,
			Capability: section.capability, ReportID: payload.ReportID,
			ReconcileComplete: section.posture.Complete, FailureCode: section.posture.FailureCode,
			ReconcileIntervalSeconds: payload.ReconcileIntervalSeconds, Resources: resources,
			ReportedAt: e.Time, EventSequence: e.Sequence,
		}); err != nil {
			return true, err
		}
	}
	return true, nil
}

func validateKubernetesPostureReport(report KubernetesControllerPostureReported) error {
	if _, err := uuid.Parse(report.ReportID); err != nil {
		return fmt.Errorf("report_id must be a UUID")
	}
	if _, err := uuid.Parse(report.AgentID); err != nil {
		return fmt.Errorf("agent_id must be a UUID")
	}
	if !validKubernetesPublicIdentity(report.ClusterID) {
		return fmt.Errorf("cluster_id must be a sha256 public identity")
	}
	if report.ReconcileIntervalSeconds < 1 || report.ReconcileIntervalSeconds > 86400 {
		return fmt.Errorf("reconcile_interval_seconds must be between 1 and 86400")
	}
	if err := validateKubernetesPostureSection(report.CertificateSigning); err != nil {
		return fmt.Errorf("certificate_signing_requests: %w", err)
	}
	if err := validateKubernetesPostureSection(report.TrustBundles); err != nil {
		return fmt.Errorf("trust_bundles: %w", err)
	}
	return nil
}

func validateKubernetesPostureSection(section KubernetesPostureSection) error {
	if section.Complete && section.FailureCode != "" {
		return fmt.Errorf("a complete reconcile cannot carry failure_code")
	}
	if !section.Complete && section.FailureCode != "not_reconciled" && section.FailureCode != "reconcile_failed" {
		return fmt.Errorf("an incomplete reconcile requires a closed-set failure_code")
	}
	if len(section.Resources) > maxKubernetesPostureResources {
		return fmt.Errorf("resource count exceeds %d", maxKubernetesPostureResources)
	}
	seen := make(map[string]struct{}, len(section.Resources))
	for _, resource := range section.Resources {
		if !validKubernetesDNSSubdomain(resource.Name, 253) || resource.UID == "" || len(resource.UID) > 128 || resource.ResourceVersion == "" || len(resource.ResourceVersion) > 128 || (resource.Namespace != "" && !validKubernetesDNSSubdomain(resource.Namespace, 63)) {
			return fmt.Errorf("resource identity/version fields are missing or over limit")
		}
		if strings.TrimSpace(resource.Name) != resource.Name || strings.TrimSpace(resource.Namespace) != resource.Namespace || strings.TrimSpace(resource.UID) != resource.UID || strings.TrimSpace(resource.ResourceVersion) != resource.ResourceVersion {
			return fmt.Errorf("resource identity/version fields must be canonical")
		}
		if !validKubernetesOpaqueMetadata(resource.UID) || !validKubernetesOpaqueMetadata(resource.ResourceVersion) {
			return fmt.Errorf("resource uid/version contains non-metadata characters")
		}
		if resource.State != "ready" && resource.State != "pending" && resource.State != "failed" {
			return fmt.Errorf("resource state %q is not allowed", resource.State)
		}
		if !validKubernetesPostureReason(resource.Reason) {
			return fmt.Errorf("resource reason %q is not allowed", resource.Reason)
		}
		if resource.PublicHash != "" && !validLowerHex(resource.PublicHash, 64) {
			return fmt.Errorf("public_hash must be lowercase SHA-256 hex")
		}
		identity := resource.Namespace + "\x00" + resource.Name + "\x00" + resource.UID
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate resource identity")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func validKubernetesDNSSubdomain(value string, limit int) bool {
	if value == "" || len(value) > limit || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	labelLength := 0
	for i, char := range value {
		switch {
		case char == '.':
			if labelLength == 0 || labelLength > 63 || value[i-1] == '-' {
				return false
			}
			labelLength = 0
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			labelLength++
		case char == '-':
			if labelLength == 0 {
				return false
			}
			labelLength++
		default:
			return false
		}
	}
	return labelLength > 0 && labelLength <= 63 && value[len(value)-1] != '-'
}

func validKubernetesOpaqueMetadata(value string) bool {
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-/", char) {
			continue
		}
		return false
	}
	return value != ""
}

func validKubernetesPostureReason(reason string) bool {
	switch reason {
	case "signed", "already_ready", "approval_pending", "issuer_not_found", "denied", "failed", "awaiting_sign", "distributed", "controller_error":
		return true
	default:
		return false
	}
}

func validKubernetesPublicIdentity(identity string) bool {
	return strings.HasPrefix(identity, "sha256:") && validLowerHex(strings.TrimPrefix(identity, "sha256:"), 64)
}

func validLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// MarshalKubernetesPostureReport returns the stable event payload used by the
// authenticated producer and tests. Keeping this in the projection contract
// prevents a second, subtly different event shape from emerging.
func MarshalKubernetesPostureReport(report KubernetesControllerPostureReported) ([]byte, error) {
	if err := validateKubernetesPostureReport(report); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}
