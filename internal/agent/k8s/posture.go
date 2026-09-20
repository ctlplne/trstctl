// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

// PostureResource is the controller-side metadata-only view of one reconciled
// object. It deliberately cannot hold raw Kubernetes object JSON or credential
// material.
type PostureResource struct {
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	State           string
	Reason          string
	PublicHash      string
}

type PostureSection struct {
	Complete    bool
	FailureCode string
	Resources   []PostureResource
}

type ControllerPostureReport struct {
	ReportID                 string
	ClusterID                string
	ReconcileIntervalSeconds int
	CertificateSigning       PostureSection
	TrustBundles             PostureSection
}

// PostureReport turns one actual reconcile result into the bounded wire-facing
// report. A failed or not-reached surface is explicit; it never masquerades as a
// successful zero-object reconcile.
func (r IssuerReconcileResult) PostureReport(clusterID string, reconcileEvery time.Duration) ControllerPostureReport {
	seconds := int(reconcileEvery / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 86400 {
		seconds = 86400
	}
	csrFailure := r.KubernetesCSRFailureCode
	if !r.KubernetesCSRComplete && csrFailure == "" {
		csrFailure = "not_reconciled"
	}
	bundleFailure := r.TrustBundleFailureCode
	if !r.TrustBundleComplete && bundleFailure == "" {
		bundleFailure = "not_reconciled"
	}
	return ControllerPostureReport{
		ReportID: uuid.NewString(), ClusterID: clusterID, ReconcileIntervalSeconds: seconds,
		CertificateSigning: PostureSection{Complete: r.KubernetesCSRComplete, FailureCode: csrFailure, Resources: r.KubernetesCSRPosture},
		TrustBundles:       PostureSection{Complete: r.TrustBundleComplete, FailureCode: bundleFailure, Resources: r.TrustBundlePosture},
	}
}

func postureResource(obj map[string]any) PostureResource {
	meta, _ := obj["metadata"].(map[string]any)
	return PostureResource{
		Namespace:       stringField(meta, "namespace"),
		Name:            stringField(meta, "name"),
		UID:             stringField(meta, "uid"),
		ResourceVersion: stringField(meta, "resourceVersion"),
	}
}

func stringField(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func publicRequestHash(obj map[string]any) string {
	spec, _ := obj["spec"].(map[string]any)
	request, _ := spec["request"].(string)
	if request == "" {
		return ""
	}
	csrDER, err := decodeKubernetesCSRRequest(request)
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(csrDER)
}

func kubernetesCSRPosture(obj map[string]any, backed bool) PostureResource {
	resource := postureResource(obj)
	resource.PublicHash = publicRequestHash(obj)
	switch {
	case kubernetesCSRConditionStatus(obj, "Denied") == "True":
		resource.State, resource.Reason = "failed", "denied"
	case kubernetesCSRConditionStatus(obj, "Failed") == "True":
		resource.State, resource.Reason = "failed", "failed"
	case isKubernetesCSRFinished(obj):
		resource.State, resource.Reason = "ready", "already_ready"
	case !isKubernetesCSRApproved(obj):
		resource.State, resource.Reason = "pending", "approval_pending"
	case !backed:
		resource.State, resource.Reason = "pending", "issuer_not_found"
	default:
		resource.State, resource.Reason = "pending", "awaiting_sign"
	}
	return resource
}

func trustBundlePosture(obj map[string]any) PostureResource {
	resource := postureResource(obj)
	status, _ := obj["status"].(map[string]any)
	resource.PublicHash = stringField(status, "bundleSHA256")
	if isReady(obj) {
		resource.State, resource.Reason = "ready", "already_ready"
	} else {
		resource.State, resource.Reason = "pending", "awaiting_sign"
	}
	return resource
}

func failedPosture(resource PostureResource) PostureResource {
	resource.State, resource.Reason = "failed", "controller_error"
	return resource
}
