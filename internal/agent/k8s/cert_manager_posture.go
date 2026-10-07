// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"encoding/base64"
	"encoding/pem"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// certManagerRequestPosture observes the API server's CertificateRequest
// status. A name or SAN is never used as an ownership claim: the only parent
// link accepted here is a controller ownerReference with a Kubernetes UID.
// The public hash is the DER fingerprint of status.certificate's first leaf.
func certManagerRequestPosture(cr map[string]any, backed bool, issuerGroup string) PostureResource {
	spec, _ := cr["spec"].(map[string]any)
	ref, _ := spec["issuerRef"].(map[string]any)
	if stringField(ref, "group") != issuerGroup {
		return PostureResource{}
	}
	resource := postureResource(cr)
	meta, _ := cr["metadata"].(map[string]any)
	if owners, ok := meta["ownerReferences"].([]any); ok {
		for _, entry := range owners {
			owner, _ := entry.(map[string]any)
			if owner["apiVersion"] == "cert-manager.io/v1" && owner["kind"] == "Certificate" && owner["controller"] == true {
				resource.ParentUID = stringField(owner, "uid")
				resource.ParentName = stringField(owner, "name")
				break
			}
		}
	}
	status, _ := cr["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	ready, denied := false, false
	for _, entry := range conditions {
		condition, _ := entry.(map[string]any)
		if condition["status"] != "True" {
			continue
		}
		switch condition["type"] {
		case "Ready":
			ready = true
		case "Denied":
			denied = true
		}
	}
	switch {
	case denied:
		resource.State, resource.Reason = "failed", "denied"
	case ready:
		if !isApproved(cr) {
			resource.State, resource.Reason = "failed", "approval_missing"
			return resource
		}
		encoded := stringField(status, "certificate")
		chain, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(chain) == 0 {
			resource.State, resource.Reason = "failed", "invalid_certificate"
			return resource
		}
		info, err := certinfo.Inspect(chain)
		if err != nil {
			resource.State, resource.Reason = "failed", "invalid_certificate"
			return resource
		}
		requestPEM, err := base64.StdEncoding.DecodeString(stringField(spec, "request"))
		if err != nil {
			resource.State, resource.Reason = "failed", "invalid_request"
			return resource
		}
		block, trailing := pem.Decode(requestPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" || len(trailing) != 0 {
			resource.State, resource.Reason = "failed", "invalid_request"
			return resource
		}
		matches, err := certinfo.LeafMatchesCSR(block.Bytes, chain)
		if err != nil {
			resource.State, resource.Reason = "failed", "invalid_request"
			return resource
		}
		if !matches {
			resource.State, resource.Reason = "failed", "certificate_key_mismatch"
			return resource
		}
		resource.PublicHash = info.SHA256Fingerprint
		if resource.ParentUID == "" || resource.ParentName == "" {
			resource.State, resource.Reason = "failed", "missing_owner"
			return resource
		}
		resource.State, resource.Reason = "ready", "signed"
	case !isApproved(cr):
		resource.State, resource.Reason = "pending", "approval_pending"
	case !backed:
		resource.State, resource.Reason = "pending", "issuer_not_found"
	default:
		resource.State, resource.Reason = "pending", "awaiting_sign"
	}
	return resource
}
