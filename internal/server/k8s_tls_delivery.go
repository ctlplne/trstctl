// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Kubernetes TLS delivery statuses a run reports per resource.
const (
	kubernetesTLSDeliveryQueued = "delivery_queued"
	kubernetesTLSDelivered      = "delivered"
	kubernetesTLSNotDelivered   = "not_delivered"
)

// kubernetesTLSNoClusterAgent says why a resource is not delivered when its
// source binds no in-cluster agent.
const kubernetesTLSNoClusterAgent = "no in-cluster agent is bound to this source: set cluster_agent_id to the host-role " +
	"agent running in the cluster and owner_id to the owner of these certificates. That agent generates each key " +
	"inside the cluster, sends only a CSR and writes the Secret itself; until one is bound, no certificate was " +
	"issued, no key was generated and nothing was written to the cluster"

// kubernetesTLSAttributesKey is the identity attribute recording which
// Kubernetes resource an identity serves and the hosts its TLS block names.
const kubernetesTLSAttributesKey = "kubernetes_tls"

type kubernetesTLSAttributes struct {
	SourceID string   `json:"source_id"`
	Resource string   `json:"resource"`
	Hosts    []string `json:"hosts"`
}

var kubernetesTLSDeliveryNamespace = uuid.MustParse("4f0c2a2e-6c1b-5a8d-9e3f-7b2d1c0e9a84")

func kubernetesTLSStableID(tenantID, sourceID, ref, part string) string {
	return uuid.NewSHA1(kubernetesTLSDeliveryNamespace, []byte(tenantID+"\x1f"+sourceID+"\x1f"+ref+"\x1f"+part)).String()
}

// deliverKubernetesTLSResource turns one resource of a bound source into
// delivery the cert-manager way: a k8s_secret target for the Secret it names,
// bound to the cluster agent; an identity for its hosts; and, while that
// identity has not been issued, the issuance that hands the agent its renewal
// job. The control plane generates no key here. It returns the per-resource
// status and the reason when the resource is not delivered. Errors are only
// for the datastore; a resource the binding cannot serve is a reason, not a
// failed run.
func (d *issuanceDispatcher) deliverKubernetesTLSResource(ctx context.Context, tenantID string, src store.DiscoverySource,
	delivery k8stls.Delivery, f k8stls.Finding) (status, reason string, err error) {
	targetConfig := map[string]string{
		"namespace": f.Namespace, "secret_name": f.TLSSecretName,
		custody.ExecutorConfigKey: custody.ExecutorAgent, "required_agent_id": delivery.ClusterAgentID,
	}
	if delivery.VerifyAddress != "" {
		targetConfig[verifyAddressKey] = delivery.VerifyAddress
		targetConfig[verifyServerNameKey] = f.CommonName
	}
	rawConfig, err := json.Marshal(targetConfig)
	if err != nil {
		return "", "", err
	}
	if _, err := d.store.ValidateHostTargetAssignment(ctx, tenantID, relay.KubernetesSecretConnector, rawConfig); err != nil {
		return kubernetesTLSNotDelivered, "the bound cluster agent cannot deliver: " + err.Error(), nil
	}
	if _, err := d.store.GetOwner(ctx, tenantID, delivery.OwnerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kubernetesTLSNotDelivered, "owner_id names no owner in this tenant", nil
		}
		return "", "", err
	}

	targetID := kubernetesTLSStableID(tenantID, src.ID, f.Ref, "target")
	target, err := d.store.GetDeploymentTarget(ctx, tenantID, targetID)
	switch {
	case errors.Is(err, pgx.ErrNoRows), err == nil && (!target.Enabled || !sameJSONObject(target.Config, rawConfig)):
		// Created on the first run; re-saved only when the binding changed, so a
		// rerun appends nothing.
		target, err = d.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			ID: targetID, Name: "k8s:" + f.Namespace + "/" + f.TLSSecretName, Type: relay.KubernetesSecretConnector,
			Config: rawConfig, Enabled: true, EnabledSet: true,
		})
		if err != nil {
			return "", "", err
		}
	case err != nil:
		return "", "", err
	}

	attributes, err := json.Marshal(map[string]any{kubernetesTLSAttributesKey: kubernetesTLSAttributes{
		SourceID: src.ID, Resource: f.Ref, Hosts: f.DNSNames,
	}})
	if err != nil {
		return "", "", err
	}
	identityID := kubernetesTLSStableID(tenantID, src.ID, f.Ref, "identity")
	if existing, err := d.store.GetIdentity(ctx, tenantID, identityID); err == nil && existing.OwnerID != delivery.OwnerID {
		return kubernetesTLSNotDelivered, "this resource's identity belongs to another owner; " +
			"set owner_id back to that owner or retire the identity", nil
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	ident, err := d.orch.EnsureIdentity(ctx, tenantID, identityID, store.Identity{
		Kind: store.KindX509Certificate, Name: f.CommonName, OwnerID: delivery.OwnerID, Attributes: attributes,
	})
	if err != nil {
		return "", "", err
	}
	if deploymentTargetID(ident.Attributes) != target.ID {
		if ident, err = d.orch.BindIdentityDeploymentTarget(ctx, tenantID, ident.ID, target); err != nil {
			return "", "", err
		}
	}

	state, err := d.orch.State(ctx, tenantID, ident.ID)
	if err != nil {
		return "", "", err
	}
	switch state {
	case orchestrator.StateRequested:
		if err := d.orch.TransitionWithIdempotency(ctx, tenantID, ident.ID, orchestrator.StateIssued,
			"Kubernetes TLS delivery for "+f.Ref, "k8s-tls-issue:"+src.ID+":"+f.Ref); err != nil {
			var notReady *store.OwnershipNotReadyError
			if errors.As(err, &notReady) {
				return kubernetesTLSNotDelivered, kubernetesTLSOwnershipReason(notReady.Reason, delivery.OwnerID), nil
			}
			return kubernetesTLSNotDelivered, "issuance was refused: " + err.Error(), nil
		}
		return kubernetesTLSDeliveryQueued, "", nil
	case orchestrator.StateIssued, orchestrator.StateRenewing, orchestrator.StateRenewalFailed:
		return d.kubernetesTLSDeliveryProgress(ctx, tenantID, ident.ID)
	case orchestrator.StateDeployed:
		return kubernetesTLSDelivered, "", nil
	default:
		return kubernetesTLSNotDelivered, fmt.Sprintf("this resource's identity is %s; it is not delivered again", state), nil
	}
}

// kubernetesTLSDeliveryProgress reports a resource whose certificate is on its
// way to the cluster from the agent's own signed receipts, newest first. With
// none yet the delivery is queued. A delivered or verified receipt means the
// Secret holds a certificate the agent wrote, as during a renewal. A failed one
// is not delivered, in the receipt's words, even while the job is retried:
// queued would claim progress the agent says it has not made.
func (d *issuanceDispatcher) kubernetesTLSDeliveryProgress(ctx context.Context, tenantID, identityID string) (status, reason string, err error) {
	// Verification and rollback receipts interleave with deploys; a short
	// window always reaches the newest deploy receipt.
	receipts, err := d.store.ListConnectorDeliveryReceiptsNewestPage(ctx, tenantID, identityID, "", store.ZeroUUID, nil, 20)
	if err != nil {
		return "", "", err
	}
	for _, receipt := range receipts {
		if receipt.Destination != "connector.deploy" {
			continue
		}
		switch receipt.Status {
		case servedstatus.ConnectorDelivered, servedstatus.ConnectorVerified:
			return kubernetesTLSDelivered, "", nil
		case servedstatus.ConnectorFailed:
			return kubernetesTLSNotDelivered, receipt.Detail, nil
		case servedstatus.ConnectorVerifyFailed:
			return kubernetesTLSNotDelivered, "the cluster agent wrote the Secret, but the listener at verify_address " +
				"did not serve the new certificate", nil
		}
		break
	}
	return kubernetesTLSDeliveryQueued, "", nil
}

// kubernetesTLSOwnershipReason says what to do when the owner is not ready for
// these certificates to reach deployment. The gate is resolved before any work
// is queued, so the agent has generated nothing yet.
func kubernetesTLSOwnershipReason(code, ownerID string) string {
	switch code {
	case "owner_application_model_is_incomplete":
		return "owner " + ownerID + " has no application ID or environment, which attesting ownership requires: complete " +
			"the owner, attest it (trstctl-cli owners attest " + ownerID + "), then run the source again"
	case "owner_application_model_changed_after_attestation":
		return "owner " + ownerID + " changed after it attested ownership: attest it again (trstctl-cli owners attest " +
			ownerID + "), then run the source again"
	default:
		return "owner " + ownerID + " has not attested ownership, or its attestation is older than the attestation cadence: " +
			"attest it (trstctl-cli owners attest " + ownerID + ") or record an ownership exception, then run the source again"
	}
}

// kubernetesTLSHosts reads the hosts a Kubernetes TLS identity serves, or nil
// when the identity records none or they do not validate.
func kubernetesTLSHosts(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var attrs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return nil
	}
	var recorded kubernetesTLSAttributes
	if err := json.Unmarshal(attrs[kubernetesTLSAttributesKey], &recorded); err != nil {
		return nil
	}
	hosts, err := k8stls.NormalizeHosts(recorded.Hosts)
	if err != nil {
		return nil
	}
	return hosts
}

// hostFirstIssuanceNames is the subject a host-executed first issuance asks
// the agent to certify: the identity's name, and for a k8s_secret target every
// host of the TLS block the Secret serves, because they share one certificate.
// A certificate for only the first host would break TLS for the others.
func hostFirstIssuanceNames(ident store.Identity, target store.DeploymentTarget) []string {
	if target.Type != relay.KubernetesSecretConnector {
		return []string{ident.Name}
	}
	hosts := kubernetesTLSHosts(ident.Attributes)
	if len(hosts) == 0 || hosts[0] != ident.Name {
		return []string{ident.Name}
	}
	return hosts
}

func sameJSONObject(a, b json.RawMessage) bool {
	var left, right map[string]any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if fmt.Sprint(right[key]) != fmt.Sprint(value) {
			return false
		}
	}
	return true
}
