// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CertificateIssuanceEvidence is the retained evidence of how one certificate
// was issued: the profile revision its issuing command bound, the approval it
// consumed, and the event that carries them.
type CertificateIssuanceEvidence struct {
	EventID  string
	Binding  *store.OperationApprovalIssuanceBinding
	Approval *store.OperationApprovalUse
}

// CertificateIssuanceEvidence reads a certificate's issuance evidence (A179).
// A lifecycle issuance or renewal names its transition in the certificate's
// issuance key: "issue:transition:<key>" / "renew:transition:<key>" for a
// command that carried a request key, otherwise "issue:<event id>" /
// "renew:<event id>", the queued command's key being the deciding transition's
// own event ID. That event carries the profile binding and any approval. A
// certificate issued through another path may carry an approval in its own
// certificate event. Anything else — an imported or discovered certificate,
// history older than reviewed profile bindings, a scheduler renewal that bound
// no profile — has none, which is an answer rather than an error.
func (o *Orchestrator) CertificateIssuanceEvidence(ctx context.Context, tenantID string, cert store.Certificate) (CertificateIssuanceEvidence, error) {
	if o.log == nil {
		return CertificateIssuanceEvidence{}, nil
	}
	transition, found, err := o.store.IdentityTransitionForIssuance(ctx, tenantID, cert.IssuanceIdempotencyKey)
	if err != nil {
		return CertificateIssuanceEvidence{}, err
	}
	if found {
		event, ok, err := o.log.EventAtSequence(ctx, transition.Seq)
		if err != nil {
			return CertificateIssuanceEvidence{}, fmt.Errorf("orchestrator: read issuance transition: %w", err)
		}
		if ok && event.TenantID == tenantID && event.Type == transition.EventType {
			return transitionIssuanceEvidence(event)
		}
		return CertificateIssuanceEvidence{}, nil
	}
	if eventID := transitionEventIDFromKey(cert.IssuanceIdempotencyKey); eventID != "" {
		event, ok, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return CertificateIssuanceEvidence{}, fmt.Errorf("orchestrator: read issuance transition: %w", err)
		}
		if ok && event.TenantID == tenantID &&
			(event.Type == projections.EventIdentityIssued || event.Type == projections.EventIdentityRenewing) {
			return transitionIssuanceEvidence(event)
		}
	}
	return o.certificateEventEvidence(ctx, tenantID, cert)
}

// transitionEventIDFromKey is the event ID a queued-command issuance key names,
// or "" for any other key.
func transitionEventIDFromKey(key string) string {
	for _, prefix := range []string{"issue:", "renew:"} {
		if rest, ok := strings.CutPrefix(key, prefix); ok && rest != "" && !strings.HasPrefix(rest, "transition:") && !strings.Contains(rest, ":") {
			return rest
		}
	}
	return ""
}

func transitionIssuanceEvidence(event events.Event) (CertificateIssuanceEvidence, error) {
	var payload transitionPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return CertificateIssuanceEvidence{}, fmt.Errorf("orchestrator: decode issuance transition: %w", err)
	}
	out := CertificateIssuanceEvidence{EventID: event.ID}
	switch event.SchemaVersion {
	case projections.LifecycleIssuanceEventSchemaVersion:
		out.Binding = payload.Issuance
	case projections.LifecycleApprovalEventSchemaVersion:
		out.Approval = payload.Approval
		if payload.Approval != nil {
			out.Binding = payload.Approval.Issuance
		}
	}
	return out, nil
}

func (o *Orchestrator) certificateEventEvidence(ctx context.Context, tenantID string, cert store.Certificate) (CertificateIssuanceEvidence, error) {
	if cert.IssuanceEventID == "" {
		return CertificateIssuanceEvidence{}, nil
	}
	event, ok, err := o.log.EventByID(ctx, cert.IssuanceEventID)
	if err != nil {
		return CertificateIssuanceEvidence{}, fmt.Errorf("orchestrator: read certificate event: %w", err)
	}
	if !ok || event.TenantID != tenantID || event.Type != projections.EventCertificateRecorded {
		return CertificateIssuanceEvidence{}, nil
	}
	var recorded projections.CertificateRecorded
	if err := json.Unmarshal(event.Data, &recorded); err != nil {
		return CertificateIssuanceEvidence{}, fmt.Errorf("orchestrator: decode certificate event: %w", err)
	}
	out := CertificateIssuanceEvidence{EventID: event.ID, Approval: recorded.Approval}
	if recorded.Approval != nil {
		out.Binding = recorded.Approval.Issuance
	}
	return out, nil
}
