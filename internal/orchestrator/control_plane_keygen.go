// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24 (A120/A130/A132): a per-tenant switch over
// control-plane key generation instead of removing the three generators.

// controlPlaneKeygenNamespace derives the stable event ID of a tenant's
// registration and upgrade decisions, so a retried registration or a second
// leader converges on one recorded decision.
var controlPlaneKeygenNamespace = uuid.MustParse("7a86ade3-4092-4299-b460-981dfae98d25")

// ControlPlaneKeygenDecisionID is the stable event ID of a tenant's decision
// from one source (registration or upgrade); operator decisions get fresh IDs.
func ControlPlaneKeygenDecisionID(tenantID, source string) string {
	return uuid.NewSHA1(controlPlaneKeygenNamespace, []byte(tenantID+"\x00"+source)).String()
}

const controlPlaneKeygenReasonLimit = 512

// ErrControlPlaneKeygenReason rejects an operator change without a reason.
var ErrControlPlaneKeygenReason = errors.New("orchestrator: a control-plane key generation change needs a reason")

// SetControlPlaneKeygen records a tenant's control-plane key generation
// decision. An operator decision names the operator and a reason. A
// registration or upgrade decision is recorded at most once per tenant under
// its stable ID; a second call returns the recorded decision unchanged.
func (o *Orchestrator) SetControlPlaneKeygen(ctx context.Context, tenantID string, decision projections.ControlPlaneKeygenSet) (projections.ControlPlaneKeygenSet, error) {
	decision.Reason = strings.TrimSpace(decision.Reason)
	decision.SetBy = strings.TrimSpace(decision.SetBy)
	if len(decision.Reason) > controlPlaneKeygenReasonLimit {
		return projections.ControlPlaneKeygenSet{}, fmt.Errorf("orchestrator: the reason exceeds %d bytes", controlPlaneKeygenReasonLimit)
	}
	if decision.SetAt.IsZero() {
		decision.SetAt = time.Now().UTC()
	}
	next := events.Event{Type: projections.EventControlPlaneKeygenSet, TenantID: tenantID}
	switch decision.Source {
	case store.ControlPlaneKeygenSourceOperator:
		if decision.SetBy == "" {
			return projections.ControlPlaneKeygenSet{}, errors.New("orchestrator: a control-plane key generation change needs the operator who made it")
		}
		if decision.Reason == "" {
			return projections.ControlPlaneKeygenSet{}, ErrControlPlaneKeygenReason
		}
		decision.Evidence = nil
	case store.ControlPlaneKeygenSourceRegistration, store.ControlPlaneKeygenSourceUpgrade:
		if decision.SetBy == "" {
			decision.SetBy = "system:" + decision.Source
		}
		next.ID = ControlPlaneKeygenDecisionID(tenantID, decision.Source)
		if existing, found, err := o.log.EventByID(ctx, next.ID); err != nil {
			return projections.ControlPlaneKeygenSet{}, err
		} else if found {
			var recorded projections.ControlPlaneKeygenSet
			if existing.Type != projections.EventControlPlaneKeygenSet || existing.TenantID != tenantID ||
				json.Unmarshal(existing.Data, &recorded) != nil {
				return projections.ControlPlaneKeygenSet{}, fmt.Errorf("orchestrator: event %s is not this tenant's %s decision", next.ID, decision.Source)
			}
			return recorded, nil
		}
	default:
		return projections.ControlPlaneKeygenSet{}, fmt.Errorf("orchestrator: unknown control-plane key generation source %q", decision.Source)
	}
	raw, err := json.Marshal(decision)
	if err != nil {
		return projections.ControlPlaneKeygenSet{}, err
	}
	next.Data = raw
	if _, err := o.emitPrepared(ctx, next); err != nil {
		return projections.ControlPlaneKeygenSet{}, err
	}
	return decision, nil
}

// ErrControlPlaneKeygenOff marks a refusal by the tenant's switch: a request
// that would generate the subject key in the control plane while the tenant
// has that turned off. The error carrying it names the path's replacements
// (ControlPlaneKeygenOff), so a caller is never left with only "no".
var ErrControlPlaneKeygenOff = errors.New("control-plane key generation is off for this tenant")

// The replacement each governed path names when the switch refuses it.
const (
	IdentityKeygenReplacement      = "supply subject_csr_pem, or bind the identity to an agent-executed target so the host generates the key"
	PKICommonNameKeygenReplacement = "send csr_pem with a key the requester generated (pki/sign/{role} on the Vault-compatible API)"
	VaultPKIKeygenReplacement      = "send the requester's CSR to pki/sign/{role}"
	// WorkloadSocketKeygenReplacement is the compatibility Workload API socket's.
	WorkloadSocketKeygenReplacement = "fetch the SVID from the host agent's Workload API socket (trstctl-agent --workload-api-socket), which generates the key on the workload's host"
)

// ControlPlaneKeygenOff is the switch's refusal for one path.
func ControlPlaneKeygenOff(replacement string) error {
	return fmt.Errorf("%w: %s, or turn control-plane key generation on (PUT /api/v1/tenant/key-generation)",
		ErrControlPlaneKeygenOff, replacement)
}

// ControlPlaneKeygenGuard decides, before a first issuance is recorded,
// whether it would generate the subject key in the control plane while the
// tenant has that turned off. The composition root supplies it: only the
// server knows whether the identity's target executes on a host agent.
type ControlPlaneKeygenGuard func(ctx context.Context, tenantID string, identity store.Identity, subjectCSRPEM string) error

// WithControlPlaneKeygenGuard refuses a requested -> issued transition the
// guard rejects, before any event or outbox intent.
func WithControlPlaneKeygenGuard(guard ControlPlaneKeygenGuard) OrchestratorOption {
	return func(o *Orchestrator) {
		o.controlPlaneKeygenGuard = guard
	}
}

// ControlPlaneKeygenRefusal runs the first-issuance guard without recording
// anything, so a preview can say what execution would refuse.
func (o *Orchestrator) ControlPlaneKeygenRefusal(ctx context.Context, tenantID string, identity store.Identity, subjectCSRPEM string) error {
	if o == nil || o.controlPlaneKeygenGuard == nil || State(identity.Status) != StateRequested {
		return nil
	}
	return o.controlPlaneKeygenGuard(ctx, tenantID, identity, strings.TrimSpace(subjectCSRPEM))
}
