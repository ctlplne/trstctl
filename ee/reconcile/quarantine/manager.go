// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
)

var _ editionseam.AdmissionHook = (*Manager)(nil)

// ObserveWitness evaluates a recorded divergence witness against the tenant
// containment policy and enters quarantine when the policy says so
// (XREC-claim-4).
func (m *Manager) ObserveWitness(ctx context.Context, idempotencyKey string, evidence witness.Evidence) (Decision, error) {
	if m == nil || m.log == nil || m.state == nil || strings.TrimSpace(idempotencyKey) == "" {
		return Decision{}, ErrInvalidQuarantine
	}
	if _, err := evidence.CanonicalBytes(); err != nil {
		return Decision{}, err
	}
	pol := m.pol.evaluate(evidence)
	if !pol.quarantine {
		return Decision{TenantID: evidence.Body.TenantID, WitnessID: evidence.Body.WitnessID, State: StateConsistent}, nil
	}
	tenantID := strings.TrimSpace(evidence.Body.TenantID)
	authorityID := strings.TrimSpace(pol.authorityID)
	if tenantID == "" || authorityID == "" || strings.TrimSpace(evidence.Body.WitnessID) == "" {
		return Decision{}, ErrInvalidQuarantine
	}
	from := StateConsistent
	if cur, ok := m.state.Lookup(tenantID, authorityID); ok {
		from = cur.State
	}
	now := m.now().Unix()
	payload := Entered{
		TenantID:     tenantID,
		AuthorityID:  authorityID,
		WitnessID:    evidence.Body.WitnessID,
		Reason:       pol.reason,
		FromState:    from,
		ThroughState: StateDiverged,
		ToState:      StateQuarantined,
		EnteredAt:    now,
	}
	ev, err := m.append(ctx, idempotencyKey, EventTypeEntered, tenantID, payload)
	if err != nil {
		return Decision{}, err
	}
	rec, _, _ := m.state.enter(tenantID, authorityID, evidence.Body.WitnessID, pol.reason, now)
	return Decision{
		Entered:     true,
		TenantID:    tenantID,
		AuthorityID: authorityID,
		WitnessID:   evidence.Body.WitnessID,
		Reason:      pol.reason,
		State:       rec.State,
		Event:       ev,
	}, nil
}

func (m *Manager) Admit(ctx context.Context, req editionseam.AdmissionRequest) (editionseam.AdmissionDecision, error) {
	if m == nil || m.state == nil || m.admission == nil {
		return editionseam.AdmissionDecision{}, ErrInvalidQuarantine
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return editionseam.AdmissionDecision{}, ErrInvalidQuarantine
	}
	// Fail closed. Containment is a security control: a lookup that cannot answer
	// must refuse the operation, never fall through to AllowAdmission().
	open, err := m.admission.HasOpenTenantQuarantine(ctx, tenantID)
	if err != nil {
		return editionseam.AdmissionDecision{}, fmt.Errorf("%w: containment state lookup: %v", ErrInvalidQuarantine, err)
	}
	if !open {
		return editionseam.AllowAdmission(), nil
	}
	// Same seam, so the tenant gate and the per-authority lookup cannot be
	// answered by two substrates that disagree.
	record, reason, err := m.refusalRecord(ctx, req)
	if err != nil {
		return editionseam.AdmissionDecision{}, fmt.Errorf("%w: containment authority lookup: %v", ErrInvalidQuarantine, err)
	}
	if record.AuthorityID == "" {
		return editionseam.AllowAdmission(), nil
	}
	ev, err := m.recordRefusal(ctx, req, record, reason)
	if err != nil {
		return editionseam.AdmissionDecision{}, err
	}
	return editionseam.AdmissionDecision{
		Allowed:   false,
		Reason:    reason,
		RefusalID: eventRefusalID(ev),
	}, nil
}

// refusalRecord resolves WHICH open quarantine an admission request collides
// with. It reads the same AdmissionState the tenant gate read, and propagates a
// lookup failure instead of degrading it to "no quarantined authority found",
// which Admit would otherwise turn into AllowAdmission().
func (m *Manager) refusalRecord(ctx context.Context, req editionseam.AdmissionRequest) (Record, string, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if len(req.ObservedInputs) == 0 {
		return Record{TenantID: tenantID, AuthorityID: "ambiguous", State: StateQuarantined, Open: true}, "ambiguous observed-state provenance while quarantine is open", nil
	}
	for _, input := range req.ObservedInputs {
		authorityID := strings.TrimSpace(input.AuthorityID)
		if authorityID == "" {
			return Record{TenantID: tenantID, AuthorityID: "ambiguous", State: StateQuarantined, Open: true}, "ambiguous observed-state provenance while quarantine is open", nil
		}
		rec, ok, err := m.admission.LookupOpenQuarantine(ctx, tenantID, authorityID)
		if err != nil {
			return Record{}, "", err
		}
		if ok {
			return rec, "observed state from quarantined authority", nil
		}
	}
	return Record{}, "", nil
}

func (m *Manager) recordRefusal(ctx context.Context, req editionseam.AdmissionRequest, rec Record, reason string) (eventspec.Event, error) {
	if m.log == nil {
		return eventspec.Event{}, ErrInvalidQuarantine
	}
	key := strings.TrimSpace(req.IdempotencyKey)
	if key == "" {
		key = refusalKey(req, rec, reason)
	}
	refusalID := refusalKey(req, rec, reason)
	payload := Refused{
		RefusalID:      refusalID,
		TenantID:       strings.TrimSpace(req.TenantID),
		AuthorityID:    rec.AuthorityID,
		WitnessID:      rec.WitnessID,
		Operation:      strings.TrimSpace(req.Operation),
		IdentityID:     strings.TrimSpace(req.IdentityID),
		Reason:         reason,
		IdempotencyKey: strings.TrimSpace(req.IdempotencyKey),
		RefusedAt:      m.now().Unix(),
	}
	return m.append(ctx, "refusal:"+key, EventTypeRefused, payload.TenantID, payload)
}

func (m *Manager) append(ctx context.Context, key, typ, tenantID string, payload any) (eventspec.Event, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return eventspec.Event{}, err
	}
	run := func(runCtx context.Context) ([]byte, error) {
		ev, err := m.log.Append(runCtx, eventspec.Event{
			Type:          typ,
			TenantID:      tenantID,
			SchemaVersion: eventspec.DefaultSchemaVersion,
			Data:          data,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(ev)
	}
	var raw []byte
	if m.idem != nil {
		raw, err = m.idem.Do(ctx, tenantID, strings.TrimSpace(key), run)
	} else {
		raw, err = run(ctx)
	}
	if err != nil {
		return eventspec.Event{}, err
	}
	var ev eventspec.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return eventspec.Event{}, err
	}
	return ev, nil
}

func refusalKey(req editionseam.AdmissionRequest, rec Record, reason string) string {
	parts := strings.Join([]string{
		strings.TrimSpace(req.TenantID),
		strings.TrimSpace(req.Operation),
		strings.TrimSpace(req.IdentityID),
		strings.TrimSpace(req.IdempotencyKey),
		strings.TrimSpace(rec.AuthorityID),
		strings.TrimSpace(rec.WitnessID),
		strings.TrimSpace(reason),
	}, "\x00")
	return hex.EncodeToString(crypto.SHA256Sum([]byte(parts)))
}

func eventRefusalID(ev eventspec.Event) string {
	var payload Refused
	if err := json.Unmarshal(ev.Data, &payload); err == nil && payload.RefusalID != "" {
		return payload.RefusalID
	}
	return fmt.Sprintf("%s:%d", ev.ID, ev.Sequence)
}
