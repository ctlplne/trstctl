// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

type retirementEvidenceKey struct {
	identityID string
	epoch      uint64
}

type retirementPolicyEvidence struct {
	retired bool
	acks    []retirement.SignedAck
	roster  retirement.Roster
	seen    map[string]bool
	window  time.Duration
}

// collectTenantRetirementEvidence holds only policy-bound facts for one tenant.
// The stream callback discards each other envelope before reading the next one.
func collectTenantRetirementEvidence(ctx context.Context, log *events.Log, tenantID string,
	policies []pcasstore.RetirementPolicy, defaultWindow time.Duration, evaluatedAt time.Time,
) (map[retirementEvidenceKey]*retirementPolicyEvidence, error) {
	view := make(map[retirementEvidenceKey]*retirementPolicyEvidence, len(policies))
	for _, policy := range policies {
		key := retirementEvidenceKey{policy.IdentityID, policy.PredecessorEpoch}
		entry := &retirementPolicyEvidence{seen: make(map[string]bool)}
		if policy.Status == "active" {
			roster, err := retirement.DecodeRoster(policy.RosterJSON)
			if err == nil {
				entry.roster = roster
			}
			entry.window = defaultWindow
			if policy.ValidityWindowSeconds > 0 {
				if window, err := validityWindowDuration(policy.ValidityWindowSeconds); err == nil {
					entry.window = window
				}
			}
		}
		view[key] = entry
	}
	if len(view) == 0 {
		return view, nil
	}
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		return log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head,
			[]string{succession.TypeRPAck, succession.TypeRetirement}, func(event events.Event) error {
				payload, err := succession.Decode(event)
				if err != nil {
					return err
				}
				switch fact := payload.(type) {
				case succession.RetirementV1:
					if fact.TenantID == tenantID {
						if entry := view[retirementEvidenceKey{fact.IdentityID, fact.Epoch}]; entry != nil {
							entry.retired = true
						}
					}
				case succession.RPAckV1:
					if fact.TenantID != tenantID || len(fact.AckSignature) == 0 || len(fact.AckSignature) > 16<<10 {
						return nil
					}
					entry := view[retirementEvidenceKey{fact.IdentityID, fact.Epoch}]
					if entry == nil || entry.roster == nil || entry.seen[fact.RelyingParty] ||
						len(entry.roster[fact.RelyingParty]) == 0 || event.Time.After(evaluatedAt) ||
						(entry.window > 0 && event.Time.Before(evaluatedAt.Add(-entry.window))) {
						return nil
					}
					if err := crypto.VerifyMessage(entry.roster[fact.RelyingParty],
						retirement.AckMessage(tenantID, fact.IdentityID, fact.Epoch, fact.RelyingParty), fact.AckSignature); err != nil {
						return nil
					}
					entry.seen[fact.RelyingParty] = true
					entry.acks = append(entry.acks, retirement.SignedAck{
						TenantID: tenantID, IdentityID: fact.IdentityID, Epoch: fact.Epoch,
						RelyingParty: fact.RelyingParty, RecordedAt: event.Time, Signature: fact.AckSignature,
					})
				}
				return nil
			})
	})
	if err != nil {
		return nil, fmt.Errorf("pcas retirement worker: read tenant evidence: %w", err)
	}
	return view, nil
}
