// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"bytes"
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
	updated time.Time
}

type retirementEvidenceCut struct {
	generation string
	head       uint64
}

type retirementEvidenceCheckpoint struct {
	cut      retirementEvidenceCut
	policies map[retirementEvidenceKey]pcasstore.RetirementPolicy
	view     map[retirementEvidenceKey]*retirementPolicyEvidence
	scanned  int
}

func observeRetirementEvidenceCut(ctx context.Context, log *events.Log) (retirementEvidenceCut, error) {
	var cut retirementEvidenceCut
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		var err error
		cut.generation, err = log.ActiveGeneration(readCtx)
		if err != nil {
			return err
		}
		cut.head, err = log.LastSequence(readCtx)
		return err
	})
	return cut, err
}

// collectTenantRetirementEvidence holds only policy-bound facts for one tenant.
// The stream callback discards each other envelope before reading the next one.
func collectTenantRetirementEvidence(ctx context.Context, log *events.Log, tenantID string,
	policies []pcasstore.RetirementPolicy, defaultWindow time.Duration, evaluatedAt time.Time,
) (map[retirementEvidenceKey]*retirementPolicyEvidence, error) {
	cut, err := observeRetirementEvidenceCut(ctx, log)
	if err != nil {
		return nil, err
	}
	checkpoint, err := collectTenantRetirementEvidenceSince(ctx, log, tenantID, policies, defaultWindow, evaluatedAt, cut, nil)
	if err != nil {
		return nil, err
	}
	return checkpoint.view, nil
}

func collectTenantRetirementEvidenceSince(ctx context.Context, log *events.Log, tenantID string,
	policies []pcasstore.RetirementPolicy, defaultWindow time.Duration, evaluatedAt time.Time,
	cut retirementEvidenceCut, previous *retirementEvidenceCheckpoint,
) (*retirementEvidenceCheckpoint, error) {
	view := make(map[retirementEvidenceKey]*retirementPolicyEvidence, len(policies))
	stamps := make(map[retirementEvidenceKey]pcasstore.RetirementPolicy, len(policies))
	from := uint64(1)
	if previous != nil && previous.cut.generation == cut.generation && previous.cut.head <= cut.head {
		from = previous.cut.head + 1
	}
	for _, policy := range policies {
		key := retirementEvidenceKey{policy.IdentityID, policy.PredecessorEpoch}
		stamps[key] = policy
		entry := &retirementPolicyEvidence{seen: make(map[string]bool), updated: policy.UpdatedAt}
		if from > 1 && previous.view[key] != nil {
			old := previous.view[key]
			entry.retired = old.retired
			if sameRetirementPolicy(previous.policies[key], policy) {
				for _, ack := range old.acks {
					if !ack.RecordedAt.After(evaluatedAt) &&
						(old.window <= 0 || !ack.RecordedAt.Before(evaluatedAt.Add(-old.window))) {
						entry.acks = append(entry.acks, ack)
						entry.seen[ack.RelyingParty] = true
					}
				}
			}
		}
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
		return &retirementEvidenceCheckpoint{cut: cut, policies: stamps, view: view}, nil
	}
	scanned := 0
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		generation, err := log.ActiveGeneration(readCtx)
		if err != nil {
			return err
		}
		if generation != cut.generation {
			return fmt.Errorf("history generation changed during retirement evidence read")
		}
		return log.ReplayTenantTypesThrough(readCtx, tenantID, from, cut.head,
			[]string{succession.TypeRPAck, succession.TypeRetirement}, func(event events.Event) error {
				// Keep this count with the checkpoint so tests can verify the replay cut.
				scanned++
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
						event.Time.Before(entry.updated) ||
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
	return &retirementEvidenceCheckpoint{cut: cut, policies: stamps, view: view, scanned: scanned}, nil
}

func sameRetirementPolicy(a, b pcasstore.RetirementPolicy) bool {
	return a.IdentityID == b.IdentityID && a.PredecessorEpoch == b.PredecessorEpoch &&
		a.Threshold == b.Threshold && a.ValidityWindowSeconds == b.ValidityWindowSeconds &&
		a.PredecessorHandle == b.PredecessorHandle && a.Status == b.Status &&
		a.UpdatedAt.Equal(b.UpdatedAt) && bytes.Equal(a.RosterJSON, b.RosterJSON)
}
