// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var errHostRotationLookupPending = errors.New("host rotation receipt lookup is progressing; run remains running")

const hostRotationLookupPage = 128

type hostRotationEvidence struct {
	Delivery, Custody events.Event
	Terminal          *events.Event
}

// Read a bounded page using exact sequence reads. The next position and sparse
// receipt offsets live with the retired job, so restarts never rescan its prefix.
// No valid result can predate the authoritative event that created its run.
func (a *agentService) hostRotationEvidence(ctx context.Context, tenantID string, job store.HostRotationJob, run store.RotationRun) (hostRotationEvidence, error) {
	var out hostRotationEvidence
	generation, err := a.log.ActiveGeneration(ctx)
	if err != nil {
		return out, err
	}
	generation = fmt.Sprintf("%s:attempt:%d", generation, job.Attempt)
	lookup, err := a.store.HostRotationLookup(ctx, tenantID, job.ID, job.Attempt)
	if err != nil {
		return out, err
	}
	if run.FirstEventSequence == 0 || run.FirstEventSequence > math.MaxInt64 {
		return out, errors.New("host rotation has no bounded source sequence")
	}
	if lookup.Generation != generation {
		lookup = store.HostRotationLookup{Generation: generation, Next: int64(run.FirstEventSequence)}
	}
	head, err := a.log.LastSequence(ctx)
	if err != nil {
		return out, err
	}
	if head >= math.MaxInt64 {
		return out, errors.New("host rotation source sequence exceeds PostgreSQL range")
	}
	if lookup.Next <= 0 || lookup.Next < int64(run.FirstEventSequence) || lookup.Next > int64(head)+1 {
		return out, errors.New("host rotation lookup cursor is outside its retained generation")
	}
	// Freeze each pass's high-water mark. Unrelated new traffic cannot keep an
	// old retired job chasing a moving head forever. A later invocation checks
	// a fresh cut after this range is exhausted, including a result appended by
	// the previous serialized invocation whose projection may have failed.
	if lookup.Through < lookup.Next {
		lookup.Through = int64(head)
	}
	if lookup.Through > int64(head) {
		return out, errors.New("host rotation lookup cut is outside retained history")
	}
	eventKey := fmt.Sprintf("%s:attempt:%d", job.IdempotencyKey, job.Attempt)
	deliveryID := evidenceID("connector-delivery-agent-event", tenantID, eventKey, job.ID)
	terminalID := evidenceID("host-rotation-result", tenantID, eventKey, job.ID)
	scanned := 0
	for lookup.Next <= lookup.Through && scanned < hostRotationLookupPage {
		event, found, err := a.log.EventAtSequence(ctx, uint64(lookup.Next))
		if err != nil {
			return out, err
		}
		if found && event.TenantID == tenantID {
			var slot *int64
			switch {
			case event.ID == deliveryID && event.Type == projections.EventConnectorDeliveryRecorded:
				slot = &lookup.Delivery
			case event.ID == terminalID && event.Type == projections.EventLifecycleRotationRecorded:
				slot = &lookup.Result
			case event.Type == projections.EventCertificateCustodyAttested:
				var receipt projections.CertificateCustodyAttested
				if json.Unmarshal(event.Data, &receipt) == nil && receipt.JobID == job.ID && receipt.Attempt == job.Attempt &&
					event.ID == orchestrator.CertificateCustodyAttestationEventID(tenantID, receipt.Fingerprint, job.ID, job.Attempt) {
					slot = &lookup.Custody
				}
			}
			if slot != nil {
				if *slot > 0 {
					previous, ok, err := a.log.EventAtSequence(ctx, uint64(*slot))
					if err != nil {
						return out, err
					}
					previous.Sequence, event.Sequence = 0, 0
					if !ok || !reflect.DeepEqual(previous, event) {
						return out, errors.New("host rotation receipt has conflicting retained envelopes")
					}
				} else {
					*slot = lookup.Next
				}
			}
		}
		lookup.Next++
		scanned++
		if scanned%16 == 0 {
			if err := a.store.SaveHostRotationLookup(ctx, tenantID, job.ID, job.Attempt, lookup); err != nil {
				return out, err
			}
		}
	}
	if err := a.store.SaveHostRotationLookup(ctx, tenantID, job.ID, job.Attempt, lookup); err != nil {
		return out, err
	}
	if lookup.Next <= lookup.Through {
		return out, errHostRotationLookupPending
	}
	load := func(sequence int64) (events.Event, error) {
		if sequence <= 0 {
			return events.Event{}, errors.New("retired host rotation is missing a retained receipt")
		}
		event, found, err := a.log.EventAtSequence(ctx, uint64(sequence))
		if err != nil {
			return events.Event{}, err
		}
		if !found || event.TenantID != tenantID {
			return events.Event{}, errors.New("host rotation receipt index differs from retained history")
		}
		return event, nil
	}
	if out.Delivery, err = load(lookup.Delivery); err != nil {
		return out, err
	}
	if out.Custody, err = load(lookup.Custody); err != nil {
		return out, err
	}
	if lookup.Result > 0 {
		terminal, err := load(lookup.Result)
		if err != nil {
			return out, err
		}
		out.Terminal = &terminal
	}
	return out, nil
}
