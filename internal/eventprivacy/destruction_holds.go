// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

var ErrRetentionHold = errors.New("event privacy: retained legal hold blocks key destruction")

const (
	archiveHoldPlaced           = "archive.legal_hold.placed"
	archiveHoldReleaseRequested = "archive.legal_hold.release_requested"
	archiveHoldRecorded         = "archive.legal_hold.recorded"
	reportHoldPlaced            = "compliance.report_run.legal_hold_placed"
	reportHoldReleased          = "compliance.report_run.legal_hold_released"
)

type RetainedHoldPolicy struct{ Policy SourcePolicy }

type retainedArchiveHold struct {
	object string
	phase  string
}

type retainedHoldState struct {
	archive     map[string]retainedArchiveHold
	objectOwner map[string]string
	reports     map[string]bool
}

// RequireClear verifies the exact historical lifetime again and reads only its
// complete fixed source cut. It never consults erased SQL hold projections and
// never turns unreadable source or an ambiguous failure into hold clearance.
// Call before removal; crash recovery needs separately admitted durable public
// authorization rather than attempting to reopen private bodies after removal.
func (policy RetainedHoldPolicy) RequireClear(ctx context.Context, input Lifetime) error {
	request, err := NewDestructionRequest(input)
	if err != nil || policy.Policy.Log == nil {
		return ErrSource
	}
	return policy.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		life, found, err := policy.Policy.LifetimeForKey(read, request.Ref)
		if err != nil {
			return err
		}
		if !found || !matchesLifetimeDestruction(life, request) {
			return ErrSource
		}
		return policy.requireCutClear(read, life, request.OffboardSequence)
	})
}

// RequireOffboardClear runs before a new protected offboard is appended, while
// admission still owns its tenant fence. A blocked tenant stays live so the
// existing permissioned hold release and bucket-readback path remains usable.
func (policy RetainedHoldPolicy) RequireOffboardClear(ctx context.Context, input Lifetime) error {
	if policy.Policy.Log == nil || input.Registration.TenantID == "" {
		return ErrSource
	}
	return policy.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
		life, err := policy.Policy.LatestLifetime(read, input.Registration.TenantID)
		if err != nil {
			return err
		}
		if life.Registration.ID != input.Registration.ID || life.Registration.Sequence != input.Registration.Sequence || life.Offboard != nil || life.Activation == nil || input.Activation == nil || life.Activation.Body.Creation.Digest() != input.Activation.Body.Creation.Digest() {
			return ErrSource
		}
		head, err := policy.Policy.Log.LastSequence(read)
		if err != nil {
			return err
		}
		return policy.requireCutClear(read, life, head)
	})
}

func (policy RetainedHoldPolicy) requireCutClear(read context.Context, life Lifetime, through uint64) error {
	if life.Activation == nil {
		return ErrSource
	}
	ref := life.Activation.Body.Creation.Ref
	state := retainedHoldState{archive: map[string]retainedArchiveHold{}, objectOwner: map[string]string{}, reports: map[string]bool{}}
	seen := map[string]events.EnvelopeMetadata{}
	err := policy.Policy.Log.ReplayTenantMetadataTypesThrough(read, ref.TenantID, life.Registration.Sequence, through,
		[]string{archiveHoldPlaced, archiveHoldReleaseRequested, archiveHoldRecorded, reportHoldPlaced, reportHoldReleased}, func(meta events.EnvelopeMetadata) error {
			if meta.SchemaVersion != 1 {
				return ErrSource
			}
			if prior, duplicate := seen[meta.ID]; duplicate {
				canonical, found, err := policy.Policy.Log.TenantMetadataByID(read, ref.TenantID, meta.ID)
				if err != nil {
					return err
				}
				if !found || canonical.Sequence != prior.Sequence || canonical.Type != prior.Type || canonical.SchemaVersion != prior.SchemaVersion || canonical.DeclaredKeyID != prior.DeclaredKeyID || !canonical.Time.Equal(prior.Time) {
					return ErrSource
				}
				return nil
			}
			seen[meta.ID] = meta
			if meta.DeclaredKeyID != "" && meta.DeclaredKeyID != ref.ID {
				return ErrSource
			}
			event, found, err := policy.Policy.Log.EventAtSequence(read, meta.Sequence)
			if err != nil {
				return err
			}
			tenant, tenantErr := uuid.Parse(event.TenantID)
			if !found || tenantErr != nil || tenant.String() != ref.TenantID || event.ID != meta.ID || event.Type != meta.Type || event.Sequence != meta.Sequence || !event.Time.Equal(meta.Time) || event.SchemaVersion != 1 || event.SensitiveErased {
				return ErrSource
			}
			return state.apply(event)
		})
	if err != nil {
		return err
	}
	for _, hold := range state.archive {
		if hold.phase != "released" {
			return ErrRetentionHold
		}
	}
	for _, held := range state.reports {
		if held {
			return ErrRetentionHold
		}
	}
	return nil
}

func (state *retainedHoldState) place(id, object string) error {
	if id == "" || object == "" {
		return ErrSource
	}
	if _, exists := state.archive[id]; exists {
		return nil
	}
	if _, held := state.objectOwner[object]; held {
		return nil
	}
	state.archive[id] = retainedArchiveHold{object: object, phase: "pending"}
	state.objectOwner[object] = id
	return nil
}

func (state *retainedHoldState) release(id string) error {
	hold, known := state.archive[id]
	if !known {
		return ErrSource
	}
	if hold.phase == "released" {
		return nil
	}
	if owner, active := state.objectOwner[hold.object]; active && owner != id {
		return nil
	}
	hold.phase = "release_pending"
	state.archive[id] = hold
	state.objectOwner[hold.object] = id
	return nil
}

func (state *retainedHoldState) apply(event events.Event) error {
	switch event.Type {
	case archiveHoldPlaced:
		var body struct {
			ID          string `json:"id"`
			Object      string `json:"object"`
			Reason      string `json:"reason"`
			ReportRunID string `json:"report_run_id,omitempty"`
		}
		if decodeRetainedHold(event.Data, &body) != nil || body.Reason == "" || len(body.Reason) > 512 || len(body.Object) > 1024 {
			return ErrSource
		}
		return state.place(body.ID, body.Object)
	case archiveHoldReleaseRequested:
		var body struct {
			ID string `json:"id"`
		}
		if decodeRetainedHold(event.Data, &body) != nil {
			return ErrSource
		}
		return state.release(body.ID)
	case archiveHoldRecorded:
		var body struct {
			ID     string    `json:"id"`
			Status string    `json:"status"`
			Detail string    `json:"detail,omitempty"`
			At     time.Time `json:"at"`
		}
		if decodeRetainedHold(event.Data, &body) != nil {
			return ErrSource
		}
		hold, known := state.archive[body.ID]
		if !known {
			return ErrSource
		}
		switch body.Status {
		case "applied":
			if hold.phase == "pending" {
				hold.phase = "applied"
			}
		case "failed":
			if hold.phase == "pending" || hold.phase == "applied" || hold.phase == "release_pending" {
				hold.phase = "failed"
				if state.objectOwner[hold.object] == body.ID {
					delete(state.objectOwner, hold.object)
				}
			}
		case "released":
			// Match the SQL state machine: a late outcome after failure is a
			// no-op until a fresh explicit release request reopens the step.
			if hold.phase == "release_pending" {
				hold.phase = "released"
				if state.objectOwner[hold.object] == body.ID {
					delete(state.objectOwner, hold.object)
				}
			}
		default:
			return ErrSource
		}
		state.archive[body.ID] = hold
	case reportHoldPlaced, reportHoldReleased:
		var body struct {
			RunID         string `json:"run_id"`
			Reason        string `json:"reason,omitempty"`
			StorageHoldID string `json:"storage_hold_id,omitempty"`
			StorageObject string `json:"storage_object,omitempty"`
		}
		if decodeRetainedHold(event.Data, &body) != nil || body.RunID == "" {
			return ErrSource
		}
		placed := event.Type == reportHoldPlaced
		if placed && (body.Reason == "" || len(body.Reason) > 512 || state.reports[body.RunID]) {
			return ErrSource
		}
		if !placed && !state.reports[body.RunID] {
			return ErrSource
		}
		state.reports[body.RunID] = placed
		if body.StorageHoldID != "" {
			if placed {
				return state.place(body.StorageHoldID, body.StorageObject)
			}
			return state.release(body.StorageHoldID)
		}
	default:
		return ErrSource
	}
	return nil
}

// Hold payloads are existing domain JSON, so whitespace/order stay compatible.
// They are flat schemas. Reject duplicate/unknown fields before interpreting a
// state transition; encoding/json's last-key-wins behavior is not authority.
func decodeRetainedHold(data []byte, target any) error {
	if !utf8.Valid(data) {
		return ErrSource
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return ErrSource
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrSource
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrSource
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return ErrSource
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrSource
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrSource
	}
	return nil
}
