// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var awsHoneyIDNamespace = uuid.MustParse("ada1103a-60b2-5d7b-8e1a-f20bcbfc8088")

// CreateAWSHoneyToken joins an already issued, durable IAM decoy lease to the
// operator inventory. A crash after IAM issuance can replay the exact event by
// lease ID; a colliding name/placement or caller is rejected rather than silently
// overwriting the original placement evidence.
func (o *Orchestrator) CreateAWSHoneyToken(ctx context.Context, tenantID string, pl projections.AWSHoneyTokenCreated) (store.HoneyToken, error) {
	if tenantID == "" || pl.LeaseID == "" || pl.AccessKeyID == "" {
		return store.HoneyToken{}, errors.New("orchestrator: AWS honeytoken requires tenant, lease, and IAM key identity")
	}
	pl.ID = uuid.NewSHA1(awsHoneyIDNamespace, []byte(tenantID+"\x00"+pl.LeaseID)).String()
	data, err := json.Marshal(pl)
	if err != nil {
		return store.HoneyToken{}, err
	}
	next := events.Event{
		ID: "honey-aws-created:" + pl.ID, Type: projections.EventAWSHoneyTokenCreated,
		TenantID: tenantID, SchemaVersion: 1, Data: data,
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		next.Actor = &actor
	}
	retained, found, err := o.log.EventByID(ctx, next.ID)
	if err != nil {
		return store.HoneyToken{}, err
	}
	if found {
		if retained.Type != next.Type || retained.TenantID != tenantID || retained.SchemaVersion != 1 ||
			!bytes.Equal(retained.Data, next.Data) || !reflect.DeepEqual(retained.Actor, next.Actor) {
			return store.HoneyToken{}, fmt.Errorf("%w: AWS honeytoken lease was already bound to different placement or caller", store.ErrIdempotencyConflict)
		}
		if err := o.proj.Apply(ctx, retained); err != nil {
			return store.HoneyToken{}, err
		}
	} else {
		committed, emitErr := o.emitPrepared(ctx, next)
		if emitErr != nil {
			return store.HoneyToken{}, emitErr
		}
		if committed.Type != next.Type || committed.TenantID != tenantID ||
			!bytes.Equal(committed.Data, next.Data) || !reflect.DeepEqual(committed.Actor, next.Actor) {
			return store.HoneyToken{}, fmt.Errorf("%w: AWS honeytoken lease was already bound to different placement or caller", store.ErrIdempotencyConflict)
		}
	}
	return o.store.GetHoneyToken(ctx, tenantID, pl.ID)
}

// RearmAWSHoneyToken starts a new alarm generation without deleting earlier
// CloudTrail event evidence. An old event seen again in an overlap cannot raise
// a new alarm because the observed-event ID remains unique in PostgreSQL.
func (o *Orchestrator) RearmAWSHoneyToken(ctx context.Context, tenantID, id, idempotencyKey string) (store.HoneyToken, error) {
	if tenantID == "" || id == "" || idempotencyKey == "" {
		return store.HoneyToken{}, errors.New("orchestrator: AWS honeytoken rearm requires tenant, decoy, and idempotency key")
	}
	eventID := "honey-aws-rearmed:" + crypto.SHA256Hex([]byte(tenantID+"\x00"+id+"\x00"+idempotencyKey))
	retained, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return store.HoneyToken{}, err
	}
	if found {
		var pl projections.AWSHoneyTokenRearmed
		if json.Unmarshal(retained.Data, &pl) != nil || pl.ID != id ||
			retained.Type != projections.EventAWSHoneyTokenRearmed || retained.TenantID != tenantID || retained.SchemaVersion != 1 {
			return store.HoneyToken{}, fmt.Errorf("%w: AWS honeytoken rearm command identity collided", store.ErrIdempotencyConflict)
		}
		if err := o.proj.Apply(ctx, retained); err != nil {
			return store.HoneyToken{}, err
		}
		return o.store.GetHoneyToken(ctx, tenantID, id)
	}
	h, err := o.store.GetHoneyToken(ctx, tenantID, id)
	if err != nil {
		return store.HoneyToken{}, err
	}
	if h.Kind != "aws" || h.State != "triggered" {
		return store.HoneyToken{}, errors.New("orchestrator: only a triggered AWS decoy can be rearmed")
	}
	data, err := json.Marshal(projections.AWSHoneyTokenRearmed{ID: id, ExpectedGeneration: h.AlarmGeneration})
	if err != nil {
		return store.HoneyToken{}, err
	}
	next := events.Event{ID: eventID, Type: projections.EventAWSHoneyTokenRearmed,
		TenantID: tenantID, SchemaVersion: 1, Data: data}
	if actor, ok := events.ActorFromContext(ctx); ok {
		next.Actor = &actor
	}
	committed, err := o.emitPrepared(ctx, next)
	if err != nil {
		return store.HoneyToken{}, err
	}
	if committed.Type != next.Type || committed.TenantID != tenantID || !bytes.Equal(committed.Data, next.Data) ||
		!reflect.DeepEqual(committed.Actor, next.Actor) {
		return store.HoneyToken{}, fmt.Errorf("%w: AWS honeytoken rearm event differs from retained command", store.ErrIdempotencyConflict)
	}
	return o.store.GetHoneyToken(ctx, tenantID, id)
}
