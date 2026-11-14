// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Leaked secrets moved into the native store (P6). A move links a finding to
// the secret that now holds its value; the first read of a newer version
// records that a consumer picked up the rotation; the leader closes the
// finding as remediated only on that read, the rotation and a completed scan
// that no longer sees the leak.

// SecretMoveClosureActor is the actor that closes a moved finding on evidence.
const SecretMoveClosureActor = "system:leaked-secret-closure"

var (
	secretConsumerReadNamespace = uuid.MustParse("b955ccea-7b7d-4a1c-b9e1-a7f8a06e9b4b")
	secretMoveClosureNamespace  = uuid.MustParse("c7e2a9d4-41f0-5b3e-8d26-6e1f0b9a2c57")
	secretResidueCheckNamespace = uuid.MustParse("5d0b8e61-2f4a-4c7e-9a13-b8e2c6f0d947")
)

// RecordDiscoveryFindingSecretMoved links a finding to the native secret its
// value moved into.
func (o *Orchestrator) RecordDiscoveryFindingSecretMoved(ctx context.Context, tenantID string, moved projections.DiscoveryFindingSecretMoved) (store.DiscoveryFindingSecretMove, error) {
	payload, err := json.Marshal(moved)
	if err != nil {
		return store.DiscoveryFindingSecretMove{}, err
	}
	if _, err := o.emit(ctx, projections.EventDiscoveryFindingSecretMoved, tenantID, payload); err != nil {
		return store.DiscoveryFindingSecretMove{}, err
	}
	m, ok, err := o.store.GetDiscoveryFindingSecretMove(ctx, tenantID, moved.FindingID)
	if err == nil && !ok {
		err = errors.New("orchestrator: the secret move was not projected")
	}
	return m, err
}

// RecordMovedSecretConsumerRead records, once per finding, that a consumer
// read a version of the moved secret newer than the moved one. The event ID
// names the finding, so replicas serving concurrent reads record it once.
func (o *Orchestrator) RecordMovedSecretConsumerRead(ctx context.Context, tenantID string, read projections.DiscoveryFindingSecretConsumerRead) error {
	eventID := uuid.NewSHA1(secretConsumerReadNamespace, []byte(tenantID+"\x00"+read.FindingID)).String()
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return err
	}
	payload, err := json.Marshal(read)
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{
		ID: eventID, Type: projections.EventDiscoveryFindingSecretConsumerRead, TenantID: tenantID, Data: payload,
	})
	return err
}

// CloseMovedSecretFinding records a moved finding remediated, by
// SecretMoveClosureActor, with the evidence that closed it. The event ID names
// the finding and the evidence, so two leaders converge on one event.
func (o *Orchestrator) CloseMovedSecretFinding(ctx context.Context, tenantID string, f store.OpenSecretMove, reason, evidenceRef string) error {
	payload, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
		ID: f.FindingID, Status: string(discovery.TriageRemediated),
		Actor: SecretMoveClosureActor, Reason: reason, EvidenceRef: evidenceRef,
	})
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(secretMoveClosureNamespace, []byte(tenantID+"\x00"+f.FindingID+"\x00"+evidenceRef)).String()
	_, err = o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventDiscoveryFindingTriageChanged, TenantID: tenantID, Data: payload})
	return err
}

// RecordSecretResidueChecked records a scan run's re-check of a moved
// secret's history residue (P6-L5). The event ID names the finding, the move
// and the run, so a retried run records it once.
func (o *Orchestrator) RecordSecretResidueChecked(ctx context.Context, tenantID string, checked projections.DiscoveryFindingSecretResidueChecked) error {
	if checked.Residue == nil {
		checked.Residue = []store.SecretResidueLocation{}
	}
	payload, err := json.Marshal(checked)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(secretResidueCheckNamespace, []byte(tenantID+"\x00"+checked.FindingID+"\x00"+checked.SecretName+"\x00"+
		strconv.Itoa(checked.SecretVersion)+"\x00"+checked.RunID)).String()
	if _, found, err := o.log.EventByID(ctx, id); err != nil || found {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventDiscoveryFindingSecretResidueChecked, TenantID: tenantID, Data: payload})
	return err
}
