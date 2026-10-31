// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AD CS certificate-database ingestion (epic F4).
//
// The domain-joined relay collects certutil rows from a CA database; the API
// layer parses and summarizes them (the production caller of adcs.ParseDBRow
// and adcs.Summarize, which had none), and this thin command records the
// per-disposition breakdown as an event. Parsing lives in the API rather than
// here because internal/ca imports the orchestrator, so importing adcs here
// would be an import cycle.

// RecordADCSDatabaseIngested emits the summarized CA-database sweep. The
// summary is computed by the caller; this appends the event and projects it.
func (o *Orchestrator) RecordADCSDatabaseIngested(ctx context.Context, tenantID string, in projections.ADCSDatabaseIngested) error {
	if strings.TrimSpace(in.CAConfig) == "" {
		return fmt.Errorf("orchestrator: adcs database ingest requires a ca_config")
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventADCSDatabaseIngested, tenantID, payload)
	return err
}

var adcsDatabaseCollectionNamespace = uuid.MustParse("5d0f3c2e-9a41-4f7b-8c6e-2b1a7d93e4c5")

// ErrADCSDatabaseCollectionPending refuses a second read of a CA while one is
// waiting or running: stacking identical reads behind an unclaimed one has the
// relay replay a backlog when it returns.
var ErrADCSDatabaseCollectionPending = errors.New("orchestrator: a CA database read for this CA is already waiting")

// ADCSDatabaseCollectionRequest asks one exact domain-joined relay to read one
// CA's database with certutil (A162).
type ADCSDatabaseCollectionRequest struct {
	CAConfig        string
	RequiredAgentID string
	IdempotencyKey  string
}

// RequestADCSDatabaseCollection appends the request and queues the relay read
// in one tenant transaction. The relay must be ready for the kind: enrolled
// with the network role, heartbeating, and advertising certutil. A retry with
// the same key returns the same request.
func (o *Orchestrator) RequestADCSDatabaseCollection(ctx context.Context, tenantID string,
	in ADCSDatabaseCollectionRequest) (projections.ADCSDatabaseCollectionRequested, error) {
	var empty projections.ADCSDatabaseCollectionRequested
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return empty, errors.New("orchestrator: CA database reads are not configured")
	}
	caConfig := strings.TrimSpace(in.CAConfig)
	agentID := strings.TrimSpace(in.RequiredAgentID)
	if !relay.ValidCAConfig(caConfig) || agentID == "" {
		return empty, errors.New("orchestrator: a CA database read needs one certsrv CA and one exact relay")
	}
	if err := o.requireDiscoveryNetworkRelayForJob(ctx, tenantID, agentID, relay.KindADCSDatabase); err != nil {
		return empty, err
	}
	seed := []byte(tenantID + "\x00" + caConfig + "\x00" + agentID + "\x00" + strings.TrimSpace(in.IdempotencyKey))
	requested := projections.ADCSDatabaseCollectionRequested{
		CollectionID: uuid.NewSHA1(adcsDatabaseCollectionNamespace, append([]byte("collection\x00"), seed...)).String(),
		CAConfig:     caConfig,
		AgentID:      agentID,
	}
	raw, err := json.Marshal(requested)
	if err != nil {
		return empty, err
	}
	intent, err := json.Marshal(relay.ADCSDatabaseIntent{ID: requested.CollectionID, CAConfig: caConfig, RequiredAgentID: agentID})
	if err != nil {
		return empty, err
	}
	eventID := uuid.NewSHA1(adcsDatabaseCollectionNamespace, append([]byte("event\x00"), seed...)).String()
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		retained, found, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if found {
			if retained.TenantID != tenantID || retained.Type != projections.EventADCSDatabaseCollectionRequested || !bytes.Equal(retained.Data, raw) {
				return fmt.Errorf("%w: CA database read differs from the retained one", store.ErrIdempotencyConflict)
			}
			return nil
		}
		pending, err := o.store.LockPendingADCSDatabaseCollectionTx(ctx, tx, tenantID, caConfig)
		if err != nil {
			return err
		}
		if pending {
			return ErrADCSDatabaseCollectionPending
		}
		event, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventADCSDatabaseCollectionRequested, TenantID: tenantID, Data: raw,
		})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventADCSDatabaseCollectionRequested ||
			event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: CA database read differs from the retained one", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: relay.KindADCSDatabase,
			IdempotencyKey: "adcs-ca-database:" + requested.CollectionID, Payload: intent,
			RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: agentID,
		})
		return err
	})
	if err != nil {
		if errors.Is(err, ErrADCSDatabaseCollectionPending) {
			return empty, err
		}
		return empty, fmt.Errorf("orchestrator: queue CA database read: %w", err)
	}
	return requested, nil
}

// RecordADCSDatabaseCollected records a relay's CA database counts under an
// event id derived from the job claim, so a retried report records once.
func (o *Orchestrator) RecordADCSDatabaseCollected(ctx context.Context, tenantID, eventID string, in projections.ADCSDatabaseIngested) error {
	if o == nil || o.log == nil || strings.TrimSpace(eventID) == "" || strings.TrimSpace(in.CAConfig) == "" {
		return errors.New("orchestrator: a relay CA database report needs its event id and CA")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventADCSDatabaseIngested, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventADCSDatabaseIngested || event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: CA database report differs from the retained one", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
}
