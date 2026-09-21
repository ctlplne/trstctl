// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// CorrelateMDMDevice records one MDM device joined to one SCEP transaction (I5).
//
// AN-2: the correlation is an event. A device's enrollment history is exactly
// the thing an operator reconstructs when a fleet keeps failing, and history
// that lives only in a mutable row cannot survive a rebuild.
func (o *Orchestrator) CorrelateMDMDevice(ctx context.Context, tenantID string, in projections.MDMDeviceCorrelated) error {
	return o.correlateMDMDevice(ctx, tenantID, "", in)
}

// CorrelateMDMDeviceFromRelay gives one reported device a stable event identity
// inside its outbox result. Replaying a report after any crash projects the
// canonical event again; it never invents a second observation.
func (o *Orchestrator) CorrelateMDMDeviceFromRelay(ctx context.Context, tenantID, resultKey string, in projections.MDMDeviceCorrelated) error {
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"mdm-relay-result\x00"+tenantID+"\x00"+resultKey+"\x00"+in.MDM+"\x00"+in.MDMDeviceID+"\x00"+in.TransactionID,
	)).String()
	return o.correlateMDMDevice(ctx, tenantID, eventID, in)
}

func (o *Orchestrator) correlateMDMDevice(ctx context.Context, tenantID, eventID string, in projections.MDMDeviceCorrelated) error {
	if strings.TrimSpace(in.MDM) == "" || strings.TrimSpace(in.MDMDeviceID) == "" {
		// A correlation with no device id joins to nothing. Recording it would
		// put a row in the join that means nothing and inflate coverage.
		return fmt.Errorf("orchestrator: an MDM correlation needs both an MDM and a device id")
	}
	switch in.InstallState {
	case "ok", "failed", "unknown":
	default:
		// Fail closed on an unrecognized state rather than storing it. A state
		// the console cannot render becomes an invisible row.
		return fmt.Errorf("orchestrator: install_state %q is not ok, failed, or unknown", in.InstallState)
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if eventID == "" {
		_, err = o.emit(ctx, projections.EventMDMDeviceCorrelated, tenantID, payload)
	} else {
		_, err = o.emitPrepared(ctx, events.Event{
			ID: eventID, Type: projections.EventMDMDeviceCorrelated, TenantID: tenantID, Data: payload,
		})
	}
	return err
}

// ConfigureMDMPollSchedule records the standing instruction to re-read an MDM
// (I5). TokenRef is a reference, never a token value.
func (o *Orchestrator) ConfigureMDMPollSchedule(ctx context.Context, tenantID string, in projections.MDMPollConfigured) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventMDMPollConfigured, tenantID, payload)
	return err
}
