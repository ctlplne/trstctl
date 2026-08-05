// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/projections"
)

// CorrelateMDMDevice records one MDM device joined to one SCEP transaction (I5).
//
// AN-2: the correlation is an event. A device's enrollment history is exactly
// the thing an operator reconstructs when a fleet keeps failing, and history
// that lives only in a mutable row cannot survive a rebuild.
func (o *Orchestrator) CorrelateMDMDevice(ctx context.Context, tenantID string, in projections.MDMDeviceCorrelated) error {
	if strings.TrimSpace(in.MDM) == "" || strings.TrimSpace(in.MDMDeviceID) == "" {
		// A correlation with no device id joins to nothing. Recording it would
		// put a row in the join that means nothing and inflate coverage.
		return fmt.Errorf("orchestrator: an MDM correlation needs both an MDM and a device id")
	}
	switch in.InstallState {
	case "ok", "failed", "unknown":
	default:
		// Fail closed on an unrecognised state rather than storing it. A state
		// the console cannot render becomes an invisible row.
		return fmt.Errorf("orchestrator: install_state %q is not ok, failed, or unknown", in.InstallState)
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventMDMDeviceCorrelated, tenantID, payload)
	return err
}
