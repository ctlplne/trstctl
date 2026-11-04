// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
)

// Renewal waves of a switching import (A265). A row moved to trstctl gets the
// one identity trstctl keeps for it: its ID is derived from the import and the
// row, so a second wave, a retried cutover or a wave after a rollback finds the
// same identity and trstctl never holds two renewals for one certificate.

// SwitchingRowIdentityID is the identity trstctl keeps for an imported row.
func SwitchingRowIdentityID(tenantID, importID string, row int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("switching-row-identity\x00%s\x00%s\x00%d", tenantID, importID, row))).String()
}

// SwitchingWaveID is the wave a cutover command records: the same command
// retried records the same wave.
func SwitchingWaveID(tenantID, importID, command string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("switching-wave\x00"+tenantID+"\x00"+importID+"\x00"+command)).String()
}

// RecordSwitchingWaveCutOver records a wave and the identity of each row.
func (o *Orchestrator) RecordSwitchingWaveCutOver(ctx context.Context, tenantID string, wave projections.SwitchingWaveCutOver) error {
	return o.emitSwitching(ctx, tenantID, switchingEventID(wave.WaveID, "cut_over"), projections.EventSwitchingWaveCutOver, wave)
}

// RecordSwitchingWaveRolledBack records that a wave's rows are watch-only again.
func (o *Orchestrator) RecordSwitchingWaveRolledBack(ctx context.Context, tenantID string, rolled projections.SwitchingWaveRolledBack) error {
	return o.emitSwitching(ctx, tenantID, switchingEventID(rolled.WaveID, "rolled_back"), projections.EventSwitchingWaveRolledBack, rolled)
}
