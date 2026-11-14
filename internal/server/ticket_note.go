// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"

	"trstctl.com/trstctl/internal/ticketintake"
)

// recordTicketNote checks a relay's work-note report against the note it was
// asked to add (P13-L1): the same note and schedule, added or found already
// there. The note itself lives in ServiceNow; the job ledger keeps the
// outcome.
func recordTicketNote(payload []byte, detail string) error {
	var intent ticketintake.NoteIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return fmt.Errorf("server: decode durable ticket note intent: %w", err)
	}
	if len(detail) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: ticket note report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report ticketintake.NoteReport
	if err := decodeStrictJSON([]byte(detail), &report); err != nil {
		return fmt.Errorf("server: decode ticket note report: %w", err)
	}
	return ticketintake.ValidateNoteReport(intent, report)
}
