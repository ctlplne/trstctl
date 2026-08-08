// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"encoding/csv"
	"io"
	"strconv"
)

// CSV export of an evidence document (epic L2).
//
// The verdict travels ON EVERY ROW. A CSV is the format that gets opened in a
// spreadsheet, sliced, and pasted into an invoice email with its context left
// behind — so signable and reason are columns, not a header comment that the
// first sort silently detaches from the numbers.
//
// The signature does NOT ride the CSV. A JWS is bytes for a verifier, not for
// a spreadsheet, and a truncated paste of one looks intact. The JSON document
// is the attestation; this is its table, and the digest column is what ties a
// row back to the attested document.
//
// This replaced the earlier WriteCSV/WriteJSONL over raw UsageRecords, which
// no served surface ever called — tested, and unreachable, which is the exact
// state this backlog exists to remove. If a raw per-record export is wanted it
// comes back WITH its caller.

// EvidenceCSVHeader names the columns, exported so a consumer can pin them.
var EvidenceCSVHeader = []string{
	"customer_id", "period_start", "period_end", "signable", "reason",
	"meter", "kind", "value", "reconciled", "event_history_value", "digest",
}

// WriteEvidenceCSV renders the document's lines with the verdict on each row.
func WriteEvidenceCSV(w io.Writer, d EvidenceDocument) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(EvidenceCSVHeader); err != nil {
		return err
	}
	reconByMeter := map[string]ReconciliationLine{}
	for _, r := range d.Reconciliation {
		reconByMeter[r.Meter] = r
	}
	rows := d.Lines
	if len(rows) == 0 {
		// A period with no usage still exports one row: the verdict must
		// arrive even when no numbers do, or an empty file reads as "no
		// document" rather than "a document that says zero".
		rows = []EvidenceLine{{}}
	}
	for _, l := range rows {
		recon := reconByMeter[l.Meter]
		checked := ""
		eventValue := ""
		if recon.Checked {
			checked = strconv.FormatBool(recon.Matches)
			eventValue = strconv.FormatInt(recon.EventHistory, 10)
		}
		if err := cw.Write([]string{
			d.CustomerID, d.PeriodStart, d.PeriodEnd,
			strconv.FormatBool(d.Signable), d.Reason,
			l.Meter, l.Kind, strconv.FormatInt(l.Value, 10),
			checked, eventValue, d.Digest,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
