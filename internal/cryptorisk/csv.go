// SPDX-License-Identifier: BUSL-1.1

package cryptorisk

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cryptoreadiness"
)

// csvHeader is one row per key, in report order.
var csvHeader = []string{
	"priority", "priority_reason", "key", "kind", "subject", "algorithm", "key_bits", "exposures",
	"deadline_status", "deadline_rule", "deprecated_after", "disallowed_after", "deadline_source",
	"dependents", "dependents_by_kind", "owners", "plan", "recommended", "evidence_ids",
}

// WriteCSV writes the report's items as CSV. A cell a spreadsheet would read as
// a formula is neutralized the way the crypto-readiness export does it, so an
// exported subject cannot execute.
func WriteCSV(w io.Writer, r Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, it := range r.Items {
		row := []string{
			strconv.Itoa(it.Priority), rankReasonOf(it), it.Key, it.Kind, it.Subject, it.Algorithm, zeroBlank(it.KeyBits),
			strings.Join(it.Exposures, ";"), it.Deadline.Status, it.Deadline.Rule, zeroBlank(it.Deadline.DeprecatedAfter),
			zeroBlank(it.Deadline.DisallowedAfter), it.Deadline.Source, strconv.Itoa(it.Dependents.Count),
			byKind(it.Dependents.ByKind), strings.Join(it.Owners, ";"), planCell(it.Plan), it.Plan.Recommended,
			strings.Join(it.EvidenceIDs, ";"),
		}
		for i := range row {
			row[i] = cryptoreadiness.SpreadsheetSafe(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func zeroBlank(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func byKind(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, ";")
}

func planCell(p Plan) string {
	parts := make([]string, 0, len(p.Actions))
	for _, a := range p.Actions {
		cell := a.CampaignID + " " + a.Status
		if !a.Deadline.IsZero() {
			cell += " by " + a.Deadline.UTC().Format(time.DateOnly)
		}
		if a.Stale {
			cell += " (stale)"
		}
		parts = append(parts, cell)
	}
	return strings.Join(parts, ";")
}
