// SPDX-License-Identifier: BUSL-1.1

package ownership

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Bulk ownership import, and what it refuses to do (epic I2).
//
// I2 wants CMDB CI records reconciled against ownership. The reconciliation
// half is the interesting half and it is not "apply the CMDB's answer": an
// external system's view of who owns a certificate is a CLAIM, sometimes a
// stale one, and the record it would overwrite may be the only thing a human
// ever confirmed.
//
// So this import applies what is safe and REPORTS what is not. The rule is one
// sentence: a source may fill in what is unknown; it may not overwrite what a
// human attested. Everything else here follows from that.
//
// The alternative — last-writer-wins — is what makes CMDB integrations
// distrusted. One import silently replaces a verified owner with a stale group
// alias, the expiry notification goes to a disbanded team, and nobody learns
// why until the certificate expires. A conflict that shows up in a queue is a
// worse day for the operator and a much better one for the estate.

// Source names where an ownership claim came from.
type Source string

const (
	// SourceUnknown is the absence of provenance, not a value. Rows that predate
	// provenance carry it, and it must never be read as "a human said so".
	SourceUnknown Source = ""
	// SourceManual is a human acting in the product.
	SourceManual Source = "manual"
	// SourceCSVImport is a bulk import, including a CMDB export somebody saved
	// to a file. Deliberately distinct from SourceCMDB: a file a person exported
	// last quarter is not a live reconciliation, and conflating them would let
	// stale data inherit a live source's credibility.
	SourceCSVImport Source = "csv-import"
	// SourceCMDB is a live reconciliation against the CMDB.
	SourceCMDB Source = "cmdb"
)

// Record is one ownership claim from an import.
type Record struct {
	OwnerName     string
	Email         string
	ApplicationID string
	Service       string
	BusinessUnit  string
	Environment   string
	// SourceRef ties this row back to the record that produced it — a CMDB
	// sys_id, a line number. A conflict nobody can trace to its cause is a
	// conflict nobody can resolve.
	SourceRef string
}

// Existing is the ownership already stored, as the import sees it.
type Existing struct {
	OwnerID       string
	ApplicationID string
	Service       string
	BusinessUnit  string
	Environment   string
	Source        Source
	// Attested is whether a human has ever confirmed this ownership. It is the
	// single most important input here: attestation is the scarcest fact in the
	// system and the only one an import must never destroy.
	Attested bool
}

// Conflict is one field an import declined to change.
type Conflict struct {
	OwnerID         string
	Field           string
	CurrentValue    string
	CurrentSource   Source
	IncomingValue   string
	IncomingSource  Source
	IncomingRef     string
	CurrentAttested bool
	// Why is the sentence an operator reads. It says what was NOT done, because
	// a conflict list whose entries look like completed work is worse than none.
	Why string
}

// Plan is what an import would do, split into what it will apply and what it
// refuses to.
//
// Separating them is the point. A single "imported 412 owners" number hides the
// eleven it silently overwrote, and those eleven are the only rows anybody
// needed to look at.
type Plan struct {
	Apply     []Update
	Conflicts []Conflict
	// Unchanged counts rows whose incoming values already match. Reported so a
	// re-run's "0 applied" reads as "already in sync" rather than "did nothing".
	Unchanged int
}

// Update is one field an import will set.
type Update struct {
	OwnerID string
	Field   string
	Value   string
	Source  Source
	Ref     string
}

// ParseCSV reads ownership records. The header names the columns, so an export
// with extra columns in a different order still imports.
func ParseCSV(r io.Reader) ([]Record, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("ownership: parse csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("ownership: csv is empty")
	}
	index := map[string]int{}
	for i, name := range rows[0] {
		index[strings.ToLower(strings.TrimSpace(name))] = i
	}
	if _, ok := index["owner"]; !ok {
		return nil, errors.New(`ownership: csv needs an "owner" column naming the owner each row is about`)
	}
	at := func(row []string, col string) string {
		i, ok := index[col]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	var out []Record
	for n, row := range rows[1:] {
		rec := Record{
			OwnerName:     at(row, "owner"),
			Email:         at(row, "email"),
			ApplicationID: at(row, "application_id"),
			Service:       at(row, "service"),
			BusinessUnit:  at(row, "business_unit"),
			Environment:   at(row, "environment"),
			SourceRef:     at(row, "source_ref"),
		}
		if rec.OwnerName == "" {
			// A row naming no owner cannot be attributed to anything. Skipping it
			// silently would make the import's count disagree with the file.
			return nil, fmt.Errorf("ownership: csv line %d names no owner", n+2)
		}
		if rec.SourceRef == "" {
			rec.SourceRef = fmt.Sprintf("line:%d", n+2)
		}
		out = append(out, rec)
	}
	return out, nil
}

// Reconcile decides what an import may apply.
//
// The rule, in full: a source fills UNKNOWN fields freely; it may CHANGE a
// known field only when the stored ownership was not human-attested; and it may
// never change an attested field, which becomes a conflict instead.
func Reconcile(rec Record, existing Existing, source Source, observed time.Time) Plan {
	var plan Plan
	fields := []struct {
		name     string
		incoming string
		current  string
	}{
		{"application_id", rec.ApplicationID, existing.ApplicationID},
		{"service", rec.Service, existing.Service},
		{"business_unit", rec.BusinessUnit, existing.BusinessUnit},
		{"environment", rec.Environment, existing.Environment},
	}
	for _, f := range fields {
		switch {
		case f.incoming == "":
			// The source said nothing about this field. Saying nothing is not
			// saying "empty": treating a blank spreadsheet cell as a deletion is
			// how bulk imports erase data nobody meant to touch.
			continue
		case f.incoming == f.current:
			plan.Unchanged++
		case f.current == "":
			// Filling in unknown. Always safe, and the main thing an import is
			// for.
			plan.Apply = append(plan.Apply, Update{
				OwnerID: existing.OwnerID, Field: f.name, Value: f.incoming, Source: source, Ref: rec.SourceRef,
			})
		case existing.Attested:
			plan.Conflicts = append(plan.Conflicts, Conflict{
				OwnerID: existing.OwnerID, Field: f.name,
				CurrentValue: f.current, CurrentSource: existing.Source,
				IncomingValue: f.incoming, IncomingSource: source, IncomingRef: rec.SourceRef,
				CurrentAttested: true,
				Why: "Not applied: a human attested this ownership, and an import does not overwrite " +
					"an attestation. Resolve it deliberately — the stored value may be right and the " +
					"source stale.",
			})
		default:
			// Known, but never attested, and a source now disagrees. Applying it
			// is defensible — nobody vouched for the old value — but it is still
			// a CHANGE to data somebody may be relying on, so it is applied AND
			// recorded rather than applied quietly.
			plan.Apply = append(plan.Apply, Update{
				OwnerID: existing.OwnerID, Field: f.name, Value: f.incoming, Source: source, Ref: rec.SourceRef,
			})
			plan.Conflicts = append(plan.Conflicts, Conflict{
				OwnerID: existing.OwnerID, Field: f.name,
				CurrentValue: f.current, CurrentSource: existing.Source,
				IncomingValue: f.incoming, IncomingSource: source, IncomingRef: rec.SourceRef,
				CurrentAttested: false,
				Why: "Applied and recorded: the stored value was never attested by a human, so the " +
					"source was taken as newer — but it did change, and a change nobody was told " +
					"about is how ownership data quietly stops matching reality.",
			})
		}
	}
	return plan
}
