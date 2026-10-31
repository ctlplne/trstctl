// SPDX-License-Identifier: BUSL-1.1

package adcs

import "trstctl.com/trstctl/internal/adcsdb"

// The certificate-database vocabulary lives in internal/adcsdb so a relay can
// summarize a CA database without importing the issuer stack (A162). These
// names keep the issuer package's existing callers unchanged.

// DBDisposition is AD CS's view of one row in its certificate database.
type DBDisposition = adcsdb.DBDisposition

// DBRow is one certificate-database row, reduced to what inventory needs.
type DBRow = adcsdb.DBRow

// DBSummary counts rows by disposition.
type DBSummary = adcsdb.DBSummary

const (
	DispositionIssued  = adcsdb.DispositionIssued
	DispositionPending = adcsdb.DispositionPending
	DispositionRevoked = adcsdb.DispositionRevoked
	DispositionDenied  = adcsdb.DispositionDenied
	DispositionFailed  = adcsdb.DispositionFailed
	DispositionUnknown = adcsdb.DispositionUnknown
)

// MapDisposition maps a certsrv disposition code to the vocabulary.
func MapDisposition(code int) DBDisposition { return adcsdb.MapDisposition(code) }

// ParseDBRow parses one certutil -view row.
func ParseDBRow(fields map[string]string) (DBRow, error) { return adcsdb.ParseDBRow(fields) }

// Summarize counts rows by disposition.
func Summarize(rows []DBRow) DBSummary { return adcsdb.Summarize(rows) }
