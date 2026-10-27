// SPDX-License-Identifier: BUSL-1.1

package tlsvalidity

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Label names the requirements a report applies, for an export that travels
// without its JSON.
func (s Source) Label() string {
	return fmt.Sprintf("CA/Browser Forum TLS Baseline Requirements %s (%s) section %s", s.Version, s.Published, s.Section)
}

// Filename is the report's export file name; it names the BR version.
func Filename(r Report) string {
	return fmt.Sprintf("validity-readiness-br-%s-%s.csv", r.Requirements.Version, r.GeneratedAt.UTC().Format(dayLayout))
}

// CSVHeader is the export's column order: one row per certificate or profile
// and step.
var CSVHeader = []string{
	"record", "id", "name", "scope", "automation", "deployment", "not_after",
	"step_effective", "step_max_days", "step_in_effect", "verdict", "reasons", "requirements",
}

// CSV renders the report as a spreadsheet-safe file. Every row names the
// requirements it was evaluated against.
func CSV(r Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(CSVHeader); err != nil {
		return nil, err
	}
	label := r.Requirements.Label()
	inEffect := make(map[string]bool, len(r.Steps))
	for _, step := range r.Steps {
		inEffect[step.Effective] = step.InEffect
	}
	write := func(record []string) error {
		for i := range record {
			record[i] = spreadsheetSafe(record[i])
		}
		return w.Write(record)
	}
	for _, cert := range r.Certificates {
		for _, step := range cert.Steps {
			if err := write([]string{
				"certificate", cert.CertificateID, cert.Subject, string(cert.Scope), string(cert.Automation),
				string(cert.Deployment), cert.NotAfter.UTC().Format(time.RFC3339), step.Effective,
				strconv.Itoa(step.MaxDays), strconv.FormatBool(inEffect[step.Effective]), string(step.Verdict),
				strings.Join(step.Reasons, ";"), label,
			}); err != nil {
				return nil, err
			}
		}
	}
	for _, profile := range r.Profiles {
		scope := "not_public_tls"
		if profile.PublicTLS {
			scope = string(ScopePublicTLS)
		}
		for _, step := range profile.Steps {
			verdict := "within_maximum"
			switch {
			case !profile.PublicTLS:
				verdict = "not_public_tls"
			case step.Flagged:
				verdict = "flagged"
			}
			if err := write([]string{
				"profile", profile.Name, fmt.Sprintf("%s v%d", profile.Name, profile.Version), scope, "", "", "",
				step.Effective, strconv.Itoa(step.MaxDays), strconv.FormatBool(inEffect[step.Effective]), verdict,
				step.Reason, label,
			}); err != nil {
				return nil, err
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// spreadsheetSafe stops a cell from reading as a formula when the file is
// opened in a spreadsheet: subjects and profile names are operator text.
func spreadsheetSafe(value string) string {
	trimmed := strings.TrimLeft(value, "\t\r\n ")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
