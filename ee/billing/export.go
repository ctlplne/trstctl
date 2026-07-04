// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"time"
)

var ExportCSVHeader = []string{"tenant_id", "tenant_slug", "meter", "kind", "period_start", "period_end", "value", "unit"}

func WriteCSV(w io.Writer, records []UsageRecord) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(ExportCSVHeader); err != nil {
		return err
	}
	for _, record := range records {
		if err := cw.Write([]string{
			record.TenantID,
			record.TenantSlug,
			record.Meter,
			record.Kind,
			record.PeriodStart.UTC().Format(time.RFC3339),
			record.PeriodEnd.UTC().Format(time.RFC3339),
			strconv.FormatInt(record.Value, 10),
			record.Unit,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func WriteJSONL(w io.Writer, records []UsageRecord) error {
	enc := json.NewEncoder(w)
	for _, record := range records {
		record.PeriodStart = record.PeriodStart.UTC()
		record.PeriodEnd = record.PeriodEnd.UTC()
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}
