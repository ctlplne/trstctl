// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/projections"
)

// AD CS certificate-database ingestion (epic F4).
//
// The domain-joined relay collects certutil rows from a CA database; the API
// layer parses and summarizes them (the production caller of adcs.ParseDBRow
// and adcs.Summarize, which had none), and this thin command records the
// per-disposition breakdown as an event. Parsing lives in the API rather than
// here because internal/ca imports the orchestrator, so importing adcs here
// would be an import cycle.

// RecordADCSDatabaseIngested emits the summarized CA-database sweep. The
// summary is computed by the caller; this appends the event and projects it.
func (o *Orchestrator) RecordADCSDatabaseIngested(ctx context.Context, tenantID string, in projections.ADCSDatabaseIngested) error {
	if strings.TrimSpace(in.CAConfig) == "" {
		return fmt.Errorf("orchestrator: adcs database ingest requires a ca_config")
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventADCSDatabaseIngested, tenantID, payload)
	return err
}
