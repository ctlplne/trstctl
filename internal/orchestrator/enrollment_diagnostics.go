// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/projections"
)

// RecordEnrollmentDiagnosis appends and projects one protocol refusal under the
// request's tenant. The immutable event is authoritative; the bounded RLS read
// model is only its operator-facing projection.
func (o *Orchestrator) RecordEnrollmentDiagnosis(ctx context.Context, tenantID string, diagnostic enrollmentdiag.Diagnosis) error {
	if o == nil || o.log == nil || o.store == nil {
		return fmt.Errorf("orchestrator: enrollment diagnostics are not configured")
	}
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("orchestrator: enrollment diagnostic tenant id is required (AN-1)")
	}
	payload, err := json.Marshal(projections.EnrollmentDiagnosticObserved{
		Protocol: string(diagnostic.Protocol), Step: string(diagnostic.Step), Cause: string(diagnostic.Cause),
		Summary: diagnostic.Summary, Remediation: diagnostic.Remediation,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEnrollmentDiagnosticObserved, tenantID, payload)
	return err
}
