// SPDX-License-Identifier: MPL-2.0

package enrollmentdiag_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
)

func TestACMEValidityDiagnosisRequiresTypedIssuanceEvidence(t *testing.T) {
	t.Parallel()
	validityErr := crypto.EnforceLeafProfileInfo(crypto.CSRInfo{}, 3*time.Minute, crypto.LeafProfile{MaxValidity: 2 * time.Minute})
	if validityErr == nil {
		t.Fatal("profile accepted an excessive requested lifetime")
	}
	nameErr := crypto.EnforceLeafProfileInfo(crypto.CSRInfo{DNSNames: []string{"outside.test"}}, time.Minute,
		crypto.LeafProfile{PermittedDNSSuffixes: []string{"allowed.test"}})
	for _, tc := range []struct {
		name string
		step enrollmentdiag.Step
		err  error
		want enrollmentdiag.Cause
	}{
		{"typed", enrollmentdiag.StepIssue, validityErr, "validity_not_permitted"},
		{"wrapped", enrollmentdiag.StepIssue, fmt.Errorf("issuance failed: %w", validityErr), "validity_not_permitted"},
		{"prose copy", enrollmentdiag.StepIssue, errors.New(validityErr.Error()), enrollmentdiag.CauseUnknown},
		{"different profile constraint", enrollmentdiag.StepIssue, nameErr, enrollmentdiag.CauseUnknown},
		{"wrong stage", enrollmentdiag.StepValidation, validityErr, enrollmentdiag.CauseUnknown},
		{"no cause", enrollmentdiag.StepIssue, nil, enrollmentdiag.CauseUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := enrollmentdiag.ClassifyACME(tc.step, "serverInternal", tc.err)
			if d.Cause != tc.want || d.Step != tc.step {
				t.Fatalf("diagnosis = %+v, want cause %s at %s", d, tc.want, tc.step)
			}
			if d.Actionable() != (tc.want != enrollmentdiag.CauseUnknown) {
				t.Fatalf("actionability does not match available evidence: %+v", d)
			}
		})
	}
}
