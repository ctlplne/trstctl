// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestRollbackAdmissionReportsAbsentAndUnappliedRunsWithoutInternalError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		runFound bool
		wanted   map[string]bool
		eligible map[string]bool
		status   int
		contains string
	}{
		{"absent run", false, map[string]bool{"asset-a": true}, nil, http.StatusNotFound, "run not found"},
		{"terminal failed run", true, map[string]bool{"asset-a": true}, nil, http.StatusConflict, "no applied, rollback-eligible result"},
		{"partially eligible", true, map[string]bool{"asset-a": true, "asset-b": true}, map[string]bool{"asset-a": true}, http.StatusConflict, "asset-b"},
		{"eligible", true, map[string]bool{"asset-a": true}, map[string]bool{"asset-a": true}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRollbackOutcome(tc.runFound, tc.wanted, tc.eligible, "run-a")
			if tc.status == 0 {
				if err != nil {
					t.Fatalf("eligible rollback refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ineligible rollback was accepted")
			}
			recorder := httptest.NewRecorder()
			api.New(nil, nil, nil).WriteError(recorder, err)
			if recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), tc.contains) {
				t.Fatalf("problem status=%d body=%s, want %d containing %q", recorder.Code, recorder.Body.String(), tc.status, tc.contains)
			}
		})
	}
}
