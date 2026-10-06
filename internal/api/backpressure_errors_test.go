// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestTransactionRollbackResponseDoesNotClaimEntireCommandWasUndone(t *testing.T) {
	api := &API{}
	response := httptest.NewRecorder()
	if !api.writeBackpressureError(response, &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}) {
		t.Fatal("PostgreSQL deadlock was not handled")
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", response.Code)
	}
	var problem struct {
		Detail    string `json:"detail"`
		Retryable bool   `json:"retryable"`
		SQLState  string `json:"sqlstate"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Retryable || problem.SQLState != "40P01" ||
		!strings.Contains(strings.ToLower(problem.Detail), "inspect the resource") ||
		strings.Contains(problem.Detail, "request's transaction back") {
		t.Fatalf("unsafe rollback response: %+v", problem)
	}
}
