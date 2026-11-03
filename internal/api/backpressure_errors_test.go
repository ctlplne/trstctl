// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/store"
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

// A busy datastore stays retryable under a handler's own status: the restore
// rehearsal's owner create came back 400 for "tenant event protection is in
// use" (CI 41548425634), which told the caller to change a valid request.
func TestBusyDatastoreUnderAHandlerStatusAnswersRetryable(t *testing.T) {
	api := &API{}
	busy := fmt.Errorf("%w: tenant event protection is in use", store.ErrDatastoreBusy)
	for name, err := range map[string]error{
		"wrapped as 400": errWithStatus(http.StatusBadRequest, busy),
		"bare":           busy,
	} {
		response := httptest.NewRecorder()
		api.writeError(response, err)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
			t.Errorf("%s: status=%d retry-after=%q, want 503 with Retry-After", name, response.Code, response.Header().Get("Retry-After"))
		}
	}
	response := httptest.NewRecorder()
	api.writeError(response, errWithStatus(http.StatusBadRequest, fmt.Errorf("owner name is required")))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("a real request error: status=%d, want 400", response.Code)
	}
}

// Every route answers a busy datastore with the documented 503 (owner note
// 2026-11-02, item 4). A handler that flattens an error into a status string
// (errStatus(s, err.Error())) or writes a problem from its text directly hides
// the busy cause from writeError; errStatusFrom keeps it. The classifier in
// responses.go is where an error's text becomes a problem on purpose, and the
// identity CSR refusal records a disposition after passing a busy store
// through.
func TestHandlersKeepTheCauseOfTheErrorsTheyClassify(t *testing.T) {
	flatten := regexp.MustCompile(`errStatus\(http\.Status\w+, \w+\.Error\(\)\)|problem\.New\(http\.Status\w+, \w+\.Error\(\)\)`)
	allowed := map[string]int{"responses.go": 7, "identity_transition_execution.go": 1}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name())) // #nosec G304 -- reads this package's own sources in a test (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for i, line := range strings.Split(string(src), "\n") {
			if flatten.MatchString(line) {
				found++
				if found > allowed[e.Name()] {
					t.Errorf("%s:%d flattens an error; use errStatusFrom(status, err) so a busy datastore still answers 503", e.Name(), i+1)
				}
			}
		}
	}
	busy := fmt.Errorf("%w: tenant event protection is in use", store.ErrDatastoreBusy)
	response := httptest.NewRecorder()
	(&API{}).writeError(response, errStatusFrom(http.StatusInternalServerError, busy))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("errStatusFrom around a busy store: status=%d, want 503", response.Code)
	}
}
