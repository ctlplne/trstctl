// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/tenancy"
)

// refusingEnroller refuses every enrollment with err.
type refusingEnroller struct{ err error }

func (e refusingEnroller) EnrollBootstrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, e.err
}
func (e refusingEnroller) EnrollRenewal(context.Context, [][]byte, []byte) ([]byte, error) {
	return nil, e.err
}
func (refusingEnroller) CABundlePEM() []byte { return nil }

// A bootstrap token holder whose tenant is refused hears the same 403 for every
// condition: the reason admission names, and any text an inner error adds,
// stay on the server.
func TestBootstrapEnrollTenantRefusalIsTheSameForEveryCondition(t *testing.T) {
	const reason = "the tenant's erasure is pending"
	for name, refusal := range map[string]error{
		"refusal":            tenancy.Refused(reason),
		"wrapped refusal":    fmt.Errorf("enroll: %w", tenancy.Refused(reason)),
		"sentinel with text": fmt.Errorf("%w: %s", tenancy.ErrServiceUnavailable, reason),
	} {
		t.Run(name, func(t *testing.T) {
			a := api.New(nil, nil, nil, api.WithAgentEnroller(refusingEnroller{err: refusal}))
			body, _ := json.Marshal(map[string]string{
				"token": "tok",
				"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
			})
			req := httptest.NewRequest(http.MethodPost, "/enroll/bootstrap", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d (%s); want 403", rec.Code, rec.Body.String())
			}
			var problem struct {
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Detail != tenancy.ErrServiceUnavailable.Error() {
				t.Errorf("detail %q; want %q", problem.Detail, tenancy.ErrServiceUnavailable.Error())
			}
			if strings.Contains(rec.Body.String(), "erasure") || strings.Contains(rec.Body.String(), "enroll:") {
				t.Errorf("the 403 carries the inner error's text: %s", rec.Body.String())
			}
		})
	}
}
