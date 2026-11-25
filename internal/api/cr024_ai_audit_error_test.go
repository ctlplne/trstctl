// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/mcpserver"
	"trstctl.com/trstctl/internal/rca"
)

func TestCR024EvidenceAuditOutageIsRetryableAndDoesNotLeakAppendDetails(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "rca", err: rca.ErrAuditUnavailable},
		{name: "mcp", err: mcpserver.ErrAuditUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&API{}).writeError(w, errors.Join(tc.err, errors.New("private append path /tmp/secret-fixture")))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "private append path") || !strings.Contains(w.Body.String(), "retry") {
				t.Fatalf("audit outage response status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}
