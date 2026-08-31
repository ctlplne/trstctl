// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestBrokerHistoryParametersRejectAmbiguousAndUnboundedReads(t *testing.T) {
	encode := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	valid := `{"at":"2026-08-31T12:00:00Z","id":"11111111-1111-1111-1111-111111111111"}`
	bad := []string{"q=a;b", "q=%zz", "limit=0", "limit=101", "limit=1&limit=2", "limit=x", "q=a&q=b", "unknown=1", "state=active", "q=" + strings.Repeat("x", 201), "method=" + strings.Repeat("x", 129), "cursor=bad"}
	for _, raw := range []string{valid + ` {}`, strings.Replace(valid, `}`, `,"unknown":1}`, 1), strings.Replace(valid, "2026-08-31T12:00:00Z", "0001-01-01T00:00:00Z", 1), strings.Replace(valid, "11111111-1111-1111-1111-111111111111", "not-a-uuid", 1)} {
		bad = append(bad, "cursor="+encode(raw))
	}
	for _, query := range bad {
		if _, _, err := brokerHistoryParams(httptest.NewRequest("GET", "/?"+query, nil)); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
	f, limit, err := brokerHistoryParams(httptest.NewRequest("GET", "/?limit=100&cursor="+encode(valid)+"&q="+url.QueryEscape("  agent-7  ")+"&state=expired", nil))
	if err != nil || limit != 100 || f.Limit != 101 || f.Query != "agent-7" || f.AfterTime == nil || f.State != "expired" {
		t.Fatalf("valid bounded query changed: %+v limit=%d err=%v", f, limit, err)
	}
}

func TestBrokerHistoryResponseDoesNotInventMissingFactsOrHealth(t *testing.T) {
	now := time.Now().UTC()
	for _, state := range store.BrokerCertificateStates() {
		row := brokerHistoryResponse(store.BrokerCertificate{CertificateID: "certificate", State: state}, now, "unknown")
		if row.MetadataState != "unavailable" || row.Issuance != nil || row.StateReason == "" || row.ProjectionState != "unknown" || row.GeneratedAt != now {
			t.Fatalf("invented history evidence: %+v", row)
		}
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		for _, absent := range []string{`"issuance":`, `"not_before":`, `"not_after":`, `"current_owner_id":`} {
			if strings.Contains(string(raw), absent) {
				t.Fatalf("missing evidence serialized as a non-null schema field: %s", absent)
			}
		}
	}
	if got := (&API{}).brokerHistoryProjectionState(t.Context()); got != "unknown" {
		t.Fatalf("missing event log became %s", got)
	}
}
