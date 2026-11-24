// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestCR676DiscoverySourceRejectsLiteralBeforeEventAndReaderList(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedTokenSubject(t, h.store, h.tenant, "cr676-writer", "discovery:write", "discovery:read")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "cr676-reader", "discovery:read")
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "cr676-create", map[string]any{
		"name": "cr676-literal", "kind": "cloud_certificate",
		"config": map[string]any{"providers": []any{map[string]any{
			"provider": "aws-acm", "region": "us-east-1", "api_key": "fake-cr676-value",
		}}},
	})
	if code != http.StatusBadRequest {
		t.Errorf("literal credential create = HTTP %d; want 400", code)
	}
	if strings.Contains(string(body), "fake-cr676-value") {
		t.Fatal("create response echoed literal credential")
	}
	if h.hasEvent(t, "discovery.source.upserted") {
		t.Fatal("rejected literal-bearing source reached the immutable event log")
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/sources", reader, nil)
	if code != http.StatusOK {
		t.Fatalf("read sources = HTTP %d", code)
	}
	if strings.Contains(string(body), "fake-cr676-value") || strings.Contains(string(body), "cr676-literal") {
		t.Fatal("reader listed a rejected literal-bearing source")
	}
}

func TestCR676DiscoveryReaderCannotSeeLegacySourceLiteral(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "cr676-legacy-reader", "discovery:read")
	_, err := h.srv.orch.UpsertDiscoverySource(t.Context(), h.tenant, store.DiscoverySource{
		Kind: "cloud_certificate", Name: "cr676-legacy",
		Config: json.RawMessage(`{"providers":[{"provider":"aws-acm","region":"us-east-1","api_key":"fake-cr676-legacy","secret_access_key_ref":"fake-cr676-ref"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/sources", reader, nil)
	if code != http.StatusOK {
		t.Fatalf("read sources = HTTP %d", code)
	}
	if strings.Contains(string(body), "fake-cr676") {
		t.Fatal("discovery reader received a legacy literal credential")
	}
	if !strings.Contains(string(body), "us-east-1") {
		t.Fatal("discovery reader lost safe provider metadata")
	}
}
