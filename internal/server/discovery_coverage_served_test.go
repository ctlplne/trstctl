// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDiscoveryCoverageThreeBuckets proves the coverage surface through
// the shipping HTTP path (full server assembly over embedded PostgreSQL,
// in-process NATS, and the real out-of-process signer — no fakes): a network
// source whose run completes against a loopback TLS target turns its classes
// OBSERVED with attribution; a class no source is configured for reports
// OBSERVABLE-UNOBSERVED with the configure action; the structural classes are
// enumerated with reasons; and the class/source_kind filters narrow the rows.
func TestServedDiscoveryCoverageThreeBuckets(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "coverage-net",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}

	if status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	}); status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("coverage = %d body %s, want 200", status, body)
	}
	type coverageClass struct {
		Class          string     `json:"class"`
		Status         string     `json:"status"`
		SourceKinds    []string   `json:"source_kinds"`
		ObservedBy     []string   `json:"observed_by"`
		LastObservedAt *time.Time `json:"last_observed_at"`
		Reason         string     `json:"reason"`
		Action         string     `json:"action"`
	}
	var got struct {
		GeneratedAt              time.Time       `json:"generated_at"`
		Observed                 int             `json:"observed"`
		Unobserved               int             `json:"unobserved"`
		StructurallyUnobservable int             `json:"structurally_unobservable"`
		Classes                  []coverageClass `json:"classes"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode coverage: %v (%s)", err, body)
	}
	byClass := map[string]coverageClass{}
	for _, c := range got.Classes {
		byClass[c.Class] = c
	}

	tls, ok := byClass["tls-endpoint"]
	if !ok || tls.Status != "OBSERVED" {
		t.Fatalf("tls-endpoint = %+v, want OBSERVED (run completed against the loopback target)", tls)
	}
	if len(tls.ObservedBy) != 1 || tls.ObservedBy[0] != "coverage-net" || tls.LastObservedAt == nil {
		t.Fatalf("tls-endpoint attribution = %+v, want observed_by [coverage-net] with a timestamp", tls)
	}
	if ck := byClass["certificate-key"]; ck.Status != "OBSERVED" {
		t.Fatalf("certificate-key = %+v, want OBSERVED via the same network envelope", ck)
	}

	ct, ok := byClass["ct-exposed-certificate"]
	if !ok || ct.Status != "OBSERVABLE-UNOBSERVED" {
		t.Fatalf("ct-exposed-certificate = %+v, want OBSERVABLE-UNOBSERVED (no ct_log source configured)", ct)
	}
	if ct.Reason == "" || ct.Action == "" {
		t.Fatalf("unobserved class must name the reason and the closing action: %+v", ct)
	}

	fw, ok := byClass["firmware-embedded-crypto"]
	if !ok || fw.Status != "STRUCTURALLY-UNOBSERVABLE" || fw.Reason == "" {
		t.Fatalf("firmware-embedded-crypto = %+v, want STRUCTURALLY-UNOBSERVABLE with a stated reason", fw)
	}

	if got.Observed+got.Unobserved+got.StructurallyUnobservable != len(got.Classes) {
		t.Fatalf("summary %d+%d+%d does not cover %d classes",
			got.Observed, got.Unobserved, got.StructurallyUnobservable, len(got.Classes))
	}
	if got.Observed < 2 || got.StructurallyUnobservable < 5 {
		t.Fatalf("implausible bucket counts: %+v", got)
	}

	// The class filter narrows to exactly the named class.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage?class=tls-endpoint", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered coverage = %d, want 200", status)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode filtered coverage: %v", err)
	}
	if len(got.Classes) != 1 || got.Classes[0].Class != "tls-endpoint" || got.Observed != 1 {
		t.Fatalf("class filter returned %+v, want exactly tls-endpoint", got.Classes)
	}

	// The source_kind filter keeps only classes that kind's envelope observes.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage?source_kind=ct_log", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("kind-filtered coverage = %d, want 200", status)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode kind-filtered coverage: %v", err)
	}
	if len(got.Classes) != 1 || got.Classes[0].Class != "ct-exposed-certificate" {
		t.Fatalf("source_kind filter returned %+v, want exactly ct-exposed-certificate", got.Classes)
	}
}
