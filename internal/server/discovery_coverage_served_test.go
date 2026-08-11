// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
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

	h := newDiscoveryRelayHarness(t, "coverage-net")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "coverage-net",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
			"segment":        "coverage-net",
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

	if status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	}); status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	executeNextDiscoveryRelayJob(t, h)

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/coverage", tok, nil)
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
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/coverage?class=tls-endpoint", tok, nil)
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
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/coverage?source_kind=ct_log", tok, nil)
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

// Coverage measured against a DECLARATION, and the honest zero (epic C3).
//
// The property that matters most is the one that reads as unhelpful: an estate
// with nothing declared must report NO coverage, not full coverage. A system
// that declares itself complete because nobody told it what it was missing is
// the exact failure this epic exists to remove — and it is the natural
// behaviour of any coverage number computed from findings alone, because what
// was never looked at leaves no trace in what was found.
func TestServedCoverageMeasuresAgainstDeclaredSegments(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	// Nothing declared: the surface must not claim coverage it cannot support.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("coverage: status %d body %s", status, body)
	}
	var empty struct {
		SegmentCoveragePercent int `json:"segment_coverage_percent"`
		Segments               []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"segments"`
	}
	if err := json.Unmarshal(body, &empty); err != nil {
		t.Fatalf("decode coverage: %v", err)
	}
	if len(empty.Segments) != 0 {
		t.Fatalf("coverage invented %d segments nobody declared", len(empty.Segments))
	}
	if empty.SegmentCoveragePercent != 0 {
		t.Errorf("an estate with no declared segments reported %d%% coverage; "+
			"a system that calls itself complete because nobody told it what it was missing "+
			"is the defect this epic removes", empty.SegmentCoveragePercent)
	}

	// Three declarations: one never swept, one swept inside its window, one
	// deliberately excluded.
	for _, seg := range []store.DiscoverySegment{
		{Name: "dmz", Ranges: []string{"10.0.1.0/24"}, StalenessHours: 24},
		{Name: "core", Ranges: []string{"10.0.2.0/24"}, StalenessHours: 24},
		{Name: "lab", Ranges: []string{"10.9.0.0/16"}, StalenessHours: 24,
			Excluded: true, ExclusionReason: "non-production, no customer data"},
	} {
		if _, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, seg); err != nil {
			t.Fatalf("declare %s: %v", seg.Name, err)
		}
	}
	if err := h.store.RecordSegmentSweep(ctx, h.tenant, "core", "relay-1", 12, time.Now().UTC()); err != nil {
		t.Fatalf("record sweep: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("coverage: status %d body %s", status, body)
	}
	var got struct {
		SegmentCoveragePercent int `json:"segment_coverage_percent"`
		Segments               []struct {
			Name            string `json:"name"`
			Status          string `json:"status"`
			ExclusionReason string `json:"exclusion_reason"`
		} `json:"segments"`
		Unknowns []struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
			Action  string `json:"action"`
		} `json:"unknowns"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode coverage: %v", err)
	}

	byName := map[string]string{}
	for _, seg := range got.Segments {
		byName[seg.Name] = seg.Status
	}
	if byName["core"] != "swept" {
		t.Errorf("core = %q, want swept", byName["core"])
	}
	if byName["dmz"] != "never" {
		t.Errorf("dmz = %q, want never — a declared segment nothing has swept is the "+
			"blind spot this whole surface exists to report", byName["dmz"])
	}
	if byName["lab"] != "excluded" {
		t.Errorf("lab = %q, want excluded", byName["lab"])
	}

	// One of two in-scope segments swept. The excluded one is in NEITHER half:
	// a coverage number that rose because somebody excluded something would
	// reward exactly the wrong behaviour.
	if got.SegmentCoveragePercent != 50 {
		t.Errorf("coverage = %d%%, want 50%% (core swept, dmz not, lab excluded from both halves)",
			got.SegmentCoveragePercent)
	}

	// And the blind spots are NAMED, with what closes each.
	kinds := map[string]string{}
	for _, u := range got.Unknowns {
		kinds[u.Kind+":"+u.Subject] = u.Action
	}
	if _, ok := kinds["segment_never_swept:dmz"]; !ok {
		t.Errorf("the never-swept segment is not in the blind-spot register: %+v", got.Unknowns)
	}
	if _, ok := kinds["segment_excluded:lab"]; !ok {
		t.Errorf("the excluded segment is not in the blind-spot register; a declared exclusion "+
			"is a blind spot an operator chose, and it still belongs on the list: %+v", got.Unknowns)
	}
	if action := kinds["segment_never_swept:dmz"]; action == "" {
		t.Error("the never-swept blind spot names no action; a gap an operator cannot close is a complaint")
	}
}
