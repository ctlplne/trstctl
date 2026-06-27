package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedDiscoveryNetworkScanEndToEnd is the JOURNEY-001 proof: the assembled
// control plane serves discovery source/run/finding APIs, queues scan execution
// through the outbox, records findings through projected events, and feeds the
// certificate inventory. On the pre-wiring tree the first POST is a 404 because
// discovery existed only as library code.
func TestServedDiscoveryNetworkScanEndToEnd(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-tls",
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
		ID       string          `json:"id"`
		TenantID string          `json:"tenant_id"`
		Kind     string          `json:"kind"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.TenantID != h.tenant || source.Kind != "network" {
		t.Fatalf("bad source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.SourceID != source.ID || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed run = %+v, want one successful discovery", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string `json:"kind"`
			Ref         string `json:"ref"`
			Provenance  string `json:"provenance"`
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("findings count = %d body %s, want 1", len(findings.Items), body)
	}
	if f := findings.Items[0]; f.Kind != "x509_certificate" || f.Ref != u.Host || f.Fingerprint == "" || !strings.Contains(f.Provenance, "network") {
		t.Fatalf("bad finding: %+v", f)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 || certs.Items[0].DeploymentLocation != u.Host || certs.Items[0].Source != "discovery:network" || certs.Items[0].Fingerprint == "" {
		t.Fatalf("inventory was not populated from discovery: %+v", certs.Items)
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; discovery is not fully event-sourced", eventType)
		}
	}
}

func TestServedDiscoveryNetworkScanBlocksReservedTargets(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "blocked-network-targets",
		"kind": "network",
		"config": map[string]any{
			"targets": []string{
				"127.0.0.1:443",
				"169.254.169.254:443",
				"10.0.0.0:443",
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}
	if !h.hasEvent(t, "discovery.network_target_blocked") {
		t.Fatal("reserved network targets were not emitted as blocked-target events")
	}
}

// TestServedCloudCertificateDiscoveryACMEndToEnd is the DISC-04 acceptance proof:
// the served discovery dispatcher constructs the AWS ACM cloud-cert collector from a
// credential-reference-only source config, runs it from the outbox worker, records
// metadata-only discovery findings, and feeds the certificate inventory. The ACM
// backend here is an ACM-compatible HTTP double with read-only List/Get operations;
// real cloud credentials can point the same config at AWS ACM.
func TestServedCloudCertificateDiscoveryACMEndToEnd(t *testing.T) {
	arn := "arn:aws:acm:us-east-1:111111111111:certificate/cloud-edge"
	var seen []string
	acm := servedACMDouble(map[string]string{
		arn: servedCloudCertPEM(t, "cloud-edge.example", "cloud-edge.example"),
	}, &seen)
	t.Cleanup(acm.Close)
	t.Setenv("TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "SECRET")

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "aws-acm-east",
		"kind": "cloud_certificate",
		"config": map[string]any{
			"providers": []map[string]any{
				{
					"provider":               "aws-acm",
					"region":                 "us-east-1",
					"endpoint":               acm.URL,
					"allow_private_endpoint": true,
					"access_key_id_ref":      "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID",
					"secret_access_key_ref":  "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cloud discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "cloud_certificate" {
		t.Fatalf("bad cloud source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start cloud discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain cloud discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get cloud discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed cloud run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed cloud run = %+v, want one successful cloud discovery", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list cloud findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "AKID") {
		t.Fatalf("served cloud finding leaked credential material or identifiers: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string          `json:"kind"`
			Ref         string          `json:"ref"`
			Provenance  string          `json:"provenance"`
			Fingerprint string          `json:"fingerprint"`
			Metadata    json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode cloud findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("cloud findings count = %d body %s, want 1", len(findings.Items), body)
	}
	f := findings.Items[0]
	if f.Kind != "x509_certificate" || f.Ref != arn || f.Provenance != "cloud:aws-acm:"+arn || f.Fingerprint == "" {
		t.Fatalf("bad cloud finding: %+v", f)
	}
	var meta map[string]any
	if err := json.Unmarshal(f.Metadata, &meta); err != nil {
		t.Fatalf("decode cloud metadata: %v (%s)", err, f.Metadata)
	}
	if meta["provider"] != "aws-acm" || meta["location"] != "us-east-1" || meta["resource_id"] != arn {
		t.Fatalf("cloud finding metadata = %+v, want provider/location/resource id", meta)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates after cloud discovery: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 || certs.Items[0].DeploymentLocation != arn || certs.Items[0].Source != "discovery:cloud:aws-acm" || certs.Items[0].Fingerprint == "" {
		t.Fatalf("inventory was not populated from cloud discovery: %+v", certs.Items)
	}

	for _, target := range seen {
		if target != "CertificateManager.ListCertificates" && target != "CertificateManager.GetCertificate" {
			t.Fatalf("cloud discovery invoked non-read-only ACM operation %q; seen=%v", target, seen)
		}
	}
	if len(seen) == 0 {
		t.Fatal("cloud discovery did not call the ACM backend")
	}
	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; cloud discovery is not event-sourced", eventType)
		}
	}
}

func servedACMDouble(arnToPEM map[string]string, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		*seen = append(*seen, target)
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch target {
		case "CertificateManager.ListCertificates":
			var summaries []map[string]string
			for arn := range arnToPEM {
				summaries = append(summaries, map[string]string{"CertificateArn": arn})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": summaries})
		case "CertificateManager.GetCertificate":
			var req struct{ CertificateArn string }
			_ = json.Unmarshal(body, &req)
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": arnToPEM[req.CertificateArn]})
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
}

func servedCloudCertPEM(t *testing.T, commonName string, dns ...string) string {
	t.Helper()
	hosts := append([]string{commonName}, dns...)
	cert, err := mtls.SelfSignedServerCert(hosts, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return string(cert.TrustPEM)
}
