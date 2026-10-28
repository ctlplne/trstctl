// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/api"

	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/config"
)

func TestServedCertificateExportWritesOnlyItsOwnCMDBBindingAndReadsBack(t *testing.T) {
	const writerRef = "secret://cmdb/export"
	var mu sync.Mutex
	rows := map[string]map[string]string{}
	posts, reads := 0, 0
	badReadback := false
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer cmdb-export-fixture" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/identifyreconcile":
			var body cmdbexport.Request
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Items) != 1 || body.Items[0].ClassName != cmdbexport.CertificateClass {
				t.Error("invalid certificate IRE request")
				w.WriteHeader(400)
				return
			}
			if r.URL.Query().Get("sysparm_data_source") != "trstctl" {
				t.Error("missing dedicated source")
			}
			item := body.Items[0]
			if !strings.HasPrefix(item.Source.Key, servedTestTenant+":") {
				t.Error("unbound source identity")
			}
			posts++
			rows[item.Values["fingerprint"]] = item.Values
			_, _ = w.Write([]byte(`{"result":{"hasError":false,"items":[{"className":"cmdb_ci_certificate","sysId":"0123456789abcdef0123456789abcdef","operation":"UPDATE","errorCount":0}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/cmdb_ci_certificate/0123456789abcdef0123456789abcdef":
			reads++
			for _, values := range rows {
				out := map[string]string{"sys_id": "0123456789abcdef0123456789abcdef"}
				for k, v := range values {
					out[k] = v
				}
				if badReadback {
					out["state"] = "wrong"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"result": out})
				return
			}
			w.WriteHeader(404)
		default:
			t.Errorf("unexpected CMDB request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer sink.Close()
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.CMDBCertificateExports = []config.CMDBCertificateExportBinding{{ID: "certificate-writer", TenantID: servedTestTenant, Enabled: true, InstanceURL: sink.URL, TokenRef: writerRef, DataSource: "trstctl", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}}
	})
	originalClient := h.srv.cmdbExports.clientFor
	h.srv.cmdbExports.clientFor = func(binding config.CMDBCertificateExportBinding) (*http.Client, error) {
		client, err := originalClient(binding)
		if err != nil {
			return nil, err
		}
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.RootCAs = sink.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		return client, nil
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "certs:read", "certs:write", "secrets:write", "connectors:read", "connectors:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "cmdb/export", "value": "cmdb-export-fixture"})
	if status != http.StatusCreated {
		t.Fatalf("credential = %d %s", status, body)
	}
	cert := seedNearExpiryNotificationCertificate(t, h, tok, "cmdb-export.example.test")
	request := map[string]any{"binding_id": "certificate-writer", "certificate_id": cert.ID}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", tok, "a224-invalid-cert", map[string]any{"binding_id": "certificate-writer", "certificate_id": "not-a-uuid"})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid certificate id %d %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", tok, "a224-export", request)
	if status != http.StatusAccepted {
		t.Fatalf("certificate export = %d %s; want queued", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" || queued.Status != "pending" {
		t.Fatalf("queued response %s: %v", body, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	get := func(id string) api.CMDBExportStatus {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/integrations/cmdb/certificate-exports/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("export status %d %s", status, body)
		}
		var got api.CMDBExportStatus
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := get(queued.ID)
	if got.Status != "verified" || got.Receipt == nil || got.Receipt.Fingerprint != cert.Fingerprint || got.Receipt.SystemID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unverified export: %+v", got)
	}
	mu.Lock()
	firstPosts, firstReads, firstRows := posts, reads, len(rows)
	mu.Unlock()
	if firstPosts != 1 || firstReads != 1 || firstRows != 1 {
		t.Fatalf("effects posts=%d reads=%d rows=%d", firstPosts, firstReads, firstRows)
	}
	// A retry after receipt append but before queue acknowledgment must not
	// write to ServiceNow again; the retained receipt settles this command.
	forceNotificationOutboxPending(t, h, queued.ID)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", tok, "a224-export", request)
	if status != http.StatusAccepted {
		t.Fatalf("idempotent export %d %s", status, body)
	}
	mu.Lock()
	afterRetry := posts
	mu.Unlock()
	if afterRetry != 1 {
		t.Fatal("receipt replay wrote another CI")
	}
	// Current lifecycle state wins when an old request reaches the worker.
	if err := h.srv.orch.RevokeCertificate(t.Context(), h.tenant, cert.Fingerprint, cert.Serial, "keyCompromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", tok, "a224-revoked-export", request)
	if status != http.StatusAccepted {
		t.Fatalf("revoked export %d %s", status, body)
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state := get(queued.ID); state.Status != "verified" || state.Receipt == nil || state.Receipt.CertificateStatus != "revoked" {
		t.Fatalf("revoked export status %+v", state)
	}
	mu.Lock()
	remoteState, count := rows[cert.Fingerprint]["state"], len(rows)
	mu.Unlock()
	if remoteState != "revoked" || count != 1 {
		t.Fatalf("remote state %q rows %d", remoteState, count)
	}
	// Read permission and tenant binding apply to the immutable receipt too.
	otherTenant := "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, otherTenant, "Other CMDB tenant")
	otherToken := seedScopedToken(t, h.store, otherTenant, "certs:read", "certs:write", "connectors:read")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/integrations/cmdb/certificate-exports/"+queued.ID, otherToken, nil)
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant receipt %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", otherToken, "a224-cross-tenant", request)
	if status != http.StatusBadRequest {
		t.Fatalf("cross-tenant binding %d %s", status, body)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", reader, "a224-reader-cannot-write", request)
	if status != http.StatusForbidden {
		t.Fatalf("reader export %d %s", status, body)
	}
	// A successful IRE response with a different independent read never gets
	// a completion receipt, even though the HTTP write itself succeeded.
	mu.Lock()
	badReadback = true
	mu.Unlock()
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/integrations/cmdb/certificate-exports", tok, "a224-bad-readback", request)
	if status != http.StatusAccepted {
		t.Fatalf("mismatch export %d %s", status, body)
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatal(err)
	}
	_ = h.srv.Drain(t.Context())
	if state := get(queued.ID); state.Status == "verified" || state.Receipt != nil {
		t.Fatalf("mismatched CI claimed verified: %+v", state)
	}
}
