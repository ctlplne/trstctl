// SPDX-License-Identifier: BUSL-1.1
package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tsa"
)

type auditScopeCheckpoint struct{ cp audit.Checkpoint }

func (s *auditScopeCheckpoint) LatestAuditCheckpoint(_ context.Context, tenant string) (audit.Checkpoint, bool, error) {
	return s.cp, s.cp.TenantID == tenant, nil
}

func TestAuditHTTPToolScopeAndRetainedExportChain(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const other = "22222222-2222-2222-2222-222222222222"
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendEvent := func(tenant, typ string) events.Event {
		t.Helper()
		e, err := log.Append(t.Context(), events.Event{TenantID: tenant, Type: typ, Data: []byte(`{"subject":"payments"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	appendEvent(other, "attestation.verified")
	prefix := appendEvent(tenant, "owner.created")
	key, err := jose.GenerateRSASigningKey("audit-tool-http")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := &auditScopeCheckpoint{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoint))
	old, err := svc.Search(t.Context(), audit.Query{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.cp = audit.Checkpoint{TenantID: tenant, BoundarySeq: prefix.Sequence, BoundaryHash: old[0].Hash, RecordCount: 1}
	appendEvent(tenant, "attestation.verified")
	appendEvent(tenant, "ephemeral.issued")
	appendEvent(tenant, "owner.created")
	role := authz.Role{Name: "audit-reader", Permissions: []authz.Permission{authz.AuditRead}}
	principal := authz.Principal{TenantID: tenant, Subject: "audit-fixture", Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tenant}}}}
	rootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	rootDER, err := crypto.SelfSignedCACert(rootKey, "Audit scope TSA root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tsaKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "Audit scope TSA"}, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaDER, err := crypto.SignTimestampingCertFromCSR(rootDER, rootKey, csr, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stamper, err := tsa.New(tsa.Config{TenantID: tenant, TSACertDER: tsaDER, TSASigner: tsaKey, Audit: auditsink.Nop{}})
	if err != nil {
		t.Fatal(err)
	}
	handler := api.New(nil, nil, nil, api.WithAudit(svc), api.WithAuditAnchor(func(ctx context.Context, head string) (auditanchor.Anchor, error) {
		return auditanchor.AnchorHead(ctx, stamper, head)
	}), api.WithRoles(role), api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }))
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	get := func(path, tenantHeader string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if tenantHeader != "" {
			req.Header.Set("X-Tenant-ID", tenantHeader)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("close audit response body: %v", err)
			}
		}()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil || resp.StatusCode != want {
			t.Fatalf("GET %s: status=%d want=%d error=%v body=%s", path, resp.StatusCode, want, err, raw)
		}
		return raw
	}
	const scope = "tool=workloads_machines&q=payments&as_of=2&limit=1"
	raw := get("/api/v1/audit/events?"+scope, "", 200)
	var response struct {
		Events []audit.Record `json:"events"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || len(response.Events) != 1 || response.Events[0].Type != "attestation.verified" || response.Events[0].TenantID != tenant {
		t.Fatalf("scoped HTTP records=%s err=%v", raw, err)
	}
	for _, path := range []string{"events", "export"} {
		get("/api/v1/audit/"+path+"?tool=not-a-tool", "", 400)
		get("/api/v1/audit/"+path+"?"+scope, other, 403)
	}
	var signed struct {
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(get("/api/v1/audit/export?"+scope, "", 200), &signed); err != nil {
		t.Fatal(err)
	}
	bundle, err := audit.VerifyBundle(signed.Bundle, svc.VerificationKeys())
	if err != nil || bundle.Count != 1 || bundle.Query.Tool != "workloads_machines" {
		t.Fatalf("signed scope lost: %+v %v", bundle, err)
	}
	stream := get("/api/v1/audit/export?format=ndjson&"+scope, "", 200)
	lines := strings.Split(strings.TrimSpace(string(stream)), "\n")
	if len(lines) != 2 {
		t.Fatalf("bounded stream has %d lines, want record and trailer", len(lines))
	}
	var row audit.Record
	var trailer struct {
		PrevHash  string `json:"prev_hash"`
		ChainHead string `json:"chain_head"`
		Count     int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatal(err)
	}
	// Stream encodings use chain_hash; the search/bundle Record shape uses
	// hash. Decode the actual wire field before challenging the chain.
	var wireHash struct {
		Hash string `json:"chain_hash"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &wireHash); err != nil || wireHash.Hash == "" {
		t.Fatalf("missing stream hash: %v", err)
	}
	row.Hash = wireHash.Hash
	if err := json.Unmarshal([]byte(lines[1]), &trailer); err != nil {
		t.Fatal(err)
	}
	if trailer.Count != 1 || trailer.PrevHash != checkpoint.cp.BoundaryHash {
		t.Fatalf("stream lost checkpoint: %+v", trailer)
	}
	head, err := audit.VerifyChainFrom(trailer.PrevHash, []audit.Record{row})
	if err != nil || head != trailer.ChainHead {
		t.Fatalf("served stream no longer verifies from its retained prefix: head=%s trailer=%s err=%v", head, trailer.ChainHead, err)
	}
	for _, format := range []auditanchor.Format{auditanchor.FormatJWS, auditanchor.FormatNDJSON, auditanchor.FormatCSV, auditanchor.FormatSplunkHEC, auditanchor.FormatSentinel} {
		raw := get("/api/v1/audit/export?format="+string(format)+"&"+scope, "", 200)
		proof, err := auditanchor.VerifyArtifact(raw, auditanchor.VerificationOptions{Format: format, AuditKeys: svc.VerificationKeys(), TSARootDER: rootDER})
		if err != nil || proof.RecordCount != 1 || proof.PrevHash != checkpoint.cp.BoundaryHash {
			t.Errorf("%s retained and scoped export must verify with pinned trust: %+v %v", format, proof, err)
		}
		if format != auditanchor.FormatJWS {
			tampered := []byte(strings.ReplaceAll(string(raw), "payments", "changed-subject"))
			if _, err := auditanchor.VerifyArtifact(tampered, auditanchor.VerificationOptions{Format: format, TSARootDER: rootDER}); err == nil {
				t.Errorf("%s verifier accepted changed scoped evidence", format)
			}
		}
	}
}
