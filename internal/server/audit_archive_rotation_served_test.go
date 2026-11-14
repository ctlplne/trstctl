// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A234-L1 Done-when: after the audit signing key is rotated, a tenant still
// downloads a segment the earlier key signed, verified with the public key its
// archive event retained in the immutable log; never unverified. A segment
// whose event names no signing key (archived before events named it) and one
// whose event names a key that did not sign it are refused (409), as is a
// changed segment.
func TestServedAuditSegmentsDownloadAfterTheAuditKeyRotatesA234L1(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	tenants := map[string]string{
		"retained": "6a1e2d3c-5b6a-4978-8c9d-0e1f2a3b4c01",
		"legacy":   "6a1e2d3c-5b6a-4978-8c9d-0e1f2a3b4c02",
		"wrong":    "6a1e2d3c-5b6a-4978-8c9d-0e1f2a3b4c03",
	}
	for name, id := range tenants {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: id, Name: "rotation " + name}); err != nil {
			t.Fatal(err)
		}
		registerServerTestTenant(t, st, log, id, "rotation "+name)
		if _, err := log.Append(ctx, events.Event{ID: "rotation-history-" + name, TenantID: id, Type: "audit.test", Data: []byte(`{"reason":"before the rotation"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	earlier, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	current, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	jwks := func(k *jose.SigningKey) string {
		doc, err := k.PublicJWKS()
		if err != nil {
			t.Fatal(err)
		}
		return string(doc)
	}
	dir := t.TempDir()
	// The server runs with the rotated key; the segments were signed with the
	// earlier one.
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: current, AuditArchiveDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	segments := map[string]string{
		"retained": seedTenantAuditSegmentSignedBy(t, log, st, earlier, srv.audit, tenants["retained"], dir, jwks(earlier)),
		"legacy":   seedTenantAuditSegmentSignedBy(t, log, st, earlier, srv.audit, tenants["legacy"], dir, ""),
		"wrong":    seedTenantAuditSegmentSignedBy(t, log, st, earlier, srv.audit, tenants["wrong"], dir, jwks(stranger)),
	}
	download := func(name string) (int, []byte) {
		token := seedServedAPIToken(t, ctx, st, tenants[name], "archive-reader-"+name+"@example.invalid", []string{string(authz.AuditArchiveRead)})
		request := httptest.NewRequest(http.MethodGet, "/api/v1/audit/archives/"+segments[name], nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes()
	}
	code, body := download("retained")
	var release struct {
		Bundle     string          `json:"bundle"`
		SignerJWKS json.RawMessage `json:"signer_jwks"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &release) != nil {
		t.Fatalf("a segment the earlier key signed, after the rotation = %d %s; want 200", code, body)
	}
	// The download names the earlier key, so an auditor verifies it offline.
	named, err := jose.ParseJWKSet(release.SignerJWKS)
	if err != nil {
		t.Fatalf("the download does not carry the key that signed it: %v (%s)", err, release.SignerJWKS)
	}
	if _, err := audit.VerifyRetentionBundle(release.Bundle, named); err != nil {
		t.Fatalf("the segment does not verify with the key its download names: %v", err)
	}
	if verified, err := audit.VerifyRetentionBundle(release.Bundle, earlier.JWKS()); err != nil || verified.TenantID != tenants["retained"] {
		t.Fatalf("the downloaded segment does not verify offline with the earlier key: %v", err)
	}
	if _, err := audit.VerifyRetentionBundle(release.Bundle, current.JWKS()); err == nil {
		t.Fatal("the segment verified with the rotated key: the test did not rotate")
	}
	for _, name := range []string{"legacy", "wrong"} {
		if code, body := download(name); code != http.StatusConflict {
			t.Fatalf("%s segment after the rotation = %d %s; want 409", name, code, body)
		}
	}
	t.Logf("A234L1_OK segment=%s", segments["retained"])
}
