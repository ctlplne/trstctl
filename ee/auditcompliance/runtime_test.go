// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tsa"
)

type unavailableTSA struct{}

func (unavailableTSA) Timestamp(context.Context, []byte) (tsa.Token, error) {
	return tsa.Token{}, errors.New("injected authority outage")
}

func TestLicensedFactoryAnchorsExactHeadAndDistinguishesAuthorityFailure(t *testing.T) {
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "audit compliance TSA root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "audit compliance TSA"}, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := crypto.SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := tsa.New(tsa.Config{TenantID: tenantA, TSACertDER: cert, TSASigner: key})
	if err != nil {
		t.Fatal(err)
	}
	runtime := auditcompliance.Build(editionseam.AuditComplianceDeps{Timestamper: authority})
	if runtime.Retention != nil {
		t.Fatal("unconfigured retention attached")
	}
	head := crypto.SHA256Hex([]byte("exact tenant audit head"))
	anchor, err := runtime.Anchor(context.Background(), head)
	if err != nil || anchor.Kind != auditanchor.KindRFC3161 {
		t.Fatalf("anchor=%+v err=%v", anchor, err)
	}
	if err := auditanchor.Verify(anchor, head, rootDER); err != nil {
		t.Fatal(err)
	}
	if err := auditanchor.Verify(anchor, crypto.SHA256Hex([]byte("different head")), rootDER); err == nil {
		t.Fatal("accepted timestamp for a different head")
	}
	runtime = auditcompliance.Build(editionseam.AuditComplianceDeps{Timestamper: unavailableTSA{}})
	anchor, err = runtime.Anchor(context.Background(), head)
	if err == nil || anchor.Kind != auditanchor.KindNone || anchor.ChainHead != head || !strings.Contains(anchor.Detail, "timestamp authority did not answer") || strings.Contains(anchor.Detail, "licence") {
		t.Fatalf("licensed failure lost its cause: anchor=%+v err=%v", anchor, err)
	}
}

func TestLicensedAssemblyRetentionSurvivesCoreDowngrade(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	dsn := st.SystemPool().Config().ConnString()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The archived event also establishes the tenant's retained authority, so
	// downgrade must preserve both signed history and access to that history.
	if _, err := log.Append(ctx, events.Event{
		ID: "licensed-old-event", Type: projections.EventTenantRegistered,
		TenantID: tenantA, Time: time.Now().Add(-48 * time.Hour),
		Data: tenantRegistered("audit downgrade"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantA, TokenHash: hash, Subject: "auditor", Scopes: []string{"audit:read"}}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("downgrade-audit")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	licensed, err := server.Build(ctx, server.Deps{Store: st, Log: log, AuditSigningKey: key, AuditRetention: time.Hour, AuditArchiveDir: dir, AuditComplianceFactory: auditcompliance.Build})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := licensed.RunRetentionOnce(ctx)
	if err != nil || summary.RecordsArchived != 1 || summary.RecordsSourceRetained != 1 || summary.RecordsPruned != 0 {
		t.Fatalf("licensed worker summary=%+v err=%v", summary, err)
	}
	checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantA)
	if err != nil || !ok {
		t.Fatalf("checkpoint=%+v exists=%t err=%v", checkpoint, ok, err)
	}
	saved, err := os.ReadFile(checkpoint.ArchiveURI)
	if err != nil {
		t.Fatal(err)
	}
	if err := licensed.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	core, err := server.Build(ctx, server.Deps{Store: st, Log: log, AuditSigningKey: key, AuditRetention: time.Nanosecond, AuditArchiveDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Shutdown(context.Background()) })
	summary, err = core.RunRetentionOnce(ctx)
	if err != nil || summary.RecordsArchived != 0 {
		t.Fatalf("downgrade ran retention: %+v %v", summary, err)
	}
	after, ok, err := st.LatestAuditCheckpoint(ctx, tenantA)
	if err != nil || !ok || after != checkpoint {
		t.Fatalf("downgrade changed checkpoint: before=%+v after=%+v err=%v", checkpoint, after, err)
	}
	archived, err := audit.VerifyRetentionBundle(string(saved), key.JWKS())
	if err != nil || archived.Count != 1 || archived.Records[0].ID != "licensed-old-event" {
		t.Fatalf("old archive unavailable after downgrade: %+v %v", archived, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=jws", nil)
	request.Header.Set("Authorization", "Bearer "+secrettext.String(raw))
	response := httptest.NewRecorder()
	core.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("core export status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope auditanchor.EvidenceEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Anchor.Kind != auditanchor.KindNone || envelope.Anchor.Detail != "anchoring requires an Enterprise licence" {
		t.Fatalf("downgrade anchor=%+v", envelope.Anchor)
	}
	remaining, err := audit.VerifyBundle(envelope.Bundle, key.JWKS())
	if err != nil || remaining.PrevHash != checkpoint.BoundaryHash || remaining.Count < 1 {
		t.Fatalf("downgrade signed continuation=%+v err=%v", remaining, err)
	}
	if err := audit.VerifyCheckpointSourceRetained(ctx, log, checkpoint); err != nil {
		t.Fatal(err)
	}
}
