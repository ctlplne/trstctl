// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/store"
)

func n0035RewriteOptions(key *jose.SigningKey) []events.TenantDataRewriteOption {
	return []events.TenantDataRewriteOption{
		events.WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return errors.New("rewrite did not change the selected event")
			}
			return nil
		}),
		events.WithTenantDataContinuity(historycontinuity.NewReceiptSigner(key)),
		events.WithTenantDataCutoverPreparation(func(ctx context.Context, _ events.TenantDataRewriteReport,
			proceed func(context.Context) error) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(context.Context, events.TenantDataAuditView) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: crypto.SHA256Hex([]byte("n0035-genesis"))}, nil
		}),
	}
}

func n0035RewriteFixture(t *testing.T) (*events.Log, []events.TenantDataRewriteOption) {
	t.Helper()
	key, err := jose.GenerateRSASigningKey("n0035-ssh-rewrite")
	if err != nil {
		t.Fatal(err)
	}
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(key)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, n0035RewriteOptions(key)
}

func TestN0035SSHRevocationsRecoverAcrossSignedOtherTenantRewriteInPages(t *testing.T) {
	ctx := t.Context()
	log, options := n0035RewriteFixture(t)
	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":42}`)},
		{Type: "fixture.data", TenantID: "tenant-b", Data: []byte(`{"value":"before"}`)},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatal(err)
	}
	before := p.verifiedSnapshot
	changed, err := log.RewriteTenantData(ctx, "tenant-b", func(_ string, _ int, data []byte) ([]byte, bool, error) {
		if !bytes.Contains(data, []byte("before")) {
			return data, false, nil
		}
		return bytes.ReplaceAll(data, []byte("before"), []byte("after")), true, nil
	}, options...)
	if err != nil || changed != 1 {
		t.Fatalf("signed cross-tenant rewrite: changed=%d err=%v", changed, err)
	}
	after, err := log.Snapshot(ctx)
	if err != nil || after.Generation == before.Generation {
		t.Fatalf("rewrite generation before=%q after=%q err=%v", before.Generation, after.Generation, err)
	}
	for page := uint64(1); page < after.LastSequence; page++ {
		if err := p.syncRevocationsWithLimit(ctx, true, 1); !errors.Is(err, errSSHKRLBehind) {
			t.Fatalf("replacement page %d: %v, want bounded behind", page, err)
		}
		if p.verifiedSnapshot != before || !p.krl.IsRevoked(42, "") {
			t.Fatalf("page %d published a partial replacement KRL", page)
		}
	}
	if err := p.syncRevocationsWithLimit(ctx, true, 1); err != nil {
		t.Fatalf("finish signed replacement generation: %v", err)
	}
	if p.verifiedSnapshot.Generation != after.Generation || !p.krl.IsRevoked(42, "") || p.KRLVersion() != 1 {
		t.Fatalf("replacement KRL lost revocation: snapshot=%+v version=%d", p.verifiedSnapshot, p.KRLVersion())
	}
	if _, err := log.Append(ctx, events.Event{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":43}`)}); err != nil {
		t.Fatal(err)
	}
	if err := p.syncRevocations(ctx, true); err != nil || !p.krl.IsRevoked(43, "") {
		t.Fatalf("new revocation after rewrite: %v", err)
	}
}

func TestN0035SSHRejectsReplacementGenerationThatDropsServedRevocation(t *testing.T) {
	ctx := t.Context()
	log, options := n0035RewriteFixture(t)
	if _, err := log.Append(ctx, events.Event{Type: eventSSHCertRevoked, TenantID: "tenant-a",
		Data: []byte(`{"serial":42}`)}); err != nil {
		t.Fatal(err)
	}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatal(err)
	}
	_, err = log.RewriteTenantData(ctx, "tenant-a", func(_ string, _ int, data []byte) ([]byte, bool, error) {
		return bytes.ReplaceAll(data, []byte(`"serial":42`), []byte(`"serial":43`)), true, nil
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.syncRevocations(ctx, true); err == nil || !p.krl.IsRevoked(42, "") || p.krl.IsRevoked(43, "") {
		t.Fatalf("unsafe replacement KRL was published: err=%v", err)
	}
}

func TestN0035ServedReadinessRecoversAfterOtherTenantRewrite(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("n0035-served-rewrite")
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarnessWithEventOptions(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		[]events.OpenOption{events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(key))})
	registerServedTenant(t, h, "SSH tenant")
	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: servedTestTenant, Data: []byte(`{"serial":42}`)},
		{Type: "fixture.data", TenantID: "tenant-b", Data: []byte(`{"value":"before"}`)},
	} {
		if _, err := h.log.Append(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.srv.protocols.ssh.syncRevocations(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	changed, err := h.log.RewriteTenantData(t.Context(), "tenant-b", func(_ string, _ int, data []byte) ([]byte, bool, error) {
		if !bytes.Contains(data, []byte("before")) {
			return data, false, nil
		}
		return bytes.ReplaceAll(data, []byte("before"), []byte("after")), true, nil
	}, n0035RewriteOptions(key)...)
	if err != nil || changed != 1 {
		t.Fatalf("signed other-tenant rewrite: changed=%d err=%v", changed, err)
	}
	h.srv.protocols.ssh.syncMu.Lock()
	h.srv.protocols.ssh.syncedFrom = time.Time{}
	h.srv.protocols.ssh.syncMu.Unlock()
	for _, path := range []string{"/readyz", "/ssh/krl"} {
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = readAllClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s after signed rewrite = %d, want 200", path, resp.StatusCode)
		}
	}
	if !h.srv.protocols.ssh.krl.IsRevoked(42, "") {
		t.Fatal("served KRL dropped the pre-rewrite denial")
	}
}

func TestN0035ServedPrivacyErasureInEitherTenantKeepsSSHReady(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("n0035-served-privacy")
	if err != nil {
		t.Fatal(err)
	}
	st := newServerTestStore(t)
	h := newServedHarnessWithOwnedStore(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		[]events.OpenOption{
			events.WithRequiredPrivacyEventPolicies(),
			events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)),
			events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(key)),
		}, st, func(d *Deps) { d.AuditSigningKey = key })
	registerServedTenant(t, h, "SSH tenant")
	const otherTenant = "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, otherTenant, "privacy tenant")
	if _, err := h.log.Append(t.Context(), events.Event{Type: eventSSHCertRevoked,
		TenantID: servedTestTenant, Data: []byte(`{"serial":42}`)}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.protocols.ssh.syncRevocations(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	const subject = "privacy-operator@example.test"
	token := seedScopedTokenSubject(t, h.store, otherTenant, subject, "*")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token,
		"n0035-create-owner", map[string]string{"kind": "user", "name": subject, "email": subject}); code != http.StatusCreated {
		t.Fatalf("other-tenant owner: %d %s", code, body)
	}
	before, err := h.log.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/privacy/subject-erasures", token,
		"n0035-erase-owner", map[string]string{"subject": subject, "reason": "erase own personal data"}); code != http.StatusCreated {
		t.Fatalf("other-tenant privacy erasure: %d %s", code, body)
	}
	after, err := h.log.Snapshot(t.Context())
	if err != nil || before.Generation == after.Generation {
		t.Fatalf("privacy erasure did not switch generation: before=%q after=%q err=%v", before.Generation, after.Generation, err)
	}
	h.srv.protocols.ssh.syncMu.Lock()
	h.srv.protocols.ssh.syncedFrom = time.Time{}
	h.srv.protocols.ssh.syncMu.Unlock()
	for _, path := range []string{"/readyz", "/ssh/krl"} {
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s after privacy erasure = %d %s", path, resp.StatusCode, body)
		}
	}
	if !h.srv.protocols.ssh.krl.IsRevoked(42, "") {
		t.Fatal("served KRL dropped the revocation after privacy erasure")
	}
	const ownSubject = "ssh-operator@example.test"
	ownToken := seedScopedTokenSubject(t, h.store, servedTestTenant, ownSubject, "*")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", ownToken,
		"n0035-create-ssh-owner", map[string]string{"kind": "user", "name": ownSubject, "email": ownSubject}); code != http.StatusCreated {
		t.Fatalf("SSH-tenant owner: %d %s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/privacy/subject-erasures", ownToken,
		"n0035-erase-ssh-owner", map[string]string{"subject": ownSubject, "reason": "erase own personal data"}); code != http.StatusCreated {
		t.Fatalf("SSH-tenant privacy erasure: %d %s", code, body)
	}
	h.srv.protocols.ssh.syncMu.Lock()
	h.srv.protocols.ssh.syncedFrom = time.Time{}
	h.srv.protocols.ssh.syncMu.Unlock()
	for _, path := range []string{"/readyz", "/ssh/krl"} {
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s after same-tenant privacy erasure = %d %s", path, resp.StatusCode, body)
		}
	}
	if !h.srv.protocols.ssh.krl.IsRevoked(42, "") {
		t.Fatal("served KRL dropped the revocation after same-tenant erasure")
	}
}

// TestSSHProtocolRestoresTenantRevocationsFromEventLog is the regression guard
// for a live g78 failure: the product API appended ssh.cert.revoked, but a fresh
// control-plane process started with an empty in-memory KRL. Hosts downloading
// /ssh/krl after that restart could therefore accept a certificate trstctl had
// already revoked.
func TestSSHProtocolRestoresTenantRevocationsFromEventLog(t *testing.T) {
	ctx := context.Background()
	log, err := eventstest.OpenFixture(ctx, config.NATS{
		Mode:     config.NATSEmbedded,
		StoreDir: filepath.Join(t.TempDir(), "nats"),
	})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":42,"reason":"compromised"}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"key_id":"retired-host","reason":"replaced"}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-b", Data: []byte(`{"serial":99}`)},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatalf("append %s event: %v", event.TenantID, err)
		}
	}

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatalf("new SSH protocol: %v", err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatalf("restore SSH revocations: %v", err)
	}
	if got := p.KRLVersion(); got != 2 {
		t.Fatalf("restored KRL version = %d, want two tenant-local revocation events", got)
	}
	if got := p.RevokedCount(); got != 2 {
		t.Fatalf("restored revoked count = %d, want serial plus key ID", got)
	}
	snapshot := p.krl.Distribute()
	if !slices.Contains(snapshot.Serials, uint64(42)) || slices.Contains(snapshot.Serials, uint64(99)) {
		t.Fatalf("restored serials = %v, want tenant-a serial only", snapshot.Serials)
	}
	if !slices.Contains(snapshot.KeyIDs, "retired-host") {
		t.Fatalf("restored key IDs = %v, want retired-host", snapshot.KeyIDs)
	}
}

// A public KRL poll advances a finite tail without returning a partial trust
// artifact. Restart must reconstruct the final artifact from immutable source
// history, including a poll that stopped midway through catch-up.
func TestSSHProtocolBoundsRequestCatchUpAndRestoresAfterRestart(t *testing.T) {
	ctx := context.Background()
	storeDir := filepath.Join(t.TempDir(), "nats")
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatal(err)
	}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.restoreRevocations(ctx, log); err != nil {
		t.Fatal(err)
	}
	for _, event := range []events.Event{
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":42}`)},
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"key_id":"retired-host"}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-b", Data: []byte(`{"serial":`)},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	p.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	if err := p.syncRevocationsWithLimit(ctx, false, 2); !errors.Is(err, errSSHKRLBehind) {
		t.Fatalf("first finite page: %v, want behind", err)
	}
	if p.applied != 2 || !p.syncedFrom.IsZero() {
		t.Fatalf("partial cursor=%d throttle=%s, want 2 and immediate retry", p.applied, p.syncedFrom)
	}
	// Simulate a process loss before the next page: the in-memory cursor is
	// gone, so the replacement must rebuild the tenant's revocations through
	// all four source positions, without parsing the other tenant's payload.
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.restoreRevocations(ctx, reopened); err != nil {
		t.Fatal(err)
	}
	if restored.KRLVersion() != 2 || restored.RevokedCount() != 2 || restored.applied != 4 {
		t.Fatalf("cold restore cursor=%d version=%d count=%d", restored.applied, restored.KRLVersion(), restored.RevokedCount())
	}
	for _, event := range []events.Event{
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)},
		{Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":43}`)},
	} {
		if _, err := reopened.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	restored.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	if err := restored.syncRevocationsWithLimit(ctx, false, 2); !errors.Is(err, errSSHKRLBehind) {
		t.Fatalf("first later page: %v, want behind", err)
	}
	if err := restored.syncRevocationsWithLimit(ctx, false, 2); err != nil {
		t.Fatalf("second later page: %v", err)
	}
	if restored.applied != 7 || restored.KRLVersion() != 3 || restored.RevokedCount() != 3 {
		t.Fatalf("complete cursor=%d version=%d count=%d", restored.applied, restored.KRLVersion(), restored.RevokedCount())
	}
}

// TestSSHProtocolFailsClosedOnMalformedRevocationHistory prevents a damaged
// source-of-truth event from silently producing an incomplete KRL at startup.
func TestSSHProtocolFailsClosedOnMalformedRevocationHistory(t *testing.T) {
	ctx := context.Background()
	log, err := eventstest.OpenFixture(ctx, config.NATS{
		Mode:     config.NATSEmbedded,
		StoreDir: filepath.Join(t.TempDir(), "nats"),
	})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, events.Event{
		Type: eventSSHCertRevoked, TenantID: "tenant-a", Data: []byte(`{"serial":`),
	}); err != nil {
		t.Fatalf("append malformed fixture: %v", err)
	}

	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", (&recordingSSHGuard{}).guard, &stubSSHWorkflow{})
	if err != nil {
		t.Fatalf("new SSH protocol: %v", err)
	}
	if err := p.restoreRevocations(ctx, log); err == nil {
		t.Fatal("malformed tenant revocation history was ignored; startup would serve an incomplete KRL")
	}
}
