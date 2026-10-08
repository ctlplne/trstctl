// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

// Batch D (the SSH journey): the raw /ssh/ mutating routes must behave exactly
// like /api/v1/ssh/certificates. They used to authenticate a bearer token and then
// mint or revoke directly: no durable revocation record (F258), no principal
// policy (F259), no option checks (RV-08d), no ABAC, rate limit, Idempotency-Key
// or actor (RV-08e, RV-08f), and certs:issue could revoke (RV-08g). Revocations
// also never reached a second replica (RV-08b).

func sshServedProtocols() config.Protocols {
	return config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}
}

// buildServedSSHReplica assembles a second control plane over the harness's
// durable spine (store, event log, signer, KEK): a restart, or another replica.
func buildServedSSHReplica(t *testing.T, h *servedHarness) *httptest.Server {
	t.Helper()
	replica, err := Build(t.Context(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: h.kek, Protocols: sshServedProtocols(),
	})
	if err != nil {
		t.Fatalf("build replica: %v", err)
	}
	cleanupServedServer(t, replica)
	ts := httptest.NewServer(replica.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func sshPost(t *testing.T, ts *httptest.Server, path, token, idem string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func sshKRL(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + "/ssh/krl")
	if err != nil {
		t.Fatalf("GET /ssh/krl: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ssh/krl = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Trstctl-Tenant-ID"); got != servedTestTenant {
		t.Fatalf("GET /ssh/krl tenant header = %q, want %q", got, servedTestTenant)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("GET /ssh/krl cache policy = %q, want no-store", got)
	}
	krl, _ := io.ReadAll(resp.Body)
	return krl
}

func sshTestPublicKey(t *testing.T) string {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	pub, err := crypto.SSHPublicKeyFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(pub))
}

func tenantEvents(t *testing.T, log *events.Log, eventType string) []events.Event {
	t.Helper()
	var out []events.Event
	if err := log.Replay(context.Background(), 1, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == servedTestTenant {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return out
}

// F258, RV-08a: a raw revocation is recorded (key ID trimmed) and survives restart.
func TestServedRawSSHRevokeSurvivesRestart(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-revoker", []string{"certs:issue", "certs:write"})
	if code, body := sshPost(t, h.ts, "/ssh/revoke", token, "f258-raw-revoke", map[string]any{"serial": 4242, "key_id": "  lost-laptop  "}); code != http.StatusNoContent {
		t.Fatalf("POST /ssh/revoke = %d %s, want 204", code, body)
	}
	recorded := false
	for _, e := range tenantEvents(t, h.log, eventSSHCertRevoked) {
		var got sshRevokeRequest
		if json.Unmarshal(e.Data, &got) == nil && got.Serial == 4242 && got.KeyID == "lost-laptop" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("raw /ssh/revoke wrote no ssh.cert.revoked event with the trimmed key ID; a restart forgets the revocation")
	}
	restarted := buildServedSSHReplica(t, h)
	if !bytes.Contains(sshKRL(t, restarted), []byte("lost-laptop")) {
		t.Fatal("restarted control plane serves a KRL without the raw /ssh/revoke revocation")
	}
}

// RV-08b: a revocation recorded on one replica reaches every replica's KRL within
// a bounded time (public KRL reads catch up at most once per sshKRLSyncInterval).
func TestServedSSHRevocationReachesEveryReplica(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	other := buildServedSSHReplica(t, h)
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-revoker", []string{"certs:write", "certs:read"})
	if code, body := sshPost(t, h.ts, "/api/v1/ssh/certificates/revoke", token, "rv08b-revoke", map[string]any{"key_id": "replica-lost-laptop"}); code != http.StatusOK {
		t.Fatalf("product revoke = %d %s, want 200", code, body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !bytes.Contains(sshKRL(t, other), []byte("replica-lost-laptop")) {
		if time.Now().After(deadline) {
			t.Fatal("second replica still serves a KRL without a revocation recorded on the first after 10s")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// A KRL poll must inspect newly appended history but cannot replay a large,
// unchanged stream for every host poll. Use real embedded JetStream with the
// production scheduler-history floor and no unrelated background event writers.
func TestServedSSHUnchangedHistorySkipsReplayAndNewRevocationCatchesUp(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	log.EnforceLegacySchedulerWriteFloor()
	p := &sshProtocol{krl: sshca.NewKRL(), log: log, tenantID: servedTestTenant}
	if err := p.syncRevocations(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if p.verifiedSnapshot.Generation == "" {
		t.Fatal("SSH startup did not verify the active event generation")
	}
	p.syncMu.Lock()
	initial := p.replayCount
	p.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	p.syncMu.Unlock()
	if err := p.syncRevocations(t.Context(), false); err != nil {
		t.Fatalf("unchanged SSH KRL poll: %v", err)
	}
	p.syncMu.Lock()
	unchanged := p.replayCount
	p.syncMu.Unlock()
	if unchanged != initial {
		t.Fatalf("unchanged stream caused %d extra full replays", unchanged-initial)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: eventSSHCertRevoked, TenantID: servedTestTenant,
		Data: []byte(`{"serial":6789,"key_id":"snapshot-catchup"}`)}); err != nil {
		t.Fatalf("append remote-style revocation: %v", err)
	}
	p.syncMu.Lock()
	p.syncedFrom = time.Now().Add(-2 * sshKRLSyncInterval)
	p.syncMu.Unlock()
	if err := p.syncRevocations(t.Context(), false); err != nil {
		t.Fatalf("changed SSH KRL poll: %v", err)
	}
	p.syncMu.Lock()
	changed := p.replayCount
	p.syncMu.Unlock()
	if changed != initial+1 || !bytes.Contains(p.KRLBytes(), []byte("snapshot-catchup")) {
		t.Fatalf("changed stream did not replay and publish its exact revocation: replays=%d", changed-initial)
	}
}

func TestSSHReplayFailureDoesNotPublishPartialKRL(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	p := &sshProtocol{krl: sshca.NewKRL(), log: log, tenantID: servedTestTenant}
	if err := p.syncRevocations(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	beforeKRL := p.KRLBytes()
	beforeApplied := p.applied
	for _, data := range []string{`{"serial":7001,"key_id":"staged-only"}`, `{`} {
		if _, err := log.Append(t.Context(), events.Event{Type: eventSSHCertRevoked,
			TenantID: servedTestTenant, Data: []byte(data)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.syncRevocations(t.Context(), true); err == nil {
		t.Fatal("malformed later revocation did not fail closed")
	}
	if p.applied != beforeApplied || p.KRLVersion() != 0 || !bytes.Equal(p.KRLBytes(), beforeKRL) {
		t.Fatal("failed replay published a partial KRL or advanced its durable cursor")
	}
}

// RV-08g: raw revocation needs certs:write, like the product revoke route.
func TestServedRawSSHRevokeRequiresCertsWrite(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
	if code, _ := sshPost(t, h.ts, "/ssh/revoke", token, "rv08g-revoke", map[string]any{"serial": 7}); code != http.StatusForbidden {
		t.Fatalf("a certs:issue-only token revoked over raw /ssh/revoke: status %d, want 403", code)
	}
}

// F259: with no principal allowlist configured, direct user certificates are
// refused on every path, including for root; host certificates still issue.
func TestServedDirectSSHUserCertsNeedPrincipalAllowlist(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
	pub := sshTestPublicKey(t)
	raw := map[string]any{"public_key": pub, "key_id": "f259", "principals": []string{"root"}, "ttl_seconds": 600}
	product := map[string]any{"certificate_type": "user", "public_key": pub, "key_id": "f259", "principals": []string{"root"}, "ttl_seconds": 600}
	for _, c := range []struct {
		name, path, idem string
		body             any
	}{
		{"raw issue", "/ssh/issue/user", "f259-raw", raw},
		{"product preview", "/api/v1/ssh/certificates/preview", "", product},
		{"product issue", "/api/v1/ssh/certificates", "f259-product", product},
	} {
		code, body := sshPost(t, h.ts, c.path, token, c.idem, c.body)
		if code != http.StatusForbidden || !strings.Contains(body, "ssh_user_principals") {
			t.Errorf("%s minted or previewed a root user certificate with no principal allowlist: status %d body %s", c.name, code, body)
		}
	}
	host := map[string]any{"public_key": pub, "key_id": "f259-host", "principals": []string{"web-1.internal"}, "ttl_seconds": 600}
	if code, body := sshPost(t, h.ts, "/ssh/issue/host", token, "f259-host", host); code != http.StatusOK {
		t.Errorf("host certificate issuance = %d %s, want 200", code, body)
	}
}

// RV-08d: raw host certificates get the product option checks.
func TestServedRawSSHHostCertRejectsUserOptions(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
	pub := sshTestPublicKey(t)
	for name, body := range map[string]map[string]any{
		"extension":       {"public_key": pub, "key_id": "rv08d-ext", "principals": []string{"web-1"}, "extensions": map[string]string{"permit-pty": ""}},
		"critical option": {"public_key": pub, "key_id": "rv08d-opt", "principals": []string{"web-1"}, "critical_options": map[string]string{"force-command": "/bin/true"}},
	} {
		if code, out := sshPost(t, h.ts, "/ssh/issue/host", token, "rv08d-"+strings.ReplaceAll(name, " ", "-"), body); code != http.StatusUnprocessableEntity {
			t.Errorf("raw host certificate with a user %s = %d %s, want 422", name, code, out)
		}
	}
}

type denySSHPaths struct{}

func (denySSHPaths) EvaluateDeny(_ context.Context, in policy.ABACInput) (policy.ABACDecision, error) {
	if strings.HasPrefix(in.Resource["request.path"], "/ssh/") {
		return policy.ABACDecision{Deny: true, Reason: "raw SSH routes are closed"}, nil
	}
	return policy.ABACDecision{}, nil
}

type exhaustedLimiter struct{}

func (exhaustedLimiter) Allow(context.Context, string) (bool, time.Duration, error) {
	return false, time.Second, nil
}

// RV-08e, RV-08f: raw routes run under the API guard and record who issued what.
func TestServedRawSSHRoutesUseTheAPIGuard(t *testing.T) {
	host := func(pub, keyID string) map[string]any {
		return map[string]any{"public_key": pub, "key_id": keyID, "principals": []string{"web-1.internal"}, "ttl_seconds": 600}
	}
	t.Run("abac deny", func(t *testing.T) {
		h := newOperatingServedHarness(t, sshServedProtocols(), func(d *Deps) {
			d.APIOptions = append(d.APIOptions, api.WithABACDenyOverlay(denySSHPaths{}, nil, nil))
		})
		token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
		if code, body := sshPost(t, h.ts, "/ssh/issue/host", token, "rv08e-abac", host(sshTestPublicKey(t), "rv08e-abac")); code != http.StatusForbidden {
			t.Fatalf("ABAC deny rule did not apply to raw /ssh/issue/host: status %d %s", code, body)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		h := newOperatingServedHarness(t, sshServedProtocols(), func(d *Deps) { d.RateLimiter = exhaustedLimiter{} })
		token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
		if code, body := sshPost(t, h.ts, "/ssh/issue/host", token, "rv08e-limit", host(sshTestPublicKey(t), "rv08e-limit")); code != http.StatusTooManyRequests {
			t.Fatalf("tenant rate limit did not apply to raw /ssh/issue/host: status %d %s", code, body)
		}
	})
	t.Run("idempotency and actor", func(t *testing.T) {
		h := newOperatingServedHarness(t, sshServedProtocols())
		token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-issuer", []string{"certs:issue"})
		pub := sshTestPublicKey(t)
		if code, body := sshPost(t, h.ts, "/ssh/issue/host", token, "", host(pub, "rv08e-nokey")); code != http.StatusBadRequest {
			t.Fatalf("raw /ssh/issue/host without Idempotency-Key = %d %s, want 400", code, body)
		}
		first, firstBody := sshPost(t, h.ts, "/ssh/issue/host", token, "rv08e-once", host(pub, "rv08e-once"))
		again, againBody := sshPost(t, h.ts, "/ssh/issue/host", token, "rv08e-once", host(pub, "rv08e-once"))
		if first != http.StatusOK || again != http.StatusOK || firstBody != againBody {
			t.Fatalf("raw /ssh/issue/host retry with the same Idempotency-Key signed again: %d %s then %d %s", first, firstBody, again, againBody)
		}
		var found bool
		for _, e := range tenantEvents(t, h.log, "ssh.cert.issued") {
			var data struct {
				KeyID          string   `json:"key_id"`
				PrincipalNames []string `json:"principal_names"`
				ValidBefore    string   `json:"valid_before"`
			}
			if json.Unmarshal(e.Data, &data) != nil || data.KeyID != "rv08e-once" {
				continue
			}
			found = true
			if e.Actor == nil || e.Actor.Subject != "ssh-issuer" || len(data.PrincipalNames) != 1 || data.PrincipalNames[0] != "web-1.internal" || data.ValidBefore == "" {
				t.Fatalf("ssh.cert.issued does not say who issued which logins until when: actor %+v data %s", e.Actor, e.Data)
			}
		}
		if !found {
			t.Fatal("no ssh.cert.issued event for the raw issuance")
		}
	})
}
