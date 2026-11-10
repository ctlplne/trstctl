// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// outageCA stands in for an ACME CA validating DNS-01 against the endpoint's
// zone. While DNS is down an order cannot be validated: the ACME adapter calls
// that a failure before finalization (nothing was submitted for signing), and
// a CA that answers ambiguously leaves the control plane unsure whether it
// minted one.
type outageCA struct {
	name      string
	down      atomic.Bool
	ambiguous atomic.Bool
}

func (c *outageCA) Name() string { return c.name }

func (c *outageCA) Issue(_ context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	if c.down.Load() {
		cause := errors.New("dns-01 validation failed: no TXT answer from the zone's name servers (SERVFAIL)")
		if c.ambiguous.Load() {
			return ca.Certificate{}, cause
		}
		return ca.Certificate{}, fmt.Errorf("%w: %w", ca.ErrIssuanceNotSubmitted, cause)
	}
	return testExternalCACertificate(req, c.name)
}

// TestServedHostRenewalHealsAfterAnOutageA36 is the owner's lab finding
// (2026-11-10) on the assembled control plane and the shipping agent runtime:
// a DNS-01 outage during a host renewal must heal with nothing deleted on the
// agent host and nothing restarted. An outage the CA reports as not submitted
// heals on its own: the same job resumes with its retained key once DNS is
// back. One the CA leaves unconfirmed blocks that job's signing for good; one
// Retry renewal ends the job and the next one completes. And a job an operator
// cancelled before its key was signed no longer refuses every later job for
// the target as another job's key: the next job names it, and the agent wipes
// that key.
func TestServedHostRenewalHealsAfterAnOutageA36(t *testing.T) {
	const authority = "dns01-acme"
	upstream := &outageCA{name: authority}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: authority, Type: "acme-dns01-test", CA: upstream}}
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a36-heal", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	certPath, keyPath, rollbackDir := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key"), filepath.Join(root, "rollback")
	const dnsName = "heal-a36.test"
	oldCert, oldKey := issueHostPair(t, h, dnsName)
	if err := fixture.WriteFile("listener.crt", oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("listener.key", oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(oldCert)
	secret.Wipe(oldKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.SetReloadCheckInterval(time.Millisecond)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})} // #nosec G112 -- loopback fixture is closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("listener: %v", serveErr)
		}
	})
	served := func() string {
		t.Helper()
		res, err := tlsprobe.Probe(ctx, listener.Addr().String(), tlsprobe.WithServerName(dnsName), tlsprobe.WithTimeout(5*time.Second))
		if err != nil || len(res.PeerCertificates) == 0 {
			t.Fatalf("probe the endpoint: %v", err)
		}
		info, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.PeerCertificates[0]}))
		if err != nil {
			t.Fatal(err)
		}
		return info.SHA256Fingerprint
	}

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
		"verify_address": listener.Addr().String(), "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/a36-heal", Type: "nginx", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "A36 heal owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(map[string]any{"name": "heal-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "heal-api", spec); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
		"profile_name": "heal-api", "issuing_authority_source": "external", "issuing_authority_id": authority})
	if err != nil {
		t.Fatal(err)
	}
	const identityID = "36360000-0000-4000-8000-000000000036"
	if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, identityID, store.Identity{Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Attributes: attrs}); err != nil {
		t.Fatal(err)
	}
	// One agent ledger for the whole test: the host is never restarted and
	// nothing in this directory is deleted by hand.
	state, err := agentrelay.NewHostRollbackStore(rollbackDir, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root},
		Actions: []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: 5 * time.Second}}}
	startServedExternalCADispatcher(t, h.servedHarness)
	token := seedScopedToken(t, h.store, h.tenant, "identities:read", "identities:write", "certs:issue", "connectors:read", "connectors:write")

	pass := func(label string) *servedHostRelayChannel {
		t.Helper()
		passCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
		if _, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(passCtx, channel, http.DefaultClient, profile, nil, nil, state, 1, 60); err != nil {
			t.Fatalf("%s: agent pass: %v", label, err)
		}
		return channel
	}
	status := func() string {
		t.Helper()
		ident, err := h.store.GetIdentity(ctx, h.tenant, identityID)
		if err != nil {
			t.Fatal(err)
		}
		return ident.Status
	}
	dueNow := func() {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET agent_next_attempt_at = now() - interval '1 second'
			   WHERE tenant_id = $1 AND destination = 'endpoint.renew' AND status = 'pending'`, h.tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	startRenewal := func(label string) {
		t.Helper()
		code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token,
			"a36-heal-"+label, map[string]any{"to": "renewing", "reason": label})
		if code != http.StatusOK {
			t.Fatalf("%s: renew = %d %s", label, code, body)
		}
		if _, err := h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{"ca.renew"}}); err != nil {
			t.Fatalf("%s: dispatch the renewal: %v", label, err)
		}
	}
	pendingSlots := func() int {
		t.Helper()
		entries, err := os.ReadDir(rollbackDir)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".renew") {
				n++
			}
		}
		return n
	}
	healed := func(label, before string) string {
		t.Helper()
		channel := pass(label)
		if channel.lastOutcome != transport.JobOutcomeVerified || !channel.lastAccepted {
			t.Fatalf("%s: outcome %q accepted %v detail %q signErr %v", label, channel.lastOutcome, channel.lastAccepted, channel.lastDetail, channel.lastSignErr)
		}
		if got := status(); got != "deployed" {
			t.Fatalf("%s: identity is %s, want deployed", label, got)
		}
		now := served()
		if now == before || !strings.EqualFold(now, channel.lastCredentialFingerprint) {
			t.Fatalf("%s: the endpoint serves %s (was %s), want the renewed %s", label, now, before, channel.lastCredentialFingerprint)
		}
		if n := pendingSlots(); n != 0 {
			t.Fatalf("%s: %d pending host keys remain after the renewal completed", label, n)
		}
		return now
	}

	// The first certificate.
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue"); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !ok {
		t.Fatalf("dispatch the first issuance: %v %v", ok, err)
	}
	fingerprint := healed("first issuance", served())

	// 1. DNS down mid-renewal, reported as not submitted: the job fails and
	// keeps its key; once DNS is back its next attempt completes.
	upstream.down.Store(true)
	startRenewal("outage-not-submitted")
	if channel := pass("not-submitted outage"); channel.lastOutcome != transport.JobOutcomeFailed {
		t.Fatalf("the outage did not fail the renewal: %q %q", channel.lastOutcome, channel.lastDetail)
	}
	if got := status(); got != "renewal_failed" || pendingSlots() != 1 {
		t.Fatalf("after the outage: identity %s, %d pending keys", got, pendingSlots())
	}
	upstream.down.Store(false)
	dueNow()
	fingerprint = healed("DNS back, same job", fingerprint)

	// 2. A CA that leaves the outage unconfirmed: the job's signing can never
	// finish, even with DNS back. One Retry renewal ends it and the next job
	// completes.
	upstream.down.Store(true)
	upstream.ambiguous.Store(true)
	startRenewal("outage-unconfirmed")
	if channel := pass("unconfirmed outage"); channel.lastOutcome != transport.JobOutcomeFailed {
		t.Fatalf("the outage did not fail the renewal: %q %q", channel.lastOutcome, channel.lastDetail)
	}
	upstream.down.Store(false)
	upstream.ambiguous.Store(false)
	dueNow()
	if channel := pass("DNS back, stuck job"); channel.lastOutcome != transport.JobOutcomeFailed || served() != fingerprint {
		t.Fatalf("the unconfirmed job completed on its own: %q %q", channel.lastOutcome, channel.lastDetail)
	}
	startRenewal("retry-after-unconfirmed")
	var superseded int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND status = 'cancelled' AND last_error = $2`,
			h.tenant, store.OutboxLastErrorSupersededByRetry).Scan(&superseded)
	}); err != nil {
		t.Fatal(err)
	}
	if superseded < 1 {
		t.Fatal("the retry did not end the stuck job")
	}
	fingerprint = healed("one retry", fingerprint)

	// 3. The A36 lead: an operator cancels a job that failed before signing,
	// then renews again. The cancelled job's key no longer refuses the next.
	upstream.down.Store(true)
	startRenewal("outage-then-cancel")
	if channel := pass("outage before cancel"); channel.lastOutcome != transport.JobOutcomeFailed {
		t.Fatalf("the outage did not fail the renewal: %q %q", channel.lastOutcome, channel.lastDetail)
	}
	upstream.down.Store(false)
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/cancel", token,
		"a36-heal-cancel", map[string]any{"reason": "restart the renewal"}); code != http.StatusOK {
		t.Fatalf("cancel = %d %s", code, body)
	}
	if pendingSlots() != 1 {
		t.Fatalf("the cancelled job's unsigned key is gone before any job named it: %d", pendingSlots())
	}
	startRenewal("renew-after-cancel")
	healed("renewal after the cancel", fingerprint)
}
