// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

// revocationRelayWaitFor reads GET /api/v1/revocation/relay-waits and returns
// the wait for one certificate serial, if listed.
func revocationRelayWaitFor(t *testing.T, h *servedHarness, token, serial string) (api.RevocationRelayWait, bool) {
	t.Helper()
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/revocation/relay-waits", token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET relay-waits = %d %s", status, raw)
	}
	var waits api.RevocationRelayWaits
	if err := json.Unmarshal(raw, &waits); err != nil {
		t.Fatalf("decode relay-waits: %v (%s)", err, raw)
	}
	want := strings.ToLower(strings.ReplaceAll(serial, ":", ""))
	for _, item := range waits.Items {
		if item.Serial == want {
			return item, true
		}
	}
	return api.RevocationRelayWait{}, false
}

// A162-L5: a revocation through an AD CS issuer whose relay has never
// connected waits for that relay without spending its retries, and the wait
// used to be invisible: the certificate stayed active and the delivery showed
// only as deferred. The Revocation center's read now names the relay, says it
// has never been seen, and carries the serial, the CA and the attempt, to a
// reader with certs:read; a caller without it is refused.
func TestServedADCSRevocationWaitingOnAnAbsentRelaySaysWhyA162L5(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the certutil stand-in drives the CA stand-in with curl")
	}
	const absentRelay = "dc-relay-a162l5"
	certsrvStandIn, certsrv := newADCSCertsrvStandIn(t)
	admin := &adcsCAAdminStandIn{certsrv: certsrvStandIn, issued: map[string]bool{}, revoked: map[string]int{}}
	adminSrv := httptest.NewServer(http.HandlerFunc(admin.serve))
	t.Cleanup(adminSrv.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSRevoke}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, absentRelay)
	})
	ctx := t.Context()
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "AD CS revocation wait", "")
	if err != nil {
		t.Fatal(err)
	}
	selected := recordADCSIssuedLeaf(t, i, certsrvStandIn, owner.ID, "web02.corp.example", "a162l5-selected")
	admin.issued[strings.ToLower(selected.Serial)] = true
	operator := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/certificates/bulk-revoke", operator, "a162l5-adcs-revoke",
		map[string]any{"certificate_ids": []string{selected.ID}, "reason": "keyCompromise"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":1`)) {
		t.Fatalf("bulk revoke of an AD CS certificate = %d %s; want it queued for the issuer", status, raw)
	}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := dispatcher.Deliver(ctx, message); !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("delivery with the relay absent = %v; want a budget-neutral wait", err)
	}

	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	wait, listed := revocationRelayWaitFor(t, h.servedHarness, reader, selected.Serial)
	if !listed {
		t.Fatal("the revocation waiting on an absent relay is not listed; an operator sees only an active certificate")
	}
	wantAgent := sshtrustrollout.EnrolledAgentID(h.tenant, absentRelay)
	if wait.Relay != absentRelay || wait.RelayAgentID != wantAgent || wait.RelayPresence != "never_seen" ||
		wait.State != "waiting_for_relay" || wait.Attempt != 1 || wait.CAConfig != adcsRevocationCA ||
		wait.IssuerID != "corp-adcs-web" || wait.QueuedAt == "" || wait.LastError != "" {
		t.Fatalf("relay wait = %+v; want relay %s (%s) never_seen, waiting_for_relay, attempt 1 at %s through corp-adcs-web",
			wait, absentRelay, wantAgent, adcsRevocationCA)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, selected.ID); err != nil || current.Status != "active" {
		t.Fatalf("certificate while its relay is absent = %+v %v; want still active", current.Status, err)
	}
	// Another delivery while the relay is still absent queues no second attempt
	// and the list still shows the one wait.
	if err := dispatcher.Deliver(ctx, message); !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("second delivery with the relay absent = %v; want a budget-neutral wait", err)
	}
	if again, listed := revocationRelayWaitFor(t, h.servedHarness, reader, selected.Serial); !listed || again.Attempt != 1 || again.RevocationID != wait.RevocationID {
		t.Fatalf("relay wait after a second delivery = %+v listed %v; want the same attempt-1 wait", again, listed)
	}
	outsider := seedScopedToken(t, h.store, h.tenant, "identities:read")
	if status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/relay-waits", outsider, nil); status != http.StatusForbidden {
		t.Fatalf("relay-waits without certs:read = %d %s; want 403", status, raw)
	}
}
