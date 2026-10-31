// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type collectorProtectionFixture struct {
	mu      sync.Mutex
	ref     eventprotect.KeyRef
	request eventprotect.DestructionRequest
}

func (f *collectorProtectionFixture) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef, visit func(context.Context) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return visit(ctx)
}
func (f *collectorProtectionFixture) WithTenantEventProtection(ctx context.Context, _ string, visit func(context.Context) error) error {
	return visit(ctx)
}
func (f *collectorProtectionFixture) EventProtectionFor(_ context.Context, event events.Event) (events.EventProtectionDecision, error) {
	if event.TenantID == f.ref.TenantID && event.Type == projections.EventOwnerCreated {
		return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: f.ref}, nil
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
}
func (f *collectorProtectionFixture) AuthorizeDestruction(_ context.Context, request eventprotect.DestructionRequest) error {
	if request != f.request {
		return eventprotect.ErrContext
	}
	return nil
}

// Actual API, PG/NATS, outbox receiver and independent file-key removal. Only
// owner.created is protected by this explicit admission/authority fixture; this
// does not qualify production activation, offboarding/quiescence or isolated
// signer processes. Removing a key with a pending batch here is fault injection.
func TestServedAuditCollectorKeepsSourceAndUsesCurrentProtectedDetails(t *testing.T) {
	collector := newAuditFeedCollectorAUD52(t)
	t.Setenv("TRSTCTL_A233_COLLECTOR_TOKEN", "collector-fixture-token")
	base := t.TempDir()
	signer, err := jose.GenerateRSASigningKey("collector-custody-fixture")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &collectorProtectionFixture{ref: eventprotect.KeyRef{TenantID: servedTestTenant, ID: "4c59ca2e-3133-4bfc-94eb-9144726d9c36"}}
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "custody"), BackupRoots: []string{filepath.Join(base, "artifacts")}, Locker: fixture, EvidenceKey: signer, DestructionAuthority: fixture})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	if err := keys.Provision(t.Context(), fixture.ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(t.Context(), fixture.ref)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies(), events.WithEventProtection(events.EventProtection{Admission: fixture, Keys: keys})}, func(d *Deps) { d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_A233_COLLECTOR_TOKEN"} })
	registerServedTenant(t, h, "Collector fixture")
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "collector-reader", []string{string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress)})
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "collector-private-owner", map[string]any{"kind": "team", "name": "Collector fixture", "email": "collector-private-person@example.invalid"})
	if status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("create protected owner: status=%d body=%s", status, body)
	}
	cidr := serviceNowSinkCIDR(t, collector.URL("/"))
	for _, feed := range []struct{ id, provider, path string }{{auditFeedSplunkID, auditsink.ProviderSplunkHEC, "/protected/live"}, {auditFeedSentinelID, auditsink.ProviderSentinel, "/protected/erased"}} {
		putAuditFeedAUD52(t, h, token, feed.id, map[string]any{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798).
			"name": "Protected collector fixture " + feed.id, "provider": feed.provider, "endpoint_url": collector.URL(feed.path), "token_ref": "env:TRSTCTL_A233_COLLECTOR_TOKEN", "interval_seconds": 300, "batch_size": 100, "enabled": true, "allow_private_endpoint": true, "private_egress_cidrs": []string{cidr},
		})
	}
	if queued, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil || queued != 2 {
		t.Fatalf("queue protected collectors: n=%d err=%v", queued, err)
	}
	type queuedCommand struct {
		payload          []byte
		destination, key string
	}
	var commands []queuedCommand
	rows, err := h.store.SystemPool().Query(t.Context(), `SELECT payload,destination,idempotency_key FROM outbox WHERE tenant_id=$1 AND destination IN ($2,$3) ORDER BY destination`, h.tenant, orchestrator.DestinationAuditFeedSplunk, orchestrator.DestinationAuditFeedSentinel)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var command queuedCommand
		if err := rows.Scan(&command.payload, &command.destination, &command.key); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 {
		t.Fatal("missing exact collector commands")
	}
	for _, command := range commands {
		if bytes.Contains(command.payload, []byte("collector-private-person@example.invalid")) || bytes.Contains(command.payload, []byte("readable_events")) {
			t.Fatal("durable collector command copied protected plaintext")
		}
	}
	// A queued record changed without its hash, or changed with a freshly forged
	// hash, must not produce even one external call. Source identity is separate
	// from an internally consistent attacker-chosen chain.
	for _, command := range commands {
		for _, rehash := range []bool{false, true} {
			var batch auditsink.FeedBatch
			if err := json.Unmarshal(command.payload, &batch); err != nil {
				t.Fatal(err)
			}
			for i := range batch.Records {
				if batch.Records[i].Type == projections.EventOwnerCreated {
					batch.Records[i].Type = "altered.collector.source"
				}
			}
			if rehash {
				batch.ChainHead = audit.SealFrom(batch.PrevHash, batch.Records)
			}
			payload, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.srv.obHandler.Deliver(t.Context(), orchestrator.Message{TenantID: h.tenant, Destination: command.destination, IdempotencyKey: command.key, Payload: payload}); err == nil {
				t.Fatal("altered queued source was delivered")
			}
		}
	}
	if collector.Count() != 0 {
		t.Fatal("invalid source reached collector")
	}
	if n, err := h.srv.outbox.DispatchScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{orchestrator.DestinationAuditFeedSplunk}}); err != nil || n != 1 {
		t.Fatalf("dispatch active details: n=%d err=%v", n, err)
	}
	live := collector.Last("/protected/live")
	if !bytes.Contains(live.Body, []byte("collector-private-person@example.invalid")) || !bytes.Contains(live.Body, []byte(`"signed_record"`)) || !bytes.Contains(live.Body, []byte(`"hash_scope":"signed_record"`)) {
		t.Fatal("live collector lost readable details or its separate source commitment")
	}
	offboarded := time.Now().UTC()
	fixture.request = eventprotect.DestructionRequest{Ref: fixture.ref, OperationID: "4db3600c-c191-45a6-bf96-1a99c4f5941b", RegistrationIdentity: "collector-fixture-registration", ActivationEventID: "collector-fixture-activation", ActivationSequence: 1, CreationDigest: creation.Digest(), OffboardEventID: "collector-fixture-offboard", OffboardSequence: 4, OffboardedAt: offboarded, NotBefore: offboarded.Add(2 * time.Millisecond)}
	time.Sleep(time.Until(fixture.request.NotBefore))
	if _, err := keys.Destroy(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.outbox.DispatchScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{orchestrator.DestinationAuditFeedSentinel}}); err != nil || n != 1 {
		t.Fatalf("dispatch erased details: n=%d err=%v", n, err)
	}
	erased := collector.Last("/protected/erased")
	if bytes.Contains(erased.Body, []byte("collector-private-person@example.invalid")) || !bytes.Contains(erased.Body, []byte(`"SensitiveErased":true`)) || !bytes.Contains(erased.Body, []byte(`"HashScope":"SignedRecord"`)) {
		t.Fatal("collector did not use current verified erasure or lost the source proof")
	}
}

func TestAuditFeedSourceFailuresHaveDistinctClosedStatus(t *testing.T) {
	for _, detail := range []string{"server: collector source reader is unavailable", "server: collector source unavailable", "server: collector commitment changed"} {
		if got := auditFeedFailureCode(errors.New(detail)); got != "collector_source_unavailable" {
			t.Fatalf("source failure classified as %q", got)
		}
	}
}
