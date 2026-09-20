// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The control plane must not race a relay for work the relay is meant to run
// (epic E1).
//
// The A3 role stamp reserves an appliance deploy for a network relay by writing
// required_agent_role='network' on the outbox row. Nothing enforced it: the
// outbox claim query has no predicate on that column — it is read by
// ClaimAgentJobs when an AGENT asks for work, never by the dispatcher — and the
// control-plane dispatcher sweeps every connector.* row on a one-second ticker.
// So the stamp was correct in the column and decided nothing; the control plane
// got there first, every time.
//
// The refusal is conditional on a relay actually being enrolled, and that
// condition is the whole design. Refusing unconditionally would turn "this
// estate has not deployed a relay yet" into "this estate's appliance deploys
// stopped working", and would retire the one path with end-to-end proof through
// the served API (the DoD connector suite drives a10, cisco, kemp and netscaler
// through the control plane to their device doubles, enrolling no relay). What
// E1 can honestly promise is narrower and worth keeping: if you run a relay, the
// control plane will not do its work behind its back.

type relayPresenceStore struct {
	present bool
	err     error
	asked   int
}

func (r *relayPresenceStore) TenantHasNetworkRelay(context.Context, string) (bool, error) {
	r.asked++
	return r.present, r.err
}

// deployMessage builds a direct connector.deploy payload for a family.
func deployMessage(t *testing.T, family string) orchestrator.Message {
	t.Helper()
	payload, err := json.Marshal(connector.DeployPayload{
		Connector: family, Target: "vip-1", Fingerprint: "abcd",
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"),
		KeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return orchestrator.Message{
		TenantID: "11111111-1111-1111-1111-111111111111", Destination: "connector.deploy",
		IdempotencyKey: "deploy-" + family, Payload: payload,
	}
}

func TestAMigratedFamilyIsRefusedWhenARelayIsEnrolled(t *testing.T) {
	t.Parallel()
	// kemp is relay-migrated: device proof, rollback, readback, support row and
	// a relay execution proof. If this stops being true the census test says so
	// first, which is why this reads it rather than hardcoding the answer.
	if !connector.RelayMigrated("kemp") {
		t.Skip("kemp is no longer relay-migrated; the census test covers that change")
	}
	relays := &relayPresenceStore{present: true}
	d := &issuanceDispatcher{relayPresence: relays}

	err := d.handleDeploy(context.Background(), deployMessage(t, "kemp"))
	if !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("deploy error = %v, want a retry-budget-neutral deferral so the row stays "+
			"claimable by the relay that is supposed to run it", err)
	}
	// DeliveryDeferredError.Error() is deliberately a fixed string so a
	// deferral cannot leak handler detail into an outbox row or a log line; the
	// cause travels on Unwrap. Assert there, which is where an operator's
	// tooling reads it from.
	if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), "network relay") {
		t.Errorf("deferral carries no reason on Unwrap: %v", cause)
	}
	if relays.asked == 0 {
		t.Error("the dispatcher refused without checking whether a relay is enrolled, which would " +
			"break every estate that has not deployed one")
	}
}

// No relay enrolled: the control plane still executes, unchanged. This is the
// half that keeps the change from being an outage.
func TestAMigratedFamilyStillDeploysWhenNoRelayIsEnrolled(t *testing.T) {
	t.Parallel()
	relays := &relayPresenceStore{present: false}
	d := &issuanceDispatcher{relayPresence: relays}

	err := d.handleDeploy(context.Background(), deployMessage(t, "kemp"))
	if orchestrator.IsDeliveryDeferred(err) {
		t.Fatal("an estate with no relay had its appliance deploy deferred; that turns 'you have " +
			"not deployed a relay yet' into 'your deploys stopped working'")
	}
	if relays.asked == 0 {
		t.Error("relay presence was never consulted")
	}
}

// An un-migrated family is never refused, whatever the relay situation. cisco
// has no rollback and no readback, so removing the control plane's fallback
// would take away recovery without providing the path that justifies it.
func TestAnUnmigratedFamilyIsNeverRefused(t *testing.T) {
	t.Parallel()
	if connector.RelayMigrated("cisco") {
		t.Skip("cisco became relay-migrated; update this test deliberately")
	}
	relays := &relayPresenceStore{present: true}
	d := &issuanceDispatcher{relayPresence: relays}

	err := d.handleDeploy(context.Background(), deployMessage(t, "cisco"))
	if orchestrator.IsDeliveryDeferred(err) {
		t.Fatal("cisco is not through its gates and was refused anyway; the control plane is its " +
			"only executor and refusing strands the deploy")
	}
}

// A legacy row has no role stamp, so the connector family is the last safe
// classification boundary. Host work still belongs to the host agent and must
// be returned to the queue before the native registry can touch this machine.
func TestAHostConnectorFamilyIsRefusedEvenWithoutARoleStamp(t *testing.T) {
	t.Parallel()
	d := &issuanceDispatcher{}
	if err := d.handleDeploy(context.Background(), deployMessage(t, "nginx")); !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("nginx deploy error = %v, want a retry-budget-neutral deferral to the host agent", err)
	}
}

// A modern row carries its role outside the sealed payload. The dispatcher can
// therefore refuse it before opening tenant ciphertext or even decoding JSON.
// Invalid JSON makes that ordering executable: if decoding starts, this test
// sees a decode error instead of the typed deferral.
func TestAHostStampedRowIsRefusedBeforePayloadDecode(t *testing.T) {
	t.Parallel()
	d := &issuanceDispatcher{}
	err := d.Deliver(context.Background(), orchestrator.Message{
		TenantID: "11111111-1111-1111-1111-111111111111", Destination: "connector.deploy",
		IdempotencyKey: "deploy-host-stamped", Payload: []byte("not-json"), RequiredAgentRole: "host",
	})
	if !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("host-stamped deploy error = %v, want deferral before payload decode", err)
	}
}

// Unknown role values are corrupted routing metadata, not permission for the
// control plane to guess. Defer before payload decode so repair/reconciliation
// can make one explicit executor choice without risking a local mutation.
func TestAnUnknownRoleStampFailsClosedBeforePayloadDecode(t *testing.T) {
	t.Parallel()
	d := &issuanceDispatcher{}
	err := d.Deliver(context.Background(), orchestrator.Message{
		TenantID: "11111111-1111-1111-1111-111111111111", Destination: "connector.deploy",
		IdempotencyKey: "deploy-unknown-role", Payload: []byte("not-json"), RequiredAgentRole: "future-role",
	})
	if !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("unknown-role deploy error = %v, want fail-closed deferral", err)
	}
}

// A failed relay-presence lookup must DEFER, not fall through to the control
// plane. Falling through is the direction that silently removes the guarantee —
// the same mistake B2's review caught, where swallowing a target-load error was
// called "the safe direction" while it was the one that generated a key.
func TestAFailedRelayLookupDefersRatherThanExecuting(t *testing.T) {
	t.Parallel()
	if !connector.RelayMigrated("kemp") {
		t.Skip("kemp is no longer relay-migrated")
	}
	relays := &relayPresenceStore{err: errors.New("database unreachable")}
	d := &issuanceDispatcher{relayPresence: relays}

	err := d.handleDeploy(context.Background(), deployMessage(t, "kemp"))
	if !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("error = %v; a failed relay lookup must defer. Falling through to the control "+
			"plane would mean a database blip silently hands relay work back to the executor "+
			"E1 exists to take it away from", err)
	}
}
