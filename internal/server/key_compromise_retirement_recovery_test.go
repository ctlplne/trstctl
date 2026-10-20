// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Run 1 lead defect:certificates-compound-completion: a retained compound
// key-compromise command returned 200 once, then its lookup after the identity
// was retired returned 404. The command must stay queryable until both the CA
// and host effects carry durable receipts, whatever the identity's later state.
func TestCompoundKeyCompromiseStaysQueryableAfterIdentityRetirement(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "retired compound owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "retired-compound.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "fixture issue"); err != nil {
		t.Fatal(err)
	}
	cert := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "retired-test-ca", "retired-test-leaf", "")
	agentID := uuid.NewString()
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "retired-compound-host", Type: "apache", Config: config,
		Enabled: false, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache", Target: target.Name,
		Fingerprint: cert.Fingerprint, Status: "verified", IdempotencyKey: "retired-fixture-deploy",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateDeployed, "fixture served leaf"); err != nil {
		t.Fatal(err)
	}
	_, version, err := h.store.IdentityApprovalTarget(ctx, h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "retired-compound-exact"
	receipt, err := h.orch.TransitionKeyCompromise(ctx, h.tenant, identity.ID, key, &version,
		orchestrator.EndpointContainmentRequest{
			TargetID: target.ID, TargetRevision: target.RevisionID, IdentityID: identity.ID,
			ExpectedFingerprint: cert.Fingerprint, RequiredAgentID: agentID,
			Connector: target.Type, Target: target.Name, Reason: "keyCompromise",
			RequestedBy: "incident-commander", IdempotencyKey: key,
		})
	if err != nil {
		t.Fatal(err)
	}
	before, host, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || before.Destination != "revocation.publish" || host.ID != receipt.ID {
		t.Fatalf("live status before retirement = %+v, %+v, %v", before, host, err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRetired, "decommissioned after compromise"); err != nil {
		t.Fatalf("retire revoked identity: %v", err)
	}
	after, hostAfter, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil {
		t.Fatalf("compound command lookup after retirement must succeed: %v", err)
	}
	if after.ID != before.ID || after.Destination != "revocation.publish" {
		t.Fatalf("CA effect changed identity after retirement: before=%+v after=%+v", before, after)
	}
	if hostAfter.ID != receipt.ID || hostAfter.Fingerprint != cert.Fingerprint {
		t.Fatalf("host receipt changed identity after retirement: before=%+v after=%+v", host, hostAfter)
	}
	if _, err := h.store.GetIdentity(ctx, h.tenant, identity.ID); err != nil {
		t.Fatalf("retired identity must stay readable: %v", err)
	}
}

// Run 1 lead defect:certificates-compound-completion, second half: the retained
// host receipt reported failed containment and nothing could recover it. An
// operator must be able to re-queue the exact reviewed host command, and a
// dead-lettered CA publication, on the same retained command without a new
// review, exactly once per retry, with the status read following the retry.
func TestCompoundKeyCompromiseEffectsRecoverAfterFailure(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "recovered compound owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "recovered-compound.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "fixture issue"); err != nil {
		t.Fatal(err)
	}
	cert := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "recovered-test-ca", "recovered-test-leaf", "")
	agentID := uuid.NewString()
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "recovered-compound-host", Type: "apache", Config: config,
		Enabled: false, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache", Target: target.Name,
		Fingerprint: cert.Fingerprint, Status: "verified", IdempotencyKey: "recovered-fixture-deploy",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateDeployed, "fixture served leaf"); err != nil {
		t.Fatal(err)
	}
	_, version, err := h.store.IdentityApprovalTarget(ctx, h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "recovered-compound-exact"
	queued, err := h.orch.TransitionKeyCompromise(ctx, h.tenant, identity.ID, key, &version,
		orchestrator.EndpointContainmentRequest{
			TargetID: target.ID, TargetRevision: target.RevisionID, IdentityID: identity.ID,
			ExpectedFingerprint: cert.Fingerprint, RequiredAgentID: agentID,
			Connector: target.Type, Target: target.Name, Reason: "keyCompromise",
			RequestedBy: "incident-commander", IdempotencyKey: key,
		})
	if err != nil || queued.OutboxID == nil || queued.Status != "containment_queued" {
		t.Fatalf("queued receipt = %+v, %v", queued, err)
	}
	// A queued host effect is not retryable: the exact agent still owns it.
	if _, _, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectHost, "incident-commander"); err == nil {
		t.Fatal("retrying a queued host containment must be refused")
	}
	failHostContainment := func(attempt int) {
		t.Helper()
		current, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, queued.ID)
		if err != nil {
			t.Fatal(err)
		}
		if tag, err := h.store.SystemPool().Exec(ctx,
			`UPDATE outbox SET status='failed', attempts=attempts+1, last_error='containment_failed', claim_completed_at=now()
			  WHERE tenant_id=$1 AND id=$2 AND destination='endpoint.contain'`, h.tenant, *current.OutboxID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("dead-letter host job rows=%d err=%v", tag.RowsAffected(), err)
		}
		failed := current
		failed.Status, failed.Attempts = "containment_failed", attempt
		failed.Reason = "host containment profile is unusable"
		failed.Detail = `{"reason":"host containment profile is unusable"}`
		if _, err := h.orch.RecordEndpointContainmentFailure(ctx, h.tenant,
			uuid.NewSHA1(uuid.NameSpaceOID, []byte("recovered-compound-failure:"+key+":"+uuid.NewString())).String(), failed); err != nil {
			t.Fatal(err)
		}
	}
	failHostContainment(1)
	_, host, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || host.Status != "containment_failed" {
		t.Fatalf("failed host status = %+v, %v", host, err)
	}
	countContainmentJobs := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='endpoint.contain'`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	_, retried, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectHost, "incident-commander")
	if err != nil {
		t.Fatalf("retry failed host containment: %v", err)
	}
	if retried.ID != queued.ID || retried.Status != "containment_queued" || retried.OutboxID == nil ||
		*retried.OutboxID == *queued.OutboxID || retried.Fingerprint != cert.Fingerprint {
		t.Fatalf("retried receipt = %+v (original outbox %d)", retried, *queued.OutboxID)
	}
	if n := countContainmentJobs(); n != 2 {
		t.Fatalf("containment jobs after retry = %d, want 2", n)
	}
	again, againHost, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectHost, "incident-commander")
	if err != nil {
		t.Fatalf("replay of the retry: %v", err)
	}
	if againHost.OutboxID == nil || *againHost.OutboxID != *retried.OutboxID || againHost.Status != "containment_queued" {
		t.Fatalf("replayed retry changed the receipt: %+v vs %+v", againHost, retried)
	}
	if n := countContainmentJobs(); n != 2 {
		t.Fatalf("containment jobs after replay = %d, want 2 (a queued retry is not retried again)", n)
	}
	ca, statusHost, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || statusHost.Status != "containment_queued" || *statusHost.OutboxID != *retried.OutboxID || ca.ID != again.ID {
		t.Fatalf("status after retry = %+v, %+v, %v", ca, statusHost, err)
	}
	// A second failure of the retried job recovers again, as a third exact job.
	failHostContainment(2)
	_, second, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectHost, "incident-commander")
	if err != nil || second.Status != "containment_queued" || *second.OutboxID == *retried.OutboxID {
		t.Fatalf("second retry = %+v, %v", second, err)
	}
	if n := countContainmentJobs(); n != 3 {
		t.Fatalf("containment jobs after second retry = %d, want 3", n)
	}

	// Dead-letter the CA publication and recover it on the same command.
	if _, _, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectCA, "incident-commander"); err == nil {
		t.Fatal("retrying a pending CA publication must be refused")
	}
	caRow := pendingOutboxByDestination(t, h, "revocation.publish")
	if tag, err := h.store.SystemPool().Exec(ctx,
		`UPDATE outbox SET status='failed', attempts=10, last_error='upstream CA unreachable' WHERE tenant_id=$1 AND id=$2`,
		h.tenant, caRow.ID); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("dead-letter CA job rows=%d err=%v", tag.RowsAffected(), err)
	}
	ca, _, err = h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || ca.Status != "failed" {
		t.Fatalf("dead-lettered CA status = %+v, %v", ca, err)
	}
	ca, _, err = h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectCA, "incident-commander")
	if err != nil || ca.ID != caRow.ID || ca.Status != "pending" || ca.Attempts != 10 {
		t.Fatalf("CA retry = %+v, %v", ca, err)
	}
	ca, _, err = h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectCA, "incident-commander")
	if err != nil || ca.ID != caRow.ID || ca.Status != "pending" {
		t.Fatalf("CA retry replay = %+v, %v", ca, err)
	}

	// Every retry survives a full rebuild from the event log and a retirement.
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	ca, statusHost, err = h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key)
	if err != nil || statusHost.Status != "containment_queued" || *statusHost.OutboxID != *second.OutboxID || ca.ID != caRow.ID {
		t.Fatalf("status after rebuild = %+v, %+v, %v", ca, statusHost, err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRetired, "decommissioned after compromise"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.orch.KeyCompromiseStatus(ctx, h.tenant, identity.ID, key); err != nil {
		t.Fatalf("status after retirement: %v", err)
	}
	failHostContainment(3)
	if _, third, err := h.orch.RetryKeyCompromiseEffect(ctx, h.tenant, identity.ID, key,
		orchestrator.KeyCompromiseEffectHost, "incident-commander"); err != nil || third.Status != "containment_queued" {
		t.Fatalf("retry after retirement = %+v, %v", third, err)
	}
}
