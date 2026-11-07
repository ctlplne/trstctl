// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This proves the served PG/NATS/mTLS queue and custody boundary. The signed
// native report is a fixture; actual Windows authentication remains separate.
func TestServedPreparedWindowsLocalRotationA268(t *testing.T) {
	ctx := t.Context()
	hostID := agentRowID(servedTestTenant, "role-agent")
	var custody seal.KeyWrapper
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "host-sam", Type: "windows", WindowsHostAgentID: hostID, AllowedRoles: []string{"hosts/admin"}, RoleBindings: map[string]string{"hosts/admin": "S-1-5-21-1-2-3-1001"}, AllowStaticRotation: true}
	p := newConfiguredDynamicProvider(cfg, map[string]bool{"hosts/admin": true}, time.Hour, integrationCredentialResolver{}, nil)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{hostaccounts.InventoryDestination, hostaccounts.RotationDestination}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.DynamicSecretProviders = []dynsecret.Provider{p}
		custody = d.KEK
	})
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	token := seedScopedTokenSubject(t, h.store, h.tenant, "host-account-custodian", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	root := "/api/v1/access/discovery/windows-hosts/" + hostID + "/local-administrators/runs"
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "native-read", nil); status != http.StatusAccepted {
		t.Fatal("inventory queue", status)
	}
	claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(claims.Jobs) != 1 {
		t.Fatal("inventory claim", e)
	}
	job := claims.Jobs[0]
	read, e := hostaccounts.DecodeInventoryIntent(job.Payload)
	if e != nil {
		t.Fatal(e)
	}
	native := winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "Owned Admin", SID: cfg.RoleBindings["hosts/admin"], Enabled: true, PasswordRequired: true}}
	inv := hostaccounts.InventoryReport{RunID: read.RunID, BindingDigest: read.BindingDigest, ObservedAt: time.Now().UTC(), Status: "complete", Inventory: &winaccounts.Inventory{Machine: native.Machine, Accounts: []winaccounts.Account{native.Account}}}
	raw, e := json.Marshal(inv)
	if e != nil {
		t.Fatal(e)
	}
	receipt := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	if accepted, e := h.client.ReportJobResult(ctx, receipt); e != nil || !accepted.Accepted {
		t.Fatal("inventory report", e)
	}
	old := []byte(`{"host":"OWNED-HOST","username":"Owned Admin","password":"owned-fixture-password"}`)
	defer secret.Wipe(old)
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", token, "seed-local-account", map[string]any{"name": "hosts/admin", "value": string(old)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatal("seed", status)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", token, "rotate-local-account", map[string]any{"provider": "host-sam", "key": "hosts/admin", "old_ref": "none", "acknowledge_single_phase": true})
	var command struct {
		ID string `json:"command_id"`
	}
	if status != http.StatusAccepted && status != http.StatusOK || json.Unmarshal(body, &command) != nil || command.ID == "" {
		t.Fatal("rotation queue", status)
	}
	drain := func() {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if e := h.srv.Drain(c); e != nil {
			t.Fatal(e)
		}
	}
	drain()
	pending, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, command.ID)
	if e != nil || pending.Phase != store.SecretStaticRotationPrepared || len(pending.SealedPreparation) == 0 {
		t.Fatal("offline rotation must retain one preparation", pending.Phase, e)
	}
	prep := append([]byte(nil), pending.SealedPreparation...)
	for range 3 {
		// Reschedule only the owned operational row; do not change the host clock.
		if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending'`, h.tenant, pending.OutboxID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		drain()
		var spent int
		if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT attempts FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, pending.OutboxID).Scan(&spent)
		}); e != nil || spent != 0 {
			t.Fatal("offline native wait spent the failure budget", spent, e)
		}
	}
	drain()
	pending, e = h.store.GetSecretStaticRotationCommand(ctx, h.tenant, command.ID)
	if e != nil || !bytes.Equal(prep, pending.SealedPreparation) || pending.Phase != store.SecretStaticRotationPrepared {
		t.Fatal("offline retry changed generation", e)
	}
	// Explicit SQL fault injection: a cache edit must never grant native
	// authority, and a lost prepared projection must recover the original job.
	sourceState, e := h.store.GetWindowsLocalRotation(ctx, h.tenant, command.ID)
	if e != nil {
		t.Fatal(e)
	}
	changed := sourceState.Intent
	changed.Native.Account.Name = "Another Admin"
	changed, e = hostaccounts.NewRotationIntent(changed)
	if e != nil {
		t.Fatal(e)
	}
	altered, e := json.Marshal(changed)
	if e != nil {
		t.Fatal(e)
	}
	updateIntent := func(raw []byte) {
		t.Helper()
		if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE windows_local_account_rotations SET intent=$3::jsonb WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID, raw)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	updateIntent(altered)
	oldDenied, newDenied, e := h.srv.api.OpenWindowsLocalRotationCredentials(ctx, h.tenant, changed, *sourceState.OutboxID, 1)
	secret.Wipe(oldDenied)
	secret.Wipe(newDenied)
	if e == nil {
		t.Fatal("forged cached SAM identity redeemed a sealed generation")
	}
	original, e := json.Marshal(sourceState.Intent)
	if e != nil {
		t.Fatal(e)
	}
	updateIntent(original)
	if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM windows_local_account_rotations WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	oldDenied, newDenied, e = h.srv.api.OpenWindowsLocalRotationCredentials(ctx, h.tenant, sourceState.Intent, *sourceState.OutboxID, 1)
	secret.Wipe(oldDenied)
	secret.Wipe(newDenied)
	if e == nil {
		t.Fatal("missing prepared projection granted native credentials")
	}
	preparedEvent, found, e := h.log.EventByID(ctx, sourceState.PreparedEventID)
	if e != nil || !found {
		t.Fatal("prepared source lost", e)
	}
	if e = projections.New(h.store).Apply(ctx, preparedEvent); e != nil {
		t.Fatal(e)
	}
	restored, e := h.store.GetWindowsLocalRotation(ctx, h.tenant, command.ID)
	if e != nil || restored.Intent != sourceState.Intent || restored.OutboxID == nil || sourceState.OutboxID == nil || *restored.OutboxID != *sourceState.OutboxID {
		t.Fatal("prepared replay minted another host generation or delivery", e)
	}
	claims, e = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.RotationDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(claims.Jobs) != 1 {
		t.Fatal("exact native rotation claim", e)
	}
	job = claims.Jobs[0]
	intent, e := hostaccounts.DecodeRotationIntent(job.Payload)
	if e != nil || intent.RotationID != command.ID || intent.Native != native {
		t.Fatal("native binding", e)
	}
	staged, e := h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, store.WindowsHostAccountProviderID(hostID), "staged", false)
	if e != nil || len(staged) != 1 || staged[0].ID != intent.AccountID {
		t.Fatal("rotation did not preserve the discovered account identity", e)
	}

	creds, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
	if e != nil || len(creds.Items) != 2 {
		t.Fatal("exact generation broker", e)
	}
	defer func() {
		for _, item := range creds.Items {
			secret.Wipe(item.Value)
		}
	}()
	if creds.Items[0].Name != hostaccounts.RotationOldCredentialName || creds.Items[1].Name != hostaccounts.RotationNewCredentialName || bytes.Equal(creds.Items[0].Value, creds.Items[1].Value) || len(creds.Items[1].Value) < 24 {
		t.Fatal("broker did not supply two distinct exact passwords")
	}
	if duplicate, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); e == nil || duplicate != nil {
		t.Fatal("generation redeemed twice")
	}
	at := time.Now().UTC()
	proof := winaccounts.RotationProof{Binding: native, GenerationID: command.ID, ObservedAt: at, NewAuthenticated: true, OldRefused: true}
	report := hostaccounts.RotationReport{RotationID: command.ID, BindingDigest: intent.BindingDigest, ObservedAt: at, Status: "succeeded", Proof: &proof}
	raw, e = json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	receipt = h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	if accepted, e := h.client.ReportJobResult(ctx, receipt); e != nil || !accepted.Accepted {
		t.Fatal("signed native result", e)
	}
	// Explicit cache corruption at the staged boundary must be detected
	// BEFORE the vault write, even when the ciphertext itself is valid.
	beforePublish, e := h.store.GetWindowsLocalRotation(ctx, h.tenant, command.ID)
	if e != nil {
		t.Fatal(e)
	}
	stagedValue, e := hostaccounts.MarshalLocalCredential(hostaccounts.LocalCredential{Host: native.Machine.Name, Username: native.Account.Name, Password: creds.Items[1].Value})
	if e != nil {
		t.Fatal(e)
	}
	stagedSeal, e := seal.Seal(custody, stagedValue, []byte(h.tenant+"/static-rotation/"+command.ID+"/new"))
	secret.Wipe(stagedValue)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE secret_static_rotation_commands SET phase='staged',new_ref=id::text,provider_type='windows',sealed_new=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID, stagedSeal); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE windows_local_account_rotations SET observed_event_id='missing-native-source' WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, command.ID, 1); e == nil {
		t.Fatal("staged native publication accepted a missing signed proof source")
	}
	unchanged, e := h.store.GetSecret(ctx, h.tenant, "hosts/admin")
	if e != nil || unchanged.Version != 1 {
		t.Fatal("vault changed before native proof validation", unchanged.Version, e)
	}
	if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE secret_static_rotation_commands SET phase='prepared',new_ref='',provider_type='',sealed_new=NULL WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE windows_local_account_rotations SET observed_event_id=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, command.ID, beforePublish.ObservedEventID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	drain()
	done, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, command.ID)
	if e != nil || done.Phase != store.SecretStaticRotationCompleted || done.ResultVersion != 2 {
		t.Fatal("native proof did not finish existing static engine", done.Phase, e)
	}
	projector := projections.New(h.store)
	if e = projector.ProjectCatchUp(ctx, h.log); e != nil {
		t.Fatal(e)
	}
	if _, e = projector.Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	if e = projector.Rebuild(ctx, h.log); e != nil {
		t.Fatal(e)
	}
	if _, _, e = projections.CanonicalWindowsLocalRotation(ctx, h.store, h.log, h.tenant, command.ID); e != nil {
		t.Fatal("snapshot/rebuild lost signed native generation", e)
	}
	// A later generation names the acknowledged HOST generation, independently
	// of outbox numbers. An unknown native result never publishes the old value.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", token, "rotate-local-account-next", map[string]any{"provider": "host-sam", "key": "hosts/admin", "old_ref": command.ID, "acknowledge_single_phase": true})
	var nextCommand struct {
		ID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &nextCommand) != nil || nextCommand.ID == "" {
		t.Fatal("next native generation queue", status)
	}
	drain()
	nextState, e := h.store.GetWindowsLocalRotation(ctx, h.tenant, nextCommand.ID)
	if e != nil || nextState.Intent.PredecessorGenerationID != command.ID {
		t.Fatal("native generation lost its host predecessor", e)
	}
	nextClaims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.RotationDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(nextClaims.Jobs) != 1 {
		t.Fatal("next native claim", e)
	}
	nextJob := nextClaims.Jobs[0]
	nextCreds, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: nextJob.JobID, Attempt: nextJob.Attempt})
	if e != nil || len(nextCreds.Items) != 2 {
		t.Fatal("next native broker", e)
	}
	if !bytes.Equal(nextCreds.Items[0].Value, creds.Items[1].Value) || bytes.Equal(nextCreds.Items[0].Value, nextCreds.Items[1].Value) {
		t.Fatal("host generation did not reuse its exact predecessor and mint a distinct successor")
	}
	for _, item := range nextCreds.Items {
		secret.Wipe(item.Value)
	}
	unknown := hostaccounts.RotationReport{RotationID: nextCommand.ID, BindingDigest: nextState.Intent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "uncertain", Failure: "execution_uncertain"}
	raw, e = json.Marshal(unknown)
	if e != nil {
		t.Fatal(e)
	}
	uncertainReceipt := h.report(t, nextJob.JobID, nextJob.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	if accepted, e := h.client.ReportJobResult(ctx, uncertainReceipt); e != nil || !accepted.Accepted {
		t.Fatal("signed unknown native effect was not retained", e)
	}
	if e = h.srv.api.FailStaticSecretRotation(ctx, h.tenant, nextCommand.ID); !orchestrator.IsDeliveryDeferred(e) {
		t.Fatal("unknown native effect fell through generic rollback", e)
	}
	still, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, nextCommand.ID)
	if e != nil || still.Phase != store.SecretStaticRotationPrepared || still.ResultVersion != 0 || still.RestoredVersion != 0 {
		t.Fatal("unknown native result changed vault state", e)
	}
	uncertainState, _, e := projections.CanonicalWindowsLocalRotation(ctx, h.store, h.log, h.tenant, nextCommand.ID)
	if e != nil || uncertainState.Observation == nil || uncertainState.Observation.Report.Status != "uncertain" {
		t.Fatal("unknown native source lost", e)
	}
	// Recreate only this owned operational delivery, then receive a refusal.
	// This call did no new effect; it cannot erase the earlier unknown effect.
	if e = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2 AND destination=$3`, h.tenant, nextJob.JobID, hostaccounts.RotationDestination)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	nextPrepared, found, e := h.log.EventByID(ctx, nextState.PreparedEventID)
	if e != nil || !found {
		t.Fatal(e)
	}
	if e = projector.Apply(ctx, nextPrepared); e != nil {
		t.Fatal(e)
	}
	recreated, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.RotationDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(recreated.Jobs) != 1 || recreated.Jobs[0].JobID == nextJob.JobID {
		t.Fatal("owned delivery recreation failed", e)
	}
	refused := hostaccounts.RotationReport{RotationID: nextCommand.ID, BindingDigest: nextState.Intent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "refused", Failure: "local_grant_absent"}
	raw, e = json.Marshal(refused)
	if e != nil {
		t.Fatal(e)
	}
	retryJob := recreated.Jobs[0]
	refusedReceipt := h.report(t, retryJob.JobID, retryJob.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	if accepted, e := h.client.ReportJobResult(ctx, refusedReceipt); e != nil || !accepted.Accepted {
		t.Fatal("later refusal not retained", e)
	}
	retained, _, e := projections.CanonicalWindowsLocalRotation(ctx, h.store, h.log, h.tenant, nextCommand.ID)
	if e != nil || retained.Observation == nil || retained.Observation.Report.Status != "uncertain" || retained.ObservedEventID != uncertainState.ObservedEventID {
		t.Fatal("later refusal erased unknown native effect", e)
	}

}
