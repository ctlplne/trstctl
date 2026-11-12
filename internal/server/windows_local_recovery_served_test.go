// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/store"
)

// TestServedWindowsLocalUncertainOutcomeIsSettledA268O1 is A268-O1: a
// Windows local-account generation whose outcome the host reported uncertain
// gets one re-delivery of the same generation. The host settles it by sign-in
// alone and reports with the agent's own outcomes: verified when the prepared
// password signs in and the predecessor is refused (the rotation then
// completes and the vault publishes it), failed with not_applied when the
// predecessor still signs in (the rotation then fails, the vault and account
// keep the current password, and the next generation starts from the same
// predecessor). The re-delivery happens once: another uncertain answer queues
// nothing more, and the queue never re-sends a settled delivery. The proved
// case is a first delivery the agent reports verified, as a current agent
// reports every proof.
func TestServedWindowsLocalUncertainOutcomeIsSettledA268O1(t *testing.T) {
	for _, outcome := range []string{"proved", "applied", "not_applied", "uncertain_again"} {
		t.Run(outcome, func(t *testing.T) { servedWindowsLocalRecovery(t, outcome) })
	}
}

func servedWindowsLocalRecovery(t *testing.T, outcome string) {
	ctx := t.Context()
	// The package's served tests share one tenant: each case has its own
	// provider, account, secret and request keys.
	suffix := map[string]string{"applied": "a", "not_applied": "b", "uncertain_again": "c", "proved": "d"}[outcome]
	providerID, role := "host-sam-"+suffix, "hosts/admin-"+suffix
	sid := map[string]string{"a": "S-1-5-21-1-2-3-1101", "b": "S-1-5-21-1-2-3-1102", "c": "S-1-5-21-1-2-3-1103", "d": "S-1-5-21-1-2-3-1104"}[suffix]
	hostID := agentRowID(servedTestTenant, "role-agent")
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: providerID, Type: "windows", WindowsHostAgentID: hostID,
		AllowedRoles: []string{role}, RoleBindings: map[string]string{role: sid}, AllowStaticRotation: true}
	p := newConfiguredDynamicProvider(cfg, map[string]bool{role: true}, time.Hour, integrationCredentialResolver{}, nil)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{hostaccounts.InventoryDestination, hostaccounts.RotationDestination}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.DynamicSecretProviders = []dynsecret.Provider{p}
	})
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	token := seedScopedTokenSubject(t, h.store, h.tenant, "host-account-custodian", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/windows-hosts/"+hostID+"/local-administrators/runs", token, "a268o1-native-read-"+suffix, nil); status != http.StatusAccepted {
		t.Fatal("inventory queue", status)
	}
	claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(claims.Jobs) != 1 {
		t.Fatal("inventory claim", e)
	}
	read, e := hostaccounts.DecodeInventoryIntent(claims.Jobs[0].Payload)
	if e != nil {
		t.Fatal(e)
	}
	native := winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3},
		Account: winaccounts.Account{Name: "Owned Admin " + suffix, SID: sid, Enabled: true, PasswordRequired: true}}
	report := func(job transport.ClaimedJob, outcome string, value any) {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if accepted, e := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, outcome, string(raw), crypto.SHA256Hex(raw))); e != nil || !accepted.Accepted {
			t.Fatalf("report %s: %v", outcome, e)
		}
	}
	report(claims.Jobs[0], transport.JobOutcomeExecuted, hostaccounts.InventoryReport{RunID: read.RunID, BindingDigest: read.BindingDigest, ObservedAt: time.Now().UTC(), Status: "complete",
		Inventory: &winaccounts.Inventory{Machine: native.Machine, Accounts: []winaccounts.Account{native.Account}}})
	old := `{"host":"OWNED-HOST","username":"Owned Admin ` + suffix + `","password":"owned-fixture-password"}`
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", token, "a268o1-seed-"+suffix, map[string]any{"name": role, "value": old}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatal("seed", status)
	}
	rotate := func(key string) string {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", token, key+"-"+suffix, map[string]any{"provider": providerID, "key": role, "old_ref": "none", "acknowledge_single_phase": true})
		var command struct {
			ID string `json:"command_id"`
		}
		if status != http.StatusAccepted && status != http.StatusOK || json.Unmarshal(body, &command) != nil || command.ID == "" {
			t.Fatalf("rotation queue = %d %s", status, body)
		}
		return command.ID
	}
	drain := func() {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if e := h.srv.Drain(c); e != nil {
			t.Fatal(e)
		}
	}
	claimRotation := func() (transport.ClaimedJob, bool) {
		t.Helper()
		jobs, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.RotationDestination}, Limit: 1, LeaseSeconds: 120})
		if e != nil {
			t.Fatal(e)
		}
		if len(jobs.Jobs) == 0 {
			return transport.ClaimedJob{}, false
		}
		return jobs.Jobs[0], true
	}
	redeem := func(job transport.ClaimedJob) (oldValue, nextValue []byte) {
		t.Helper()
		creds, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
		if e != nil || len(creds.Items) != 2 {
			t.Fatalf("redeem the generation: %v", e)
		}
		return creds.Items[0].Value, creds.Items[1].Value
	}

	commandID := rotate("rotate-local-account")
	drain()
	first, ok := claimRotation()
	if !ok {
		t.Fatal("no rotation job")
	}
	intent, e := hostaccounts.DecodeRotationIntent(first.Payload)
	if e != nil || intent.RotationID != commandID {
		t.Fatalf("rotation intent = %+v, %v", intent, e)
	}
	firstOld, firstNext := redeem(first)
	defer secret.Wipe(firstOld)
	defer secret.Wipe(firstNext)
	vault := func() (string, int) {
		t.Helper()
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/"+role, token, nil)
		var current struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &current) != nil {
			t.Fatalf("read the vault = %d", status)
		}
		return current.Value, current.Version
	}
	// deliveries reads this generation's host deliveries: the original and,
	// once its outcome was uncertain, the one recovery.
	deliveries := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		rows, err := h.store.SystemPool().Query(ctx, `SELECT idempotency_key,status,COALESCE(last_error,'') FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key LIKE '%' || $3`, h.tenant, hostaccounts.RotationDestination, commandID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var k, st, le string
			if err := rows.Scan(&k, &st, &le); err != nil {
				t.Fatal(err)
			}
			kind := "original"
			if strings.Contains(k, ":recover:") {
				kind = "recovery"
			}
			out[kind] = st + "/" + le
		}
		return out
	}
	if outcome == "proved" {
		at := time.Now().UTC()
		proof := winaccounts.RotationProof{Binding: native, GenerationID: commandID, ObservedAt: at, NewAuthenticated: true, OldRefused: true}
		report(first, transport.JobOutcomeVerified, hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: at, Status: "succeeded", Proof: &proof})
		drain()
		done, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
		if e != nil || done.Phase != store.SecretStaticRotationCompleted || done.ResultVersion != 2 {
			t.Fatalf("a verified proof did not complete the rotation: %s %q, %v", done.Phase, done.Error, e)
		}
		if value, version := vault(); version != 2 || !strings.Contains(value, string(firstNext)) {
			t.Fatal("the vault did not publish the proved generation")
		}
		if got := deliveries(); len(got) != 1 || !strings.HasPrefix(got["original"], "delivered/") {
			t.Fatalf("deliveries after a proof = %v", got)
		}
		return
	}
	// The host lost the outcome of its native commit: an uncertain report, sent
	// as the agent sends every report that is not a proof.
	report(first, transport.JobOutcomeFailed, hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(),
		Status: "uncertain", Failure: "execution_uncertain"})

	// One re-delivery of the same generation follows, bound to its own
	// delivery, with the same two passwords.
	recovery, ok := claimRotation()
	if !ok {
		t.Fatal("an uncertain outcome got no recovery delivery")
	}
	var key string
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT idempotency_key FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, recovery.JobID).Scan(&key); err != nil || !strings.Contains(key, ":recover:") {
		t.Fatalf("the recovery delivery's key = %q, %v", key, err)
	}
	recovered, e := hostaccounts.DecodeRotationIntent(recovery.Payload)
	if e != nil || recovered != intent {
		t.Fatalf("the recovery delivery carries another generation: %+v", recovered)
	}
	recoveryOld, recoveryNext := redeem(recovery)
	defer secret.Wipe(recoveryOld)
	defer secret.Wipe(recoveryNext)
	if !bytes.Equal(recoveryOld, firstOld) || !bytes.Equal(recoveryNext, firstNext) {
		t.Fatal("the recovery delivery redeemed other passwords")
	}
	// The queue never re-sends the original: the recovery replaces it.
	if got := deliveries()["original"]; got != "failed/local_rotation_uncertain" {
		t.Fatalf("the original delivery after an uncertain outcome = %q", got)
	}

	switch outcome {
	case "applied":
		at := time.Now().UTC()
		proof := winaccounts.RotationProof{Binding: native, GenerationID: commandID, ObservedAt: at, NewAuthenticated: true, OldRefused: true}
		report(recovery, transport.JobOutcomeVerified, hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: at, Status: "succeeded", Proof: &proof})
		drain()
		done, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
		if e != nil || done.Phase != store.SecretStaticRotationCompleted || done.ResultVersion != 2 {
			t.Fatalf("a recovered applied generation did not complete: %+v, %v", done.Phase, e)
		}
		value, version := vault()
		if version != 2 || !strings.Contains(value, string(recoveryNext)) {
			t.Fatal("the vault did not publish the recovered generation")
		}
		if got := deliveries()["recovery"]; !strings.HasPrefix(got, "delivered/") {
			t.Fatalf("the recovery delivery after a proof = %q", got)
		}
	case "not_applied":
		report(recovery, transport.JobOutcomeFailed, hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(),
			Status: "not_applied", Failure: "predecessor_signs_in"})
		drain()
		done, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
		if e != nil || done.Phase != store.SecretStaticRotationFailed || done.ResultVersion != 0 || !strings.Contains(done.Error, "never applied") {
			t.Fatalf("a generation never applied did not end cleanly: %s %q, %v", done.Phase, done.Error, e)
		}
		if value, version := vault(); version != 1 || value != old {
			t.Fatalf("the vault changed after a generation that was never applied: version %d", version)
		}
		if _, more := claimRotation(); more {
			t.Fatal("a settled generation was delivered again")
		}
		if got := deliveries()["recovery"]; got != "failed/local_rotation_not_applied" {
			t.Fatalf("the recovery delivery after a never-applied answer = %q", got)
		}
		// The next generation starts from the same predecessor (none here).
		next := rotate("rotate-local-account-again")
		drain()
		job, ok := claimRotation()
		if !ok {
			again, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, next)
			t.Fatalf("the account could not rotate again: %s %q, %v", again.Phase, again.Error, e)
		}
		nextIntent, e := hostaccounts.DecodeRotationIntent(job.Payload)
		if e != nil || nextIntent.RotationID != next || nextIntent.PredecessorGenerationID != "" {
			t.Fatalf("the next generation = %+v, %v", nextIntent, e)
		}
	case "uncertain_again":
		report(recovery, transport.JobOutcomeFailed, hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(),
			Status: "uncertain", Failure: "execution_uncertain"})
		drain()
		if _, more := claimRotation(); more {
			t.Fatal("a second uncertain answer queued another delivery")
		}
		if got := deliveries()["recovery"]; got != "failed/local_rotation_uncertain" {
			t.Fatalf("the recovery delivery after a second uncertain answer = %q", got)
		}
		var rows int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key LIKE '%' || $3`, h.tenant, hostaccounts.RotationDestination, commandID).Scan(&rows)
		}); err != nil || rows != 2 {
			t.Fatalf("rotation deliveries = %d, want the original and one recovery: %v", rows, err)
		}
		still, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
		if e != nil || still.Phase != store.SecretStaticRotationPrepared || still.ResultVersion != 0 {
			t.Fatalf("an unsettled generation changed state: %s, %v", still.Phase, e)
		}
	}
}
