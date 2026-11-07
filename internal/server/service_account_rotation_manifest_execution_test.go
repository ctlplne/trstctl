// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestServedSealedManifestDrivesOneRotationAndInverseA267(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "forward"
		if fail {
			name = "inverse"
		}
		t.Run(name, func(t *testing.T) {
			servedDependentRotationScenario(t, nil, fail, dependentRotationOptions{ManifestExecution: true})
		})
	}
}
func TestServedSealedManifestReconciliationAndInverseRecoveryA267(t *testing.T) {
	t.Run("reconcile", func(t *testing.T) {
		servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true, Reconcile: true})
	})
	t.Run("inverse recovery", func(t *testing.T) {
		servedDependentRotationScenario(t, nil, true, dependentRotationOptions{ManifestExecution: true, RecoverInverse: true})
	})
}
func TestServedSealedManifestPreservesLostApprovalAndVaultFencesA267(t *testing.T) {
	t.Run("claimed erasure", func(t *testing.T) {
		servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true, Reconcile: true, LoseQueueProjection: true, EraseClaim: true})
	})
	t.Run("vault changed before reset", func(t *testing.T) {
		servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true}, true)
	})
	t.Run("vault changed after reset", func(t *testing.T) {
		servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true}, false, true)
	})
}
func servedDependentExecutionManifest(t *testing.T, h *roleHarness, token, root string, binding servicedependents.HostBinding, inventory servicedependents.InventoryReport, reconcile bool) servicedependents.RotationIntent {
	t.Helper()
	input := map[string]any{"secret_name": "app/dependent"}
	if reconcile {
		input["mode"] = "reconcile"
	}
	code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/reviews", token, "owned-execution-manifest", input)
	var state store.ServiceDependentManifest
	if code != http.StatusCreated || json.Unmarshal(raw, &state) != nil {
		t.Fatalf("open execution review: %d %s", code, raw)
	}
	scan, err := h.store.GetServiceDependentScan(t.Context(), h.tenant, inventory.RunID)
	if err != nil {
		t.Fatal(err)
	}
	host := servicedependents.RotationManifestHost{Binding: binding, InventoryRunID: inventory.RunID, InventoryDigest: scan.ReportDigest, ObservedAt: inventory.ObservedAt}
	entries := []servicedependents.RotationManifestEntry{}
	add := func(family, name string) {
		entries = append(entries, servicedependents.RotationManifestEntry{Host: host, Ref: servicedependents.DependentRef{AgentID: binding.AgentID, Family: family, Name: name}, ProbeID: "owned-functional-work"})
	}
	for _, v := range inventory.Services {
		add("services", v.Name)
	}
	for _, v := range inventory.Tasks {
		add("tasks", v.Path)
	}
	for _, v := range inventory.Pools {
		add("iis", v.Name)
	}
	path := "/api/v1/access/discovery/dependent-reviews/" + state.Header.ID
	previous := state.HeaderDigest
	// Keep empty host declarations in the chain before, between and after effects.
	for n := 0; n < 2*len(entries)+1; n++ {
		selected := []servicedependents.RotationManifestEntry(nil)
		if n%2 == 1 {
			selected = []servicedependents.RotationManifestEntry{entries[n/2]}
		}
		code, raw = secretsReqKey(t, h.servedHarness, http.MethodPut, fmt.Sprintf("%s/pages/%d", path, n), token, fmt.Sprintf("owned-execution-page-%d", n), map[string]any{"header_digest": state.HeaderDigest, "previous_digest": previous, "hosts": []servicedependents.RotationManifestHost{host}, "entries": selected})
		var page servicedependents.RotationManifestPage
		if code != http.StatusCreated || json.Unmarshal(raw, &page) != nil {
			t.Fatalf("execution page: %d %s", code, raw)
		}
		previous = page.Digest
	}
	code, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, path+"/seal", token, "owned-execution-seal", map[string]string{"header_digest": state.HeaderDigest, "tail_digest": previous})
	if code != http.StatusCreated || json.Unmarshal(raw, &state) != nil || state.Seal == nil {
		t.Fatalf("execution seal: %d %s", code, raw)
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, path, token, nil)
	var value struct {
		Intent servicedependents.RotationIntent `json:"intent"`
		Digest string                           `json:"intent_digest"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &value) != nil || value.Digest == "" || value.Intent.Plan.Manifest == nil {
		t.Fatalf("server did not return exact sealed queue authority: %d %s", code, raw)
	}
	digest, err := value.Intent.Digest()
	if err != nil || digest != value.Digest || value.Intent.Plan.ID != state.Header.ID || value.Intent.Plan.Manifest.Digest != state.Seal.Digest {
		t.Fatal("sealed account intent changed authority", err)
	}
	return value.Intent
}

func TestServedSealedManifestCursorFencesSQLRewindAndLostProjectionA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true, ManifestCursorFaults: true})
}
func proveDependentCursorProjectionGap(t *testing.T, h *roleHarness, step servicedependents.RotationStep, directory *dependentDirectoryBoundary) {
	t.Helper()
	ctx := t.Context()
	parent, err := h.store.GetServiceDependentRotation(ctx, h.tenant, step.RotationID)
	if err != nil || parent.ManifestCursor == nil {
		t.Fatal("missing source-backed cursor", err)
	}
	original := *parent.ManifestCursor
	// Read-time cursor guards consume an immutable transition attestation. The
	// writer/projection must still resolve full page links and native evidence.
	resolver, pending, err := projections.ResolveServiceDependentManifestCursor(ctx, h.log, parent)
	if err != nil || pending != nil {
		t.Fatal("unexpected cursor source before projection adversity", err)
	}
	to, err := resolver.Advance(original)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := h.store.GetServiceDependentStep(ctx, h.tenant, parent.ID, step.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"locator", "skip", "report"} {
		value := servicedependents.ManifestCursorAdvance{RotationID: parent.ID, IntentDigest: parent.IntentDigest, PreviousSourceID: parent.ManifestCursorSourceID, From: original, To: to, Cause: servicedependents.ManifestNativeSucceeded, StepID: step.ID, ReportDigest: projections.ServiceDependentReportDigest(saved.Report), At: time.Now().UTC()}
		switch field {
		case "locator":
			value.To.Position.PageNumber += 2
		case "skip":
			value.Cause = servicedependents.ManifestNotApplicable
			value.StepID = ""
			value.ReportDigest = ""
		case "report":
			value.ReportDigest = strings.Repeat("0", 64)
		}
		id := servicedependents.ManifestCursorAdvanceSourceID(h.tenant, parent.ID, parent.ManifestCursorSourceID)
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return h.store.ApplyServiceDependentCursorAdvanceTx(ctx, tx, h.tenant, id, parent.ManifestCursorSequence+1, value)
		}); err == nil {
			t.Fatal("projection accepted an unproven native cursor transition", field)
		}
	}

	set := func(cursor *servicedependents.ManifestCursor, id string, sequence uint64) {
		t.Helper()
		raw, err := json.Marshal(cursor)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE service_account_rotations SET manifest_cursor=$3::jsonb,manifest_cursor_source_id=$4,manifest_cursor_sequence=$5 WHERE tenant_id=$1 AND id=$2`, h.tenant, parent.ID, raw, id, sequence)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []string{"position", "source", "sequence"} {
		altered := original
		id := parent.ManifestCursorSourceID
		sequence := parent.ManifestCursorSequence
		switch change {
		case "position":
			altered.Position.EntryOrdinal = 1
			altered.Position.PageNumber = 3
		case "source":
			id = uuid.NewString()
		case "sequence":
			sequence++
		}
		set(&altered, id, sequence)
		err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, parent.CommandID, 1)
		set(&original, parent.ManifestCursorSourceID, parent.ManifestCursorSequence)
		if err == nil || directory.applied != 0 {
			t.Fatalf("rewritten %s selected native work", change)
		}
	}
	expectedID := servicedependents.ManifestCursorAdvanceSourceID(h.tenant, parent.ID, parent.ManifestCursorSourceID)
	locked := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			var id string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM service_account_rotations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, h.tenant, parent.ID).Scan(&id); err != nil {
				return err
			}
			close(locked)
			<-release
			return errors.New("owned cursor barrier release")
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-locked:
	case err := <-lockDone:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("owned cursor row lock unavailable")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- h.srv.api.AdvanceStaticSecretRotation(workerCtx, h.tenant, parent.CommandID, 1) }()
	deadline := time.Now().Add(10 * time.Second)
	var appended bool
	for time.Now().Before(deadline) {
		_, found, err := h.log.EventByID(ctx, expectedID)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			appended = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !appended {
		t.Fatal("cursor advance never appended before projection")
	}
	cancel()
	select {
	case err := <-workerDone:
		if err == nil {
			t.Fatal("cancelled projection reported completion")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cursor projection did not honor cancellation")
	}
	close(release)
	released = true
	<-lockDone
	unchanged, err := h.store.GetServiceDependentRotation(ctx, h.tenant, parent.ID)
	if err != nil || unchanged.ManifestCursorSourceID != parent.ManifestCursorSourceID || directory.applied != 0 {
		t.Fatal("lost cursor projection changed native authority", err)
	}
	raw, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	agent := &agentService{store: h.store, log: h.log}
	if _, err := agent.boundServiceDependentStep(ctx, h.tenant, step.Ref.AgentID, "service-dependent-step:"+parent.ID+":"+step.ID, raw); err == nil {
		t.Fatal("pending canonical successor revived an old host grant")
	}
	for retry := 0; retry < 2; retry++ {
		_ = h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, parent.CommandID, 1)
		recovered, err := h.store.GetServiceDependentRotation(ctx, h.tenant, parent.ID)
		if err != nil || recovered.ManifestCursorSourceID != expectedID || recovered.ManifestCursorSequence <= parent.ManifestCursorSequence || recovered.ManifestCursor == nil || recovered.ManifestCursor.Position.EntryOrdinal != 1 || directory.applied != 0 {
			t.Fatal("exact cursor source did not recover without native replay", err)
		}
		if retry == 0 {
			nextEntry, err := resolver.Entry(to)
			if err != nil {
				t.Fatal(err)
			}
			nextID := servicedependents.RotationStepID(parent.ID, parent.IntentDigest, to.Direction, to.Position.Stage, nextEntry.Ref)
			nextSource, found, err := h.log.EventByID(ctx, servicedependents.StepSourceID(parent.ID, nextID))
			if err != nil || !found || nextSource.Type != projections.EventServiceDependentStepQueued {
				t.Fatal("one worker call restored cursor metadata but did not queue the next exact native effect", err)
			}
			set(&original, parent.ManifestCursorSourceID, parent.ManifestCursorSequence)
		}
	}
	event, found, err := h.log.EventByID(ctx, expectedID)
	var value projections.ServiceDependentCursorAdvanced
	if err != nil || !found || json.Unmarshal(event.Data, &value) != nil || value.Cause != servicedependents.ManifestNativeSucceeded || value.StepID != step.ID {
		t.Fatal("cursor source lost its first exact native observation", err)
	}
}

func TestServedSealedManifestFencesSQLScopeAfterFinalPreflightA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestExecution: true, Reconcile: true, ManifestResetScopeFault: true})
}
func proveDependentFinalPreflightScopeFence(t *testing.T, h *roleHarness, token, root, commandID string, directory *dependentDirectoryBoundary) {
	t.Helper()
	// Ordinary selection is locked while this rotation is active. An extra SQL
	// projection row must also fail closed at the complete-scope barrier.
	const name = "dependent-selected-after-final-preflight"
	identity := enrollAgentWithRoles(t, h.servedHarness, name, h.serverName, []string{mtls.AgentRoleHost})
	creds, err := identity.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := transport.NewAgentClient(conn)
	if _, err := client.Heartbeat(t.Context(), &transport.HeartbeatRequest{AgentID: name, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	id := agentRowID(h.tenant, name)
	code, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+id, token, "owned-final-preflight-new-host", map[string]any{"enabled": true})
	if code != http.StatusConflict {
		t.Fatalf("active rotation allowed host membership change: %d %s", code, raw)
	}
	parentCommand, err := h.store.GetSecretStaticRotationCommand(t.Context(), h.tenant, commandID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := h.store.GetServiceDependentRotation(t.Context(), h.tenant, parentCommand.DependentChangeID)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberate read-model corruption, without a canonical selection source.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyServiceDependentHostSavedTx(t.Context(), tx, h.tenant, parent.Intent.Plan.Account, id, true, "owned-sql-fault", time.Now().UTC(), 1)
	}); err != nil {
		t.Fatal(err)
	}
	advanceErr := h.srv.api.AdvanceStaticSecretRotation(t.Context(), h.tenant, commandID, 1)
	cmd, err := h.store.GetSecretStaticRotationCommand(t.Context(), h.tenant, commandID)
	if err != nil {
		t.Fatal(err)
	}
	directory.mu.Lock()
	applied, restored := directory.applied, directory.restored
	directory.mu.Unlock()
	if cmd.Phase != store.SecretStaticRotationFailed || cmd.ResultVersion != 0 || applied != 0 || restored != 0 {
		t.Fatalf("final preflight bypassed complete selected scope: phase=%s version=%d reset=%d inverse=%d err=%v", cmd.Phase, cmd.ResultVersion, applied, restored, advanceErr)
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/app/dependent", token, nil)
	var current struct {
		Version int `json:"version"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &current) != nil || current.Version != 1 {
		t.Fatal("scope rejection published a vault generation")
	}
}
