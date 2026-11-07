// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

// This provider is a directory-boundary fault fixture, not a native AD proof.
// Samba and Windows fixtures separately qualify their actual native adapters.
type dependentDirectoryBoundary struct {
	native    dynsecret.Provider
	reconcile bool
	*dependentDirectoryState
}
type dependentDirectoryState struct {
	refusePublicationProof bool
	publicationProofs      int
	lastNative             *secret.Buffer
	mu                     sync.Mutex
	current                *secret.Buffer
	applied                int
	restored               int
	afterApply             func()
}

const dependentFixtureDN = "CN=service,DC=lab,DC=test"
const dependentFixtureSID = "S-1-5-21-1-2-3-1001"

func (f *dependentDirectoryBoundary) StaticReconciliation(role string) (dynsecret.Provider, dynsecret.ADReconcilePrincipal, error) {
	var pins dynsecret.ADReconcilePrincipal
	if f.reconcile || !f.AllowsStaticRotation(role) {
		return nil, pins, errors.New("fixture reconcile role unavailable")
	}
	selected := *f
	selected.reconcile = true
	if f.native != nil {
		p, identity, err := f.native.(dynsecret.StaticReconciliationProvider).StaticReconciliation(role)
		if err != nil {
			return nil, pins, err
		}
		selected.native = p
		return &selected, identity, nil
	}
	pins = dynsecret.ADReconcilePrincipal{DN: "CN=reconcile,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1101", GUID: strings.Repeat("b", 32)}
	return &selected, pins, nil
}
func (f *dependentDirectoryBoundary) Name() string {
	if f.native != nil {
		return f.native.Name()
	}
	return "owned-dependent-directory"
}
func (f *dependentDirectoryBoundary) AllowsStaticRotation(role string) bool {
	if f.native != nil {
		return f.native.(dynsecret.StaticRotationProvider).AllowsStaticRotation(role)
	}
	return role == "app/dependent"
}
func (f *dependentDirectoryBoundary) RotationPhase(role string) string {
	if f.native != nil {
		return f.native.(dynsecret.RotationPhaser).RotationPhase(role)
	}
	return dynsecret.RotationSinglePhase
}
func (f *dependentDirectoryBoundary) StaticRotationBinding(role string) string {
	if f.native != nil {
		return f.native.(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding(role)
	}
	if f.reconcile {
		return strings.Repeat("f", 64)
	}
	return strings.Repeat("e", 64)
}
func (*dependentDirectoryBoundary) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("fixture requires durable prepared custody")
}
func (f *dependentDirectoryBoundary) Revoke(ctx context.Context, ref string) error {
	if f.native != nil {
		return f.native.Revoke(ctx, ref)
	}
	return nil
}
func (f *dependentDirectoryBoundary) VerifyStaticCredential(ctx context.Context, ref string, credential []byte) (string, error) {
	if f.native != nil {
		return f.native.(dynsecret.StaticRotationProvider).VerifyStaticCredential(ctx, ref, credential)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current == nil || !bytes.Equal(f.current.Bytes(), credential) {
		return "", errors.New("owned native password rejected")
	}
	return "connected", nil
}
func (f *dependentDirectoryBoundary) ValidateStaticRecoveryCredential(req dynsecret.GenerateRequest, raw []byte) error {
	if f.native != nil {
		return f.native.(dynsecret.StaticRecoveryCredentialValidator).ValidateStaticRecoveryCredential(req, raw)
	}
	return dynsecret.ValidateADRecoveryCredential(raw, req.Predecessor)
}
func (f *dependentDirectoryBoundary) PrepareStaticCredential(ctx context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	if f.native != nil {
		return f.native.(dynsecret.PreparedStaticRotationProvider).PrepareStaticCredential(ctx, req)
	}
	random, e := crypto.RandomBytes(24)
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(random)
	password, e := secret.New(4 + hex.EncodedLen(len(random)))
	if e != nil {
		return nil, e
	}
	defer password.Destroy()
	copy(password.Bytes(), []byte("Tr5!"))
	hex.Encode(password.Bytes()[4:], random)
	return dependentFixturePasswordJSON(struct {
		Role      string `json:"role"`
		Operation string `json:"operation_id"`
		Binding   string `json:"provider_binding"`
		DN        string `json:"bind_dn"`
		User      string `json:"username"`
		SID       string `json:"native_sid"`
		GUID      string `json:"native_guid"`
	}{req.Role, req.LeaseID, f.StaticRotationBinding(req.Role), dependentFixtureDN, "service", "010500000000000515000000010000000200000003000000e9030000", strings.Repeat("a", 32)}, password.Bytes())
}
func (f *dependentDirectoryBoundary) VerifyStaticPreparedCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared, credential []byte) error {
	f.mu.Lock()
	f.publicationProofs++
	refuse := f.refusePublicationProof
	f.mu.Unlock()
	if refuse {
		return errors.New("owned exact native publication proof refused")
	}

	if f.native != nil {
		return f.native.(dynsecret.PreparedStaticRotationVerifier).VerifyStaticPreparedCredential(ctx, req, prepared, credential)
	}
	_, err := f.VerifyStaticCredential(ctx, req.Predecessor, credential)
	return err
}
func (f *dependentDirectoryBoundary) GenerateStaticPrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	var credential dynsecret.Credential
	if f.native != nil {
		var err error
		credential, err = f.native.(dynsecret.PreparedStaticRotationProvider).GenerateStaticPrepared(ctx, req, prepared)
		if err != nil {
			return credential, err
		}
	} else {
		var p struct {
			Password secret.JSONBytes `json:"password"`
		}
		if err := json.Unmarshal(prepared, &p); err != nil {
			return credential, err
		}
		defer secret.Wipe(p.Password)
		raw, err := dependentFixtureCredential(p.Password)
		if err != nil {
			return credential, err
		}
		credential = dynsecret.Credential{BackendRef: dependentFixtureDN, Secret: raw, Metadata: map[string]string{"provider_type": "ldap"}}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	held, err := secret.NewFrom(credential.Secret)
	if err != nil {
		secret.Wipe(credential.Secret)
		return dynsecret.Credential{}, err
	}
	if f.current != nil {
		f.current.Destroy()
	}
	f.current = held
	if f.native != nil {
		if f.lastNative != nil {
			f.lastNative.Destroy()
		}
		f.lastNative, err = secret.NewFrom(credential.Secret)
		if err != nil {
			secret.Wipe(credential.Secret)
			return dynsecret.Credential{}, err
		}
	}
	f.applied++
	if f.afterApply != nil {
		hook := f.afterApply
		f.afterApply = nil
		hook()
		secret.Wipe(credential.Secret)
		return dynsecret.Credential{}, errors.New("owned native apply response interrupted")
	}
	return credential, nil
}

func (f *dependentDirectoryBoundary) RestoreStaticCredential(_ context.Context, _ string, _ string, old []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil && bytes.Equal(f.current.Bytes(), old) {
		return nil
	}
	held, e := secret.NewFrom(old)
	if e != nil {
		return e
	}
	if f.current != nil {
		f.current.Destroy()
	}
	f.current = held
	f.restored++
	return nil
}
func (f *dependentDirectoryBoundary) RestorePreparedStaticCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte, old []byte) error {
	if f.native != nil {
		if err := f.native.(dynsecret.PreparedStaticRotationProvider).RestorePreparedStaticCredential(ctx, req, prepared, old); err != nil {
			return err
		}
	}
	return f.RestoreStaticCredential(ctx, req.Role, req.Predecessor, old)
}
func dependentFixtureCredential(password []byte) ([]byte, error) {
	return dependentFixturePasswordJSON(struct {
		Username string `json:"username"`
		DN       string `json:"bind_dn"`
	}{"service", dependentFixtureDN}, password)
}

// Secret quoting uses owned wipeable slices, never encoding/json's pooled
// encoder. Only public fixture metadata enters that encoder.
func dependentFixturePasswordJSON(metadata any, password []byte) ([]byte, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	quoted, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(quoted)
	out := make([]byte, 0, len(raw)+len(quoted)+12)
	out = append(out, raw[:len(raw)-1]...)
	out = append(out, []byte(`,"password":`)...)
	out = append(out, quoted...)
	return append(out, '}'), nil
}

func TestServedDependentRotationWaitsForEveryHostAndRollsBackA267(t *testing.T) {
	t.Run("vault edit during preflight", func(t *testing.T) { servedDependentRotation(t, false, true) })
	t.Run("vault edit after unrecorded native apply", func(t *testing.T) { servedDependentRotation(t, false, false, true, true) })
	t.Run("vault edit after directory apply", func(t *testing.T) { servedDependentRotation(t, false, false, true) })
	t.Run("vault edit during dependent failure", func(t *testing.T) { servedDependentRotation(t, true, false, true) })
	for _, fail := range []bool{false, true} {
		name := "forward"
		if fail {
			name = "dependent failure"
		}
		t.Run(name, func(t *testing.T) { servedDependentRotation(t, fail) })
	}
}
func servedDependentRotation(t *testing.T, injectFailure bool, moved ...bool) {
	servedDependentRotationCase(t, nil, injectFailure, moved...)
}
func servedDependentRotationCase(t *testing.T, native *dependentNativeDirectoryFixture, injectFailure bool, moved ...bool) {
	servedDependentRotationCaseWithMode(t, native, injectFailure, false, moved...)
}
func TestServedDependentReconciliationRequiresIndependentReviewA267(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "forward"
		if failure {
			name = "dependent failure"
		}
		t.Run(name, func(t *testing.T) { servedDependentRotationCaseWithMode(t, nil, failure, true) })
	}
}

type dependentRotationOptions struct {
	ManifestReviewOnly      bool
	ManifestDependencyOrder bool
	ManifestLargeReview     bool
	RecoverInverse          bool
	ExpiredInverse          bool
	ExpireBeforeApply       bool
	InvalidRecovery         bool
	EraseClaim              bool
	LoseQueueProjection     bool
	Reconcile               bool
	RefusePublicationProof  bool
}

func servedDependentRotationCaseWithMode(t *testing.T, native *dependentNativeDirectoryFixture, injectFailure, reconcile bool, moved ...bool) {
	servedDependentRotationScenario(t, native, injectFailure, dependentRotationOptions{Reconcile: reconcile}, moved...)
}
func TestServedReconciliationRefusesChangedNativePublicationProofA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{Reconcile: true, RefusePublicationProof: true})
}
func servedDependentRotationScenario(t *testing.T, native *dependentNativeDirectoryFixture, injectFailure bool, scenario dependentRotationOptions, moved ...bool) {
	reconcile, proofFailure := scenario.Reconcile, scenario.RefusePublicationProof
	staleVault := len(moved) > 0 && moved[0]
	lateVault := len(moved) > 1 && moved[1]
	partialNative := len(moved) > 2 && moved[2]
	concurrentValue := []byte("owned-concurrent-vault-value")
	movedVault := false
	ctx := t.Context()
	identity := servicedependents.AccountBinding{Name: "service", DN: dependentFixtureDN, SID: dependentFixtureSID, GUID: strings.Repeat("a", 32)}
	old, e := dependentFixtureCredential([]byte(strings.Repeat("owned-bootstrap-", 3)))
	if native != nil {
		secret.Wipe(old)
		identity = native.identity
		old = append([]byte(nil), native.initial.Bytes()...)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(old)
	held, e := secret.NewFrom(old)
	if e != nil {
		t.Fatal(e)
	}
	directory := &dependentDirectoryBoundary{dependentDirectoryState: &dependentDirectoryState{current: held, refusePublicationProof: proofFailure}}
	t.Cleanup(func() {
		directory.mu.Lock()
		defer directory.mu.Unlock()
		directory.current.Destroy()
		if directory.lastNative != nil {
			directory.lastNative.Destroy()
		}
	})
	if reconcile && native == nil {
		drift, err := dependentFixtureCredential([]byte(strings.Repeat("owned-external-drift-", 3)))
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := secret.NewFrom(drift)
		secret.Wipe(drift)
		if err != nil {
			t.Fatal(err)
		}
		directory.current.Destroy()
		directory.current = replacement
	}
	options := []func(*Deps){withSecretsEnabled(t, nil), func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.DynamicSecretProviders = []dynsecret.Provider{directory}
	}}
	var ownedStore *store.Store
	if native == nil {
		options = append(options, withIsolatedTenant)
	} else {
		directory.native = native.provider
		ownedStore = native.store
	}
	var eventOptions []events.OpenOption
	if native == nil && (!injectFailure || scenario.RecoverInverse) && !staleVault && !lateVault {
		// The source-erasure proof uses the production coordinator/verifier and
		// the same real audit key in the server's continuity callbacks.
		ownedStore = newServerTestStore(t)
		auditKey, err := jose.GenerateRSASigningKey("dependent-privacy-proof")
		if err != nil {
			t.Fatal(err)
		}
		eventOptions = []events.OpenOption{
			events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(ownedStore)),
			events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(auditKey)),
		}
		options = append(options, func(d *Deps) { d.AuditSigningKey = auditKey })
	}
	h := newRoleHarnessNamedWithOwnedStore(t, "dependent-rotation-host", []string{mtls.AgentRoleHost}, []string{servicedependents.InventoryDestination, servicedependents.RotationDestination}, eventOptions, ownedStore, options...)
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	projector := projections.New(h.store)
	appendSource := func(kind string, value any) {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		event, e := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: kind, Data: raw})
		if e != nil {
			t.Fatal(e)
		}
		if e = projector.Apply(ctx, event); e != nil {
			t.Fatal(e)
		}
	}
	appendSource(projections.EventPAMDiscoverySourceSaved, projections.PAMDiscoverySourceSaved{ProviderID: directory.Name(), ProviderType: "ldap", Actor: "owned-reader", At: now})
	appendSource(projections.EventPAMDiscoveryRunCompleted, projections.PAMDiscoveryRunCompleted{RunID: uuid.NewString(), ProviderID: directory.Name(), Status: "completed", RequestedBy: "owned-reader", StartedAt: now, FinishedAt: now, Accounts: []pamdiscovery.Account{{Key: "user:" + identity.Name, Name: identity.Name, Kind: pamdiscovery.KindDirectoryServiceAccount, Details: map[string]string{"dn": identity.DN, "service_account": "true", "configured_rotation_account": "true", "native_sid": identity.SID, "native_guid": identity.GUID}}}})
	accounts, e := h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, directory.Name(), "staged", false)
	if e != nil || len(accounts) != 1 {
		t.Fatal("native account source unavailable", e)
	}
	token := seedScopedTokenSubject(t, h.store, h.tenant, "owned-rotation-operator", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", token, "owned-initial-value", map[string]any{"name": "app/dependent", "value": secret.JSONBytes(storedDependentFixtureValue(old, scenario.InvalidRecovery))})
	if code != 200 && code != 201 {
		t.Fatalf("initial secret: %d %s", code, body)
	}
	if partialNative {
		directory.afterApply = func() {
			code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/secrets/store/app/dependent", token, "owned-partial-native-vault-edit", map[string]any{"value": secret.JSONBytes(concurrentValue)})
			if code != http.StatusOK {
				t.Fatal("owned partial-native vault edit failed")
			}
			movedVault = true
		}
	}
	root := "/api/v1/access/discovery/accounts/" + accounts[0].ID + "/dependents"
	hostID := agentRowID(h.tenant, h.agent)
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+hostID, token, "owned-host", map[string]any{"enabled": true})
	if code != 200 {
		t.Fatalf("host binding: %d %s", code, body)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", token, "refuse-dependent-bypass", map[string]any{"provider": directory.Name(), "key": "app/dependent", "old_ref": strings.ToUpper(identity.DN), "acknowledge_single_phase": true}); status != http.StatusConflict {
		t.Fatalf("ordinary rotation bypassed selected native dependents: %d", status)
	}
	if scenario.ExpireBeforeApply {
		// Seed a genuinely historical scan command, then accept its signed
		// observation now. Only PAM's fixture clock is scoped to that command;
		// review/worker deadlines still use the unchanged real host clock.
		previousClock := h.srv.pam.clock
		h.srv.pam.clock = func() time.Time {
			return time.Now().UTC().Add(-servicedependents.RotationInventoryMaxAge + 8*time.Second)
		}
		defer func() { h.srv.pam.clock = previousClock }()
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+hostID+"/runs", token, "owned-inventory", nil)
	if code != 202 {
		t.Fatalf("inventory: %d %s", code, body)
	}
	claim, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(claim.Jobs) != 1 {
		t.Fatal("inventory not claimed", e)
	}
	inventoryJob := claim.Jobs[0]
	inventoryIntent, e := servicedependents.DecodeInventoryIntent(inventoryJob.Payload)
	if e != nil {
		t.Fatal(e)
	}
	inventory := servicedependents.InventoryReport{RunID: inventoryIntent.RunID, BindingDigest: inventoryIntent.BindingDigest, ObservedAt: time.Now().UTC(), Coverage: []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}},
		Services: []windependents.Service{{Name: "owned-service", AccountSID: identity.SID, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true}},
		Tasks:    []windependents.Task{{Path: "\\owned\\task", AccountSID: identity.SID, ConfigSHA256: strings.Repeat("c", 64), Enabled: true, LogonType: 1, ActionCount: 1}},
		Pools:    []windependents.Pool{{Name: "owned-pool", AccountSID: identity.SID, ConfigSHA256: strings.Repeat("d", 64), EncryptionProvider: "native", PasswordProtected: true, WasStarted: true}}}
	if scenario.ManifestLargeReview {
		inventory = largeManifestInventory(inventory, identity.SID)
	}
	if scenario.ManifestDependencyOrder {
		inventory.Services = []windependents.Service{{Name: "base", AccountSID: identity.SID, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true}, {Name: "child", AccountSID: identity.SID, ConfigSHA256: strings.Repeat("c", 64), Dependencies: []string{"BASE"}, WasRunning: true}}
	}
	if scenario.ExpireBeforeApply {
		inventory.ObservedAt = time.Now().UTC().Add(-servicedependents.RotationInventoryMaxAge + 8*time.Second)
	}
	raw, e := json.Marshal(inventory)
	if e != nil {
		t.Fatal(e)
	}
	if receipt, e := h.client.ReportJobResult(ctx, h.report(t, inventoryJob.JobID, inventoryJob.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))); e != nil || !receipt.Accepted {
		t.Fatal("inventory not accepted", e)
	}
	if scenario.ManifestLargeReview {
		servedLargeDependentManifestReview(t, h, token, root, inventoryIntent.Binding, inventory, directory, projector)
		return
	}
	if scenario.ManifestReviewOnly {
		servedDependentManifestReview(t, h, token, root, inventoryIntent.Binding, inventory, directory, projector, scenario.ManifestDependencyOrder)
		return
	}
	order := []servicedependents.DependentRef{{AgentID: hostID, Family: "services", Name: "owned-service"}, {AgentID: hostID, Family: "tasks", Name: "\\owned\\task"}, {AgentID: hostID, Family: "iis", Name: "owned-pool"}}
	probes := []servicedependents.ProbeBinding{}
	for _, ref := range order {
		probes = append(probes, servicedependents.ProbeBinding{Ref: ref, ProbeID: "owned-functional-work"})
	}
	// A SQL rewrite before review may not manufacture a signed host fact,
	// even when its digest and the caller's order are internally consistent.
	forged := inventory
	forged.Services = append([]windependents.Service(nil), inventory.Services...)
	forged.Services[0].Name = "fabricated-service"
	forgedRaw, e := json.Marshal(forged)
	if e != nil {
		t.Fatal(e)
	}
	originalRaw, e := json.Marshal(inventory)
	if e != nil {
		t.Fatal(e)
	}
	replaceReport := func(payload []byte) {
		t.Helper()
		if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE service_account_host_scans SET report=$3::jsonb,report_digest=$4 WHERE tenant_id=$1 AND id=$2`, h.tenant, inventory.RunID, payload, crypto.SHA256Hex(payload))
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	replaceReport(forgedRaw)
	forgedOrder := append([]servicedependents.DependentRef(nil), order...)
	forgedOrder[0].Name = "fabricated-service"
	forgedProbes := append([]servicedependents.ProbeBinding(nil), probes...)
	forgedProbes[0].Ref = forgedOrder[0]
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations/preview", token, "reject-unsigned-native-facts", map[string]any{"secret_name": "app/dependent", "order": forgedOrder, "probes": forgedProbes}); status != http.StatusConflict {
		t.Fatalf("rewritten native SQL metadata accepted for review: %d", status)
	}
	replaceReport(originalRaw)
	previewInput := map[string]any{"secret_name": "app/dependent", "order": order, "probes": probes}
	if reconcile {
		previewInput["mode"] = "reconcile"
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations/preview", token, "owned-review", previewInput)
	var preview struct {
		Intent servicedependents.RotationIntent `json:"intent"`
		Digest string                           `json:"intent_digest"`
	}
	if code != 200 || json.Unmarshal(body, &preview) != nil || preview.Digest == "" {
		t.Fatalf("reviewed dependent rotation: status=%d body=%s", code, body)
	}
	request := map[string]any{"intent": preview.Intent, "intent_digest": preview.Digest, "acknowledge_single_phase": true}
	if reconcile {
		var wire struct {
			Intent struct {
				Mode      string `json:"mode"`
				Reconcile struct {
					DN   string `json:"dn"`
					SID  string `json:"sid"`
					GUID string `json:"guid"`
				} `json:"reconcile"`
			} `json:"intent"`
		}
		if json.Unmarshal(body, &wire) != nil || wire.Intent.Mode != "reconcile" || wire.Intent.Reconcile.SID == "" || wire.Intent.Reconcile.SID == identity.SID || len(wire.Intent.Reconcile.GUID) != 32 {
			t.Fatal("public reconciliation review omitted exact designated authority")
		}
		assertNoQueue := func(key string) {
			t.Helper()
			if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations", token, key, request); status != http.StatusConflict {
				t.Fatalf("unapproved reconciliation queued: %d", status)
			}
			if _, found, e := h.log.EventByID(ctx, preview.Intent.Plan.ID); e != nil || found {
				t.Fatal("refused reconciliation poisoned the canonical event stream", e)
			}
			if directory.applied != 0 {
				t.Fatal("refused reconciliation reached native reset")
			}
		}
		assertNoQueue("reconcile-without-approval")
		code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations/approval", token, "request-reconcile-review", map[string]any{"intent": preview.Intent, "intent_digest": preview.Digest, "reason": "Repair independently observed drift for owned-rotation-operator"})
		var review struct {
			RequestID string `json:"approval_request_id"`
			Digest    string `json:"approval_intent_digest"`
			Status    string `json:"status"`
		}
		if code != http.StatusAccepted || json.Unmarshal(body, &review) != nil || review.RequestID == "" || review.Digest == "" || review.Status != "pending" {
			t.Fatalf("request exact reconciliation review: %d %s", code, body)
		}
		request["approval_request_id"], request["approval_intent_digest"] = review.RequestID, review.Digest
		assertNoQueue("reconcile-pending-approval")
		ownReview := root + "/rotations/reviews/" + preview.Intent.Plan.ID + "?approval_request_id=" + review.RequestID
		status, resumed := secretsReq(t, h.servedHarness, http.MethodGet, ownReview, token, nil)
		var pending struct {
			Digest   string `json:"intent_digest"`
			Approval struct {
				ID     string `json:"approval_request_id"`
				Status string `json:"status"`
			} `json:"approval"`
			Reason string `json:"reason"`
		}
		if status != http.StatusOK || json.Unmarshal(resumed, &pending) != nil || pending.Digest != preview.Digest || pending.Approval.ID != review.RequestID || pending.Approval.Status != "pending" || pending.Reason != "Repair independently observed drift for owned-rotation-operator" {
			t.Fatalf("requester could not resume exact pending review without approval permission: %d %s", status, resumed)
		}
		outsider := seedScopedTokenSubject(t, h.store, h.tenant, "owned-other-rotation-operator", "access:read", "access:targets.write", "secrets:read", "secrets:write")
		if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, ownReview, outsider, nil); status != http.StatusForbidden {
			t.Fatalf("another writer resumed someone else's review: %d", status)
		}

		self := seedScopedTokenSubject(t, h.store, h.tenant, "owned-rotation-operator", "access:approve")
		if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.RequestID+"/approvals", self, "refuse-self-reconcile-review", map[string]string{"intent_digest": review.Digest}); status != http.StatusForbidden {
			t.Fatalf("self reconciliation review accepted: %d", status)
		}
		reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "owned-independent-reconcile-reviewer", "access:approve")
		status, listed := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", reviewer, nil)
		if status != http.StatusOK || !bytes.Contains(listed, []byte(review.RequestID)) {
			t.Fatalf("independent reviewer could not discover reconciliation: %d %s", status, listed)
		}
		status, manifest := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/reconciliation-reviews/"+preview.Intent.Plan.ID, reviewer, nil)
		var opened struct {
			Intent servicedependents.RotationIntent `json:"intent"`
			Digest string                           `json:"intent_digest"`
		}
		if status != http.StatusOK || json.Unmarshal(manifest, &opened) != nil || opened.Digest != preview.Digest || opened.Intent.Mode != servicedependents.Reconcile || opened.Intent.Reconcile == nil || opened.Intent.Reconcile.SID != wire.Intent.Reconcile.SID {
			t.Fatalf("reviewer could not open the complete frozen reconcile manifest: %d %s", status, manifest)
		}
		if e, err := opened.Intent.Digest(); err != nil || e != preview.Digest {
			t.Fatal("review manifest no longer matches approved digest", err)
		}
		if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/reconciliation-reviews/"+preview.Intent.Plan.ID, token, nil); status != http.StatusForbidden {
			t.Fatalf("review manifest omitted independent review permission: %d", status)
		}
		code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.RequestID+"/approvals", reviewer, "approve-exact-reconciliation", map[string]string{"intent_digest": review.Digest})
		if code != http.StatusOK {
			t.Fatalf("independent exact reconciliation review: %d %s", code, body)
		}
		status, resumed = secretsReq(t, h.servedHarness, http.MethodGet, ownReview, token, nil)
		if status != http.StatusOK || json.Unmarshal(resumed, &pending) != nil || pending.Approval.Status != "approved" || pending.Approval.ID != review.RequestID {
			t.Fatal("requester approval refresh did not retain its exact review")
		}

	}

	if scenario.LoseQueueProjection {
		interruptDependentQueueProjection(t, h, root, token, preview.Intent.Plan.ID, request)
	}
	if scenario.EraseClaim {
		eraseAndRecoverDependentClaim(t, h, preview.Intent.Plan.ID)
		return
	}

	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations", token, "owned-rotate", request)
	var queued struct {
		Rotation store.ServiceDependentRotation `json:"rotation"`
	}
	if code != 202 || json.Unmarshal(body, &queued) != nil || queued.Rotation.CommandID == "" {
		t.Fatalf("atomic queue: %d %s", code, body)
	}
	if reconcile {
		status, recovered := secretsReq(t, h.servedHarness, http.MethodGet, root+"/rotations/reviews/"+preview.Intent.Plan.ID+"?approval_request_id="+request["approval_request_id"].(string), token, nil)
		var result struct {
			RotationID string `json:"rotation_id"`
		}
		if status != http.StatusOK || json.Unmarshal(recovered, &result) != nil || result.RotationID != queued.Rotation.ID || directory.applied != 0 {
			t.Fatal("lost queue response did not recover existing operation without native replay")
		}
	}
	if queued.Rotation.ID != preview.Intent.Plan.ID {
		t.Fatal("reviewed identity changed")
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations", token, "owned-rotate", request)
	if code != 202 {
		t.Fatalf("queue retry: %d %s", code, body)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+hostID, token, "refuse-midflight-host-change", map[string]any{"enabled": false}); status != http.StatusConflict {
		t.Fatalf("in-flight native host membership changed: %d", status)
	}
	if scenario.ExpireBeforeApply || scenario.InvalidRecovery {
		assertDependentNoEffectAdmission(t, h, directory, root, token, queued.Rotation.CommandID, preview.Intent.Plan.ExpiresAt, scenario.ExpireBeforeApply)
		return
	}
	recoveredInverse := false
	checkedAuthority := false
	checkedStepSource := false
	failed := false
	var failedJobID int64
	var seen []string
	var final store.SecretStaticRotationCommand
	deadline := time.Now().Add(45 * time.Second)
	var expiredInverseID string
	if scenario.ExpiredInverse {
		deadline = deadline.Add(181 * time.Second)
	}
	for time.Now().Before(deadline) {
		command, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.Rotation.CommandID)
		if e != nil {
			t.Fatal(e)
		}
		if command.Terminal() {
			final = command
			break
		}
		if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending'`, h.tenant, command.OutboxID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludeDestinations: []string{store.SecretStaticRotationDestination}}); e != nil {
			t.Fatal(e)
		}
		if failedJobID > 0 {
			parent, e := h.store.GetServiceDependentRotation(ctx, h.tenant, queued.Rotation.ID)
			if e != nil {
				t.Fatal(e)
			}
			if parent.Direction == servicedependents.Inverse {
				var status string
				if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, failedJobID).Scan(&status)
				}); e != nil {
					t.Fatal(e)
				}
				if status != "cancelled" {
					t.Fatalf("superseded native job retains retry/claim authority: %s", status)
				}
			}
		}
		jobs, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.RotationDestination}, Limit: 1, LeaseSeconds: 120})
		if e != nil {
			t.Fatal(e)
		}
		if len(jobs.Jobs) == 0 {
			continue
		}
		job := jobs.Jobs[0]
		step, e := servicedependents.DecodeRotationStep(job.Payload)
		if e != nil {
			t.Fatal(e)
		}
		if !checkedAuthority {
			checkedAuthority = true
			// Removing a projected parent reference must not turn a coordinated
			// reset into an ordinary one and bypass every host preflight.
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE secret_static_rotation_commands SET dependent_change_id=NULL WHERE tenant_id=$1 AND id=$2`, h.tenant, queued.Rotation.CommandID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			advanceErr := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.Rotation.CommandID, 1)
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE secret_static_rotation_commands SET dependent_change_id=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, queued.Rotation.CommandID, queued.Rotation.ID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if advanceErr == nil || directory.applied != 0 {
				t.Fatalf("removed SQL parent bypassed native preflight authority: err=%v native=%d", advanceErr, directory.applied)
			}
			setParent := func(direction string, restored bool) {
				t.Helper()
				if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE service_account_rotations SET direction=$3,directory_restored=$4 WHERE tenant_id=$1 AND id=$2`, h.tenant, queued.Rotation.ID, direction, restored)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			setParent(servicedependents.Inverse, true)
			forged := step
			forged.Action = servicedependents.Update
			forged.Direction = servicedependents.Inverse
			raw, e := h.srv.api.OpenDependentRotationCredential(ctx, h.tenant, forged)
			secret.Wipe(raw)
			setParent(servicedependents.Forward, false)
			if e == nil {
				t.Fatal("rewritten SQL selected an inverse credential without a canonical recovery source")
			}
		}
		seen = append(seen, step.Direction+":"+step.Action+":"+step.Ref.Family)
		report := servicedependents.StepReport{RotationID: step.RotationID, PlanDigest: step.PlanDigest, StepID: step.ID, Direction: step.Direction, Status: "succeeded", ObservedAt: time.Now().UTC()}
		if step.Action == servicedependents.Preflight {
			if step.Service != nil {
				report.Runtime = &windependents.Runtime{Running: true, ProcessID: 101, AccountSID: step.AccountSID}
			}
			if step.Pool != nil {
				report.Runtime = &windependents.Runtime{Running: true, AccountSID: step.AccountSID}
			}
		}
		if step.Action == servicedependents.Preflight && directory.applied != 0 {
			t.Fatal("directory changed before every host preflight")
		}
		if step.Action == servicedependents.Update {
			material, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
			if e != nil || len(material.Items) != 1 {
				t.Fatal("exact sealed generation not redeemed", e)
			}
			var current struct {
				Password secret.JSONBytes `json:"password"`
			}
			directory.mu.Lock()
			e = json.Unmarshal(directory.current.Bytes(), &current)
			directory.mu.Unlock()
			if e != nil || !bytes.Equal(current.Password, material.Items[0].Value) {
				t.Fatal("host received another directory generation")
			}
			secret.Wipe(current.Password)
			secret.Wipe(material.Items[0].Value)
			if injectFailure && !failed && step.Direction == servicedependents.Forward && step.Ref.Family == "tasks" {
				failed = true
				report.Status = "failed"
				report.Failure = "native_operation_failed"
			}
		} else if _, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); e == nil {
			t.Fatal("non-update host work redeemed a password")
		}
		if step.Action == servicedependents.Stop {
			report.Runtime = &windependents.Runtime{}
			if step.Pool != nil {
				previousPID := uint32(101)
				if step.Direction == servicedependents.Inverse {
					previousPID = 202
				}
				report.PoolProof = &windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, PreviousPIDs: []uint32{previousPID}}
			}
		}
		runtimePID := uint32(202)
		if step.Direction == servicedependents.Inverse {
			runtimePID = 303
		}
		if step.Action == servicedependents.Start || step.Action == servicedependents.Probe {
			report.Runtime = &windependents.Runtime{Running: true, ProcessID: runtimePID, AccountSID: step.AccountSID}
			if step.Pool != nil {
				report.PoolProof = &windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, StartedObserved: true, PreviousPIDs: step.PreviousPIDs}
			}
		}
		if step.Action == servicedependents.Probe {
			report.Functional = &servicedependents.FunctionalProof{ProbeID: step.ProbeID, Challenge: step.Challenge, ProcessID: runtimePID, AccountSID: step.AccountSID, EvidenceSHA256: strings.Repeat("f", 64)}
			if step.Task != nil {
				report.Runtime = nil
				report.Functional.ProcessID = 0
				instance := uuid.NewString()
				report.TaskProof = &windependents.TaskRunProof{StartedAt: step.NotBefore, CompletedAt: report.ObservedAt, Path: step.Task.Path, AccountSID: step.AccountSID, InstanceID: instance, StartRecordID: 11, CompletionRecordID: 13, Actions: []windependents.TaskActionResult{{RecordID: 12, ResultCode: 0}}}
				report.Functional.TaskInstanceID = instance
			}
		}
		recoverThisStep := scenario.RecoverInverse && !recoveredInverse && step.Direction == servicedependents.Inverse && step.Action == servicedependents.Probe && step.Task != nil
		if recoverThisStep && !scenario.ExpiredInverse {
			report.Status = "uncertain"
			report.Failure = "task_start_uncertain"
			report.Runtime = nil
			report.TaskProof = nil
			report.PoolProof = nil
			report.Functional = nil
		}
		raw, e := json.Marshal(report)
		if e != nil {
			t.Fatal(e)
		}
		checkSourceBarrier := func(payload []byte) {
			t.Helper()
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE service_account_rotation_steps SET status='succeeded',report=$4::jsonb WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, h.tenant, step.RotationID, step.ID, payload)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			advanceErr := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.Rotation.CommandID, 1)
			var count int
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM service_account_rotation_steps WHERE tenant_id=$1 AND rotation_id=$2`, h.tenant, step.RotationID).Scan(&count)
			}); e != nil {
				t.Fatal(e)
			}
			if count != 1 || advanceErr == nil || !strings.Contains(advanceErr.Error(), "canonical") || directory.applied != 0 {
				t.Fatalf("SQL step metadata bypassed canonical evidence barrier: steps=%d err=%v native=%d", count, advanceErr, directory.applied)
			}
			status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/dependent-rotations/"+step.RotationID+"/steps", token, nil)
			if status != http.StatusConflict {
				t.Fatalf("served evidence trusted changed SQL step metadata: %d", status)
			}
		}
		if !checkedStepSource {
			// A plausible SQL success without a signed source cannot authorize
			// the next host or the directory reset.
			checkSourceBarrier(raw)
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE service_account_rotation_steps SET status='queued',report=NULL WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, h.tenant, step.RotationID, step.ID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
		if recoverThisStep && scenario.ExpiredInverse {
			expiredInverseID = step.ID
			waitForExpiredDependentLease(t, step)
			requestDependentInverseRecovery(t, h, token, step)
			assertLateDependentReceipt(t, h, job.JobID, job.Attempt, report)
			recoveredInverse = true
			continue
		}
		outcome := transport.JobOutcomeExecuted
		if report.Status != "succeeded" {
			// A failed native task must remain a failed report so the host's
			// durable start fence cannot be retired as a successful execution.
			invalid, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw)))
			if err == nil && invalid.Accepted {
				t.Fatal("failed native status accepted as successful execution")
			}
			outcome = transport.JobOutcomeFailed
			if !recoverThisStep {
				failedJobID = job.JobID
			}
		}
		if receipt, e := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, outcome, string(raw), crypto.SHA256Hex(raw))); e != nil || !receipt.Accepted {
			t.Fatalf("native step report rejected %s %s: %v", step.Direction, step.Action, e)
		}
		if recoverThisStep {
			requestDependentInverseRecovery(t, h, token, step)
			recoveredInverse = true
		}
		if !checkedStepSource {
			checkedStepSource = true
			// The signed report exists now; replacing its PID in SQL must
			// still refuse advancement and predecessor-process selection.
			forged := report
			runtime := *report.Runtime
			runtime.ProcessID = 909
			forged.Runtime = &runtime
			forgedRaw, e := json.Marshal(forged)
			if e != nil {
				t.Fatal(e)
			}
			checkSourceBarrier(forgedRaw)
			if e := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE service_account_rotation_steps SET report=$4::jsonb WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, h.tenant, step.RotationID, step.ID, raw)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
		if !movedVault && step.Direction == servicedependents.Forward && (staleVault && step.Action == servicedependents.Preflight || lateVault && step.Action == servicedependents.Update) {
			replacement := old
			if lateVault {
				replacement = concurrentValue
			}
			code, value := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/secrets/store/app/dependent", token, "owned-concurrent-vault-edit", map[string]any{"value": secret.JSONBytes(replacement)})
			if code != http.StatusOK {
				t.Fatalf("concurrent vault edit: %d %s", code, value)
			}
			movedVault = true
		}
		if step.Action != servicedependents.Probe {
			status, value := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/app/dependent", token, nil)
			var current struct {
				Version int `json:"version"`
			}
			if status != 200 || json.Unmarshal(value, &current) != nil || current.Version != func() int {
				if movedVault {
					return 2
				}
				return 1
			}() {
				t.Fatal("vault published before all native functional evidence")
			}
		}
	}
	want := store.SecretStaticRotationCompleted
	if injectFailure || proofFailure {
		want = store.SecretStaticRotationRolledBack
	}
	if staleVault {
		want = store.SecretStaticRotationFailed
	}
	if lateVault {
		want = store.SecretStaticRotationRollbackFailed
	}
	if proofFailure && (directory.publicationProofs == 0 || final.ResultVersion != 0) {
		t.Fatal("native identity proof failure was ignored or allowed successor vault publication")
	}
	if final.Phase != want {
		t.Fatalf("incomplete dependent coordinator phase=%s error=%s steps=%v", final.Phase, final.Error, seen)
	}
	if (injectFailure || lateVault || proofFailure) && (injectFailure && !failed || directory.restored != 1) {
		t.Fatal("dependent failure did not restore directory once")
	}
	if !injectFailure {
		expected := 1
		if staleVault {
			expected = 0
		}
		if directory.applied != expected {
			t.Fatal("directory apply repeated or ran after a stale vault version")
		}
	}
	directory.mu.Lock()
	same := bytes.Equal(directory.current.Bytes(), old)
	directory.mu.Unlock()
	if same != (injectFailure || staleVault || lateVault || proofFailure) {
		t.Fatal("upstream directory final generation differs")
	}
	if native != nil {
		assertNativeDependentDirectory(t, native, directory, old, injectFailure || proofFailure)
	}
	if lateVault {
		code, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/app/dependent", token, nil)
		var current struct {
			Version int              `json:"version"`
			Value   secret.JSONBytes `json:"value"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &current) != nil || current.Version != 2 || !bytes.Equal(current.Value, concurrentValue) {
			t.Fatal("native recovery overwrote an unrelated vault version")
		}
		secret.Wipe(current.Value)
		if !strings.Contains(final.Error, "vault version") {
			t.Fatal("recovered native effects hid the unresolved vault conflict")
		}
	}
	readRoot := "/api/v1/access/discovery/dependent-rotations/" + queued.Rotation.ID
	status, view := secretsReq(t, h.servedHarness, http.MethodGet, readRoot, token, nil)
	var progress struct {
		Rotation store.ServiceDependentRotation `json:"rotation"`
		Command  struct {
			Phase string `json:"phase"`
		} `json:"command"`
	}
	if status != http.StatusOK || json.Unmarshal(view, &progress) != nil || progress.Command.Phase != want || progress.Rotation.ID != queued.Rotation.ID {
		t.Fatal("public coordinator progress disagrees with actual command")
	}
	after := ""
	seenSteps := map[string]bool{}
	for {
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, readRoot+"/steps?limit=2&after="+after, token, nil)
		var page struct {
			Items []store.ServiceDependentStep `json:"items"`
			Next  string                       `json:"next_cursor"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &page) != nil || len(page.Items) > 2 {
			t.Fatal("native step paging failed")
		}
		for _, step := range page.Items {
			if step.Intent.ID == expiredInverseID {
				if seenSteps[step.Intent.ID] || step.Report != nil || step.Status != "queued" || step.DeliveryStatus != "cancelled" {
					t.Fatal("expired predecessor gained invented evidence or remained deliverable")
				}
			} else if seenSteps[step.Intent.ID] || step.Report == nil || step.Status == "queued" || step.DeliveryStatus == "" {
				t.Fatal("public progress lost, duplicated or invented native evidence")
			}
			seenSteps[step.Intent.ID] = true
		}
		if page.Next == "" {
			break
		}
		if page.Next == after {
			t.Fatal("native step cursor failed to advance")
		}
		after = page.Next
	}
	if len(seenSteps) != len(seen) {
		t.Fatalf("step progress omitted native work: have%d want%d", len(seenSteps), len(seen))
	}
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, readRoot+"/steps?after=not-a-step", token, nil); status != http.StatusBadRequest {
		t.Fatal("invalid native step cursor was accepted")
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "Owned dependent isolation")
	otherToken := seedScopedToken(t, h.store, other, "access:read", "secrets:read")
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, readRoot, otherToken, nil); status != http.StatusNotFound {
		t.Fatal("foreign tenant read native rotation")
	}
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, readRoot+"/steps", otherToken, nil); status != http.StatusNotFound {
		t.Fatal("foreign tenant read signed dependent steps")
	}
	if reconcile {
		event, found, err := h.log.EventByID(ctx, queued.Rotation.ID)
		var source struct {
			Approval *store.OperationApprovalUse `json:"approval"`
		}
		if err != nil || !found || json.Unmarshal(event.Data, &source) != nil || source.Approval == nil || source.Approval.Action != "reconcile" || source.Approval.ResourceKind != "pam_service_reconcile" || source.Approval.Requester != "owned-rotation-operator" {
			t.Fatal("completed reconciliation lacks exact audited authority", err)
		}
		if event.SchemaVersion != 2 {
			t.Fatal("reconciliation widened the historical ordinary source schema")
		}
		approval, err := h.store.GetOperationApproval(ctx, h.tenant, source.Approval.RequestID)
		if err != nil || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID != event.ID {
			t.Fatal("reconciliation approval not consumed by its exact root", err)
		}
	}
	if e := projector.ProjectCatchUp(ctx, h.log); e != nil {
		t.Fatal(e)
	}
	if _, e := projector.Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	if e := projector.Rebuild(ctx, h.log); e != nil {
		t.Fatal("coordinator did not survive snapshot/rebuild", e)
	}
	restored, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, final.ID)
	if e != nil || restored.Phase != want {
		t.Fatal("rebuild lost coordinator outcome", e)
	}
	reclaimed, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.RotationDestination}, Limit: 4, LeaseSeconds: 120})
	if e != nil || len(reclaimed.Jobs) != 0 {
		t.Fatal("completed native effects replayed after rebuild", e)
	}
	if native == nil && (!injectFailure || scenario.RecoverInverse) && !staleVault && !lateVault {
		const subject = "owned-rotation-operator"
		admin := seedScopedTokenSubject(t, h.store, h.tenant, "owned-privacy-operator", "privacy:read", "privacy:write", "access:read", "secrets:read")
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/privacy/subject-erasures", admin, "erase-owned-dependent-operator", map[string]string{"subject": subject, "reason": "owned source privacy proof"})
		if status != http.StatusCreated || bytes.Contains(body, []byte(subject)) {
			t.Fatalf("dependent actor source erasure failed: status=%d", status)
		}
		assertEventLogOmitsRawSubject(t, ctx, h.log, h.tenant, subject)
		if e := projector.Rebuild(ctx, h.log); e != nil {
			t.Fatal("erased native workflow could not rebuild", e)
		}
		parent, e := h.store.GetServiceDependentRotation(ctx, h.tenant, queued.Rotation.ID)
		if e != nil || parent.Actor != privacy.Placeholder(privacy.SubjectRef(h.tenant, subject)) {
			t.Fatal("coordinator source resurrected the erased actor", e)
		}
		if status, body := secretsReq(t, h.servedHarness, http.MethodGet, readRoot, admin, nil); status != http.StatusOK || bytes.Contains(body, []byte(subject)) {
			t.Fatal("served coordinator retained the erased actor")
		}
		if status, body := secretsReq(t, h.servedHarness, http.MethodGet, readRoot+"/steps", admin, nil); status != http.StatusOK || bytes.Contains(body, []byte(subject)) {
			t.Fatal("erasure lost exact native step evidence")
		}
		claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.RotationDestination}, Limit: 4, LeaseSeconds: 120})
		if e != nil || len(claims.Jobs) != 0 {
			t.Fatal("privacy rebuild revived completed native effects", e)
		}
	}
}
