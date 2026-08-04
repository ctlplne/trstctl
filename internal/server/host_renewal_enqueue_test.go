// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

// The reachability tests for host-generated renewal (epic B2).
//
// These exist because the feature was, for a while, completely unreachable: the
// job kind, the RPC, the agent executor and the parity gate all worked, all had
// tests, and nothing in the served code ever queued an endpoint.renew job. Every
// test passed and the capability had never run.
//
// So the property under test is not "does the enqueue function work" — it is
// "does a renewal for an agent-executed target take this path at all".

func agentExecutedTarget(t *testing.T) store.DeploymentTarget {
	t.Helper()
	return store.DeploymentTarget{
		ID: "44444444-4444-4444-4444-44444444c001", Name: "edge-1", Type: "nginx",
		Enabled: true,
		Config:  json.RawMessage(`{"executor":"agent","cert_path":"/etc/nginx/tls.crt","key_path":"/etc/nginx/tls.key"}`),
	}
}

// The marker is what decides the path, and it must be read the same way on both
// sides of the codebase.
//
// internal/api duplicates these constants because it may not import
// internal/server. The duplication is fine; the DRIFT is not — an api package
// that read the marker differently would report a target as migrated while the
// server kept sending it keys, which is the exact false claim B2 exists to make
// impossible.
func TestTheExecutorMarkerIsReadIdenticallyOnBothSides(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  string
		want bool
	}{
		{"marked", `{"executor":"agent"}`, true},
		{"mixed case value", `{"executor":"Agent"}`, true},
		{"padded value", `{"executor":"  agent  "}`, true},
		{"absent", `{"cert_path":"/etc/x"}`, false},
		{"other executor", `{"executor":"control_plane"}`, false},
		{"empty config", ``, false},
		{"unparseable", `{not json`, false},
		// A non-string value must not be coerced. `executor: true` is a config
		// error, and reading it as consent would migrate a target its operator
		// never marked.
		{"non-string value", `{"executor":true}`, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := targetExecutorIsAgent(json.RawMessage(tc.cfg))
			if got != tc.want {
				t.Errorf("server side read %q as %v, want %v", tc.cfg, got, tc.want)
			}
			// The console reads the SAME function, not a copy of it — that is
			// what makes drift impossible rather than merely detectable.
			if shared := custody.TargetExecutorIsAgent([]byte(tc.cfg)); shared != got {
				t.Errorf("the shared vocabulary reads %q as %v but the parity gate reads it as "+
					"%v; a target would be reported migrated while still receiving keys",
					tc.cfg, shared, got)
			}
		})
	}
}

// A credential-bearing deploy to an agent-executed target is refused, not
// downgraded. The refusal is the backstop behind the enqueue branch: even if a
// path is added later that mints for such a target, the key cannot ship.
func TestAKeyBearingDeployToAnAgentTargetIsRefused(t *testing.T) {
	t.Parallel()
	target := agentExecutedTarget(t)
	if err := enforceExecutorParity(target.Config, []byte("-----BEGIN PRIVATE KEY-----")); err == nil {
		t.Fatal("a deploy carrying key bytes to an agent-executed target was permitted")
	}
	// A certificate-only deploy is exactly what such a target should receive.
	if err := enforceExecutorParity(target.Config, nil); err != nil {
		t.Errorf("a certificate-only deploy to an agent-executed target was refused: %v", err)
	}
	// And an unmarked target is untouched by this feature entirely.
	if err := enforceExecutorParity(json.RawMessage(`{"cert_path":"/etc/x"}`),
		[]byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Errorf("an unmarked target's legacy deploy was refused: %v; targets that never opted "+
			"in must not change behaviour because a version shipped", err)
	}
}

// The renewal intent carries a subject binding and no credential fields.
func TestTheRenewalIntentCarriesNoCredentialFields(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(RelayDeployIntent{
		Connector: "nginx", Target: "edge-1", IdentityID: "id-1",
		SubjectCommonName: "api.example.test",
		SubjectDNSNames:   []string{"api.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"key_pem", "cert_pem", "credential_refs", "sealed"} {
		if _, present := fields[forbidden]; present {
			t.Errorf("the renewal intent carries %q; a host-generated renewal queues a binding, "+
				"not material", forbidden)
		}
	}
	// And it must carry what the agent actually needs.
	if names := signJobCSRPermittedNames(payload); len(names) != 1 || names[0] != "api.example.test" {
		t.Errorf("the queued intent does not authorize the name it was built for: %v", names)
	}
}

// The renewal actually reaches the queue (epic B2).
//
// This is the test whose absence let the whole feature ship unreachable. Every
// other B2 test exercised a piece — the job kind, the RPC, the CSR rule, the
// agent executor — and each passed. Nothing asserted that a renewal for an
// agent-executed target ever produced an endpoint.renew row, and nothing did.
//
// It asserts three things together, because any one alone would pass over the
// bug: a job IS queued, no certificate WAS minted, and no key material exists.
func TestARenewalForAnAgentExecutedTargetQueuesHostWorkAndMintsNothing(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)

	owner, err := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "Platform", Email: "p@example.test",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}

	// The realistic migration: the target starts on the legacy path, gets a
	// certificate the ordinary way, and is marked agent-executed afterwards.
	// Marking it before first issuance would exercise the first-issuance divert
	// instead, which has its own test.
	target := agentExecutedTarget(t)
	target.TenantID = h.tenant
	legacy := target
	legacy.Config = json.RawMessage(`{"cert_path":"/etc/nginx/tls.crt"}`)
	if err := h.store.UpsertDeploymentTarget(ctx, legacy); err != nil {
		t.Fatalf("upsert deployment target: %v", err)
	}

	attrs, err := json.Marshal(map[string]any{
		"deployment_target_id": target.ID,
		"connector":            target.Type,
		"target":               target.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "api.example.test", OwnerID: owner.ID,
		Attributes: attrs,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	// Initial issue still goes the ordinary way — B2 changes RENEWAL custody.
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)
	before := len(dispatcherCertificates(t, h))
	if before != 1 {
		t.Fatalf("after initial issue certificates = %d, want 1", before)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatalf("transition to deployed: %v", err)
	}
	dispatchOutbox(t, h, 1)

	// The operator marks the target agent-executed.
	if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatalf("mark target agent-executed: %v", err)
	}

	// Now renew. This is the moment custody is decided.
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "scheduled renewal"); err != nil {
		t.Fatalf("transition to renewing: %v", err)
	}
	dispatchOutbox(t, h, 1)

	// 1. A host renewal job was queued, demanding the host role.
	payload, role := queuedHostRenewal(t, ctx, h)
	if len(payload) == 0 {
		t.Fatal("no endpoint.renew job was queued for an agent-executed target; the whole " +
			"host-generated-key path is unreachable in production — an agent can execute this " +
			"work but nothing ever asks it to")
	}
	if role != mtls.AgentRoleHost {
		t.Errorf("the queued renewal demands role %q, want %q; a network relay could claim work "+
			"whose whole point is that the key is born on the serving host", role, mtls.AgentRoleHost)
	}

	// 2. It names the identity and the subject.
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatalf("queued renewal payload is not an intent: %v", err)
	}
	if intent.IdentityID != ident.ID {
		t.Errorf("queued renewal names identity %q, want %q", intent.IdentityID, ident.ID)
	}
	if len(signJobCSRPermittedNames(payload)) == 0 {
		t.Error("the queued renewal authorizes no names, so SignJobCSR would refuse every CSR " +
			"an agent built for it")
	}

	// 3. NOTHING was minted. If the control plane minted here it generated a
	// private key, and no later refusal can unmake that.
	if after := len(dispatcherCertificates(t, h)); after != before {
		t.Errorf("certificates went %d -> %d during a host-generated renewal; the control plane "+
			"minted for a target whose key is supposed to be born on the host", before, after)
	}

	// 4. And no key material rests anywhere in this tenant's tables.
	for _, f := range assertNoPrivateKeyMaterial(t, ctx, h.store, h.tenant) {
		t.Errorf("private key material in %s.%s (row %s, marker %q) after a host-generated renewal",
			f.Table, f.Column, f.RowRef, f.Marker)
	}
}

// queuedHostRenewal reads the endpoint.renew row's payload and demanded role.
//
// Reads the column directly because orchestrator.Record does not carry
// required_agent_role, and the role is half of what makes this row safe: the
// kind-level vantage map says endpoint.renew is host work, but the per-row
// demand is what the claim predicate actually evaluates against the agent's
// certificate.
func queuedHostRenewal(t *testing.T, ctx context.Context, h *issuanceDispatcherHarness) ([]byte, string) {
	t.Helper()
	var payload []byte
	var role string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		//trstctl:system-query — test-only read of this tenant's own outbox row.
		return tx.QueryRow(ctx,
			`SELECT payload, coalesce(required_agent_role, '') FROM outbox
			  WHERE tenant_id = $1 AND destination = $2
			  ORDER BY id DESC LIMIT 1`,
			h.tenant, agentJobKindEndpointRenew).Scan(&payload, &role)
	}); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, ""
		}
		t.Fatalf("read queued host renewal: %v", err)
	}
	return payload, role
}

// The renewal must not strand the identity in `renewing` (epic B2).
//
// The dispatcher hands the work off without transitioning, because there is no
// certificate yet. That makes the agent's report the ONLY thing that can close
// the loop, and if it does not, the failure is silent and permanent: the
// lifecycle scheduler will not re-renew an identity already in renewing, so the
// endpoint stops being renewed and expires while the rotation run that started
// it still reads "succeeded".
func TestAHostRenewalReportReturnsTheIdentityToDeployed(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)
	srv := &Server{orch: h.orch}

	owner, err := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "P", Email: "p@example.test",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "api.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	for _, to := range []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing,
	} {
		if err := h.orch.Transition(ctx, h.tenant, ident.ID, to, "setup"); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	payload, err := json.Marshal(RelayDeployIntent{IdentityID: ident.ID, Target: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}

	srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified)

	state, err := h.orch.State(ctx, h.tenant, ident.ID)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != orchestrator.StateDeployed {
		t.Fatalf("identity is %s after a completed host renewal, want %s; an identity left in "+
			"renewing is never renewed again, so the endpoint expires while the rotation run "+
			"still reads succeeded", state, orchestrator.StateDeployed)
	}

	// A duplicate report must be a no-op rather than forcing another transition.
	srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified)
	if again, _ := h.orch.State(ctx, h.tenant, ident.ID); again != orchestrator.StateDeployed {
		t.Errorf("a duplicate report moved the identity to %s", again)
	}
}

// A FAILED renewal must also un-stick the identity. Leaving a failed one in
// renewing produces the same silent non-renewal as leaving a successful one.
func TestAFailedHostRenewalAlsoReturnsTheIdentityToDeployed(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)
	srv := &Server{orch: h.orch}

	owner, _ := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "P", Email: "p2@example.test",
	})
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "b.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing,
	} {
		if err := h.orch.Transition(ctx, h.tenant, ident.ID, to, "setup"); err != nil {
			t.Fatal(err)
		}
	}
	payload, _ := json.Marshal(RelayDeployIntent{IdentityID: ident.ID})
	srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeFailed)

	if state, _ := h.orch.State(ctx, h.tenant, ident.ID); state != orchestrator.StateDeployed {
		t.Fatalf("a failed host renewal left the identity in %s; it would never be renewed "+
			"again", state)
	}
}

// First issuance to an agent-executed target must not mint a control-plane key
// (epic B2).
//
// handleIssue's server-keygen fallback generated a key, recorded the
// certificate, and only THEN reached enforceExecutorParity, which refused. The
// refusal was correct and useless: the key existed by then, for a target whose
// operator had explicitly opted out of receiving one.
func TestFirstIssuanceToAnAgentTargetIsDivertedNotRefused(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)

	owner, err := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "P", Email: "p3@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := agentExecutedTarget(t)
	target.TenantID = h.tenant
	if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	attrs, _ := json.Marshal(map[string]any{
		"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
	})
	// No CSR anywhere: this is the server-keygen fallback, the only case that
	// was broken. A CSR-bearing identity already has the custody B2 wants.
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "fresh.example.test", OwnerID: owner.ID,
		Attributes: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)

	if n := len(dispatcherCertificates(t, h)); n != 0 {
		t.Errorf("first issuance minted %d certificates for an agent-executed target; the "+
			"control plane generated a private key for a target that opted out of receiving "+
			"one, and refusing the deploy afterwards cannot unmake it", n)
	}
	payload, role := queuedHostRenewal(t, ctx, h)
	if len(payload) == 0 {
		t.Fatal("first issuance to an agent-executed target queued no host work, so the " +
			"identity would never get a certificate at all")
	}
	if role != mtls.AgentRoleHost {
		t.Errorf("queued role = %q, want %q", role, mtls.AgentRoleHost)
	}
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	// A first issuance replaces nothing, and must not claim to.
	if intent.PredecessorCertificateID != "" {
		t.Errorf("first issuance names predecessor %q; it replaces nothing",
			intent.PredecessorCertificateID)
	}
}

// A renewal carries its predecessor so the old certificate is superseded.
func TestAHostRenewalNamesTheCertificateItReplaces(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)

	owner, _ := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "P", Email: "p4@example.test",
	})
	target := agentExecutedTarget(t)
	target.TenantID = h.tenant
	if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	attrs, _ := json.Marshal(map[string]any{
		"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
	})
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "api.example.test", OwnerID: owner.ID,
		Attributes: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Give it a certificate the ordinary way first — an identity created before
	// its target was marked, which is exactly the migration case.
	if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
		ID: target.ID, TenantID: h.tenant, Name: target.Name, Type: target.Type,
		Enabled: true, Config: json.RawMessage(`{"cert_path":"/etc/nginx/tls.crt"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("setup produced %d certificates, want 1", len(certs))
	}

	// Now the operator marks the target agent-executed and a renewal fires.
	if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "renewal"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)

	payload, _ := queuedHostRenewal(t, ctx, h)
	if len(payload) == 0 {
		t.Fatal("no host renewal was queued")
	}
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.PredecessorCertificateID != certs[0].ID {
		t.Errorf("renewal names predecessor %q, want %q; without it the issued successor is "+
			"recorded with no ReplacesID, the old certificate is never superseded, and the "+
			"identity reads as having two active certificates",
			intent.PredecessorCertificateID, certs[0].ID)
	}
}
