// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
)

func TestRewrapGateRefusesWithoutFleetCutover(t *testing.T) {
	s := newOperationApprovalStore(t)
	if _, err := s.BeginTenantApplicationSecretRewrap(t.Context(), tenantA, "migrate"); !errors.Is(err, store.ErrRewrapFleetCutoverUnavailable) {
		t.Fatalf("tenant rewrap without old-role cutover = %v", err)
	}
	if err := s.BeginDeploymentApplicationSecretRewrap(t.Context(),
		"a7770000-0000-4000-8000-000000009626", []string{tenantA}); !errors.Is(err, store.ErrRewrapFleetCutoverUnavailable) {
		t.Fatalf("deployment rewrap without old-role cutover = %v", err)
	}
}

func TestRewrapGateAcceptsVerifiedDisposableFleetCutover(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	operationID, err := s.BeginTenantApplicationSecretRewrap(t.Context(), tenantA, "migrate")
	if err != nil {
		t.Fatalf("tenant gate after old-login shutdown: %v", err)
	}
	if err := s.CompleteTenantApplicationSecretRewrap(t.Context(), tenantA, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplicationSecretTenantEpoch(t.Context(), tenantB); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeploymentApplicationSecretRewrap(t.Context(),
		"a7770000-0000-4000-8000-000000009627", []string{tenantA, tenantB}); err != nil {
		t.Fatalf("deployment gate after old-login shutdown: %v", err)
	}
}

// CR-045: a command's activity may already be terminal after its broker ACK
// was lost. The separate producer journal still fences both gate activation
// and key-retirement completion until publication is reconciled.
func TestRewrapGateRefusesPendingIngressJournalAfterActivityTerminalCR045(t *testing.T) {
	for _, kind := range []string{"tenant-begin", "deployment-begin", "tenant-complete", "deployment-complete"} {
		t.Run(kind, func(t *testing.T) {
			s := newOperationApprovalRewrapStore(t)
			ctx := t.Context()
			for _, tenant := range []string{tenantA, tenantB} {
				if _, err := s.ApplicationSecretTenantEpoch(ctx, tenant); err != nil {
					t.Fatal(err)
				}
			}
			const deploymentOperation = "a7770000-0000-4000-8000-000000009629"
			var tenantOperation string
			var err error
			switch kind {
			case "tenant-complete":
				tenantOperation, err = s.BeginTenantApplicationSecretRewrap(ctx, tenantA, "migrate")
			case "deployment-complete":
				err = s.BeginDeploymentApplicationSecretRewrap(ctx, deploymentOperation, []string{tenantA, tenantB})
			}
			if err != nil {
				t.Fatal(err)
			}
			pendingTenant := tenantA
			if strings.HasPrefix(kind, "deployment") {
				pendingTenant = tenantB
			}
			const journalOperation = "a7770000-0000-4000-8000-000000009630"
			if _, err := s.SystemPool().Exec(ctx, `INSERT INTO trstctl_recovery.event_ingress_journal
				(tenant_id,operation_id,event_id,event_type,producer_tenant_scope,producer_key_id,producer_mac,explicit_time)
				VALUES ($1,$2,'plain-pending-rewrap','tenant.registered',$4,'plain-journal-v1',$3,false)`,
				pendingTenant, journalOperation, bytes.Repeat([]byte{0x4a}, 32), pendingTenant); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = s.SystemPool().Exec(context.Background(),
					`DELETE FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND operation_id=$2`,
					pendingTenant, journalOperation)
			})
			switch kind {
			case "tenant-begin":
				_, err = s.BeginTenantApplicationSecretRewrap(ctx, tenantA, "migrate")
			case "deployment-begin":
				err = s.BeginDeploymentApplicationSecretRewrap(ctx, deploymentOperation, []string{tenantA, tenantB})
			case "tenant-complete":
				err = s.CompleteTenantApplicationSecretRewrap(ctx, tenantA, tenantOperation)
			case "deployment-complete":
				err = s.CompleteDeploymentApplicationSecretRewrap(ctx, deploymentOperation)
			}
			if !errors.Is(err, store.ErrRestoreActivityUnresolved) {
				t.Fatalf("%s crossed unresolved ingress journal: %v", kind, err)
			}
		})
	}
}

func TestRewrapCompletionRefusesReenabledOldLogin(t *testing.T) {
	for _, kind := range []string{"tenant", "deployment"} {
		t.Run(kind, func(t *testing.T) {
			admin := newOperationApprovalStore(t)
			fixture := storetest.ProvisionRewrapCutover(t, admin, testDSN)
			s, err := store.Open(t.Context(), fixture.DSN, store.WithRewrapFleetCutover(fixture.Cutover))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			for _, tenant := range []string{tenantA, tenantB} {
				if _, err := s.ApplicationSecretTenantEpoch(t.Context(), tenant); err != nil {
					t.Fatal(err)
				}
			}
			operationID := "a7770000-0000-4000-8000-000000009628"
			if kind == "tenant" {
				operationID, err = s.BeginTenantApplicationSecretRewrap(t.Context(), tenantA, "migrate")
			} else {
				err = s.BeginDeploymentApplicationSecretRewrap(t.Context(), operationID, []string{tenantA, tenantB})
			}
			if err != nil {
				t.Fatal(err)
			}
			oldRole := pgx.Identifier{fixture.Cutover.OldLoginRole}.Sanitize()
			if _, err := admin.SystemPool().Exec(t.Context(), "ALTER ROLE "+oldRole+" LOGIN"); err != nil {
				t.Fatal(err)
			}
			complete := func() error {
				if kind == "tenant" {
					return s.CompleteTenantApplicationSecretRewrap(t.Context(), tenantA, operationID)
				}
				return s.CompleteDeploymentApplicationSecretRewrap(t.Context(), operationID)
			}
			if err := complete(); !errors.Is(err, store.ErrRewrapFleetCutoverUnavailable) {
				t.Fatalf("completion after old login reenabled = %v", err)
			}
			gate, found, err := s.GetTenantApplicationSecretRewrapGate(t.Context(), tenantA)
			if err != nil || !found || !gate.InProgress {
				t.Fatalf("refused completion released gate: %+v found=%t err=%v", gate, found, err)
			}
			if _, err := admin.SystemPool().Exec(t.Context(), "ALTER ROLE "+oldRole+" NOLOGIN"); err != nil {
				t.Fatal(err)
			}
			if err := complete(); err != nil {
				t.Fatalf("completion after old login disabled: %v", err)
			}
		})
	}
}

func newOperationApprovalRewrapStore(t *testing.T) *store.Store {
	t.Helper()
	admin := newOperationApprovalStore(t)
	return storetest.OpenRewrapCutoverStore(t, admin, testDSN)
}

// CR-045: SQL, rather than an upgraded process alone, must stop an older
// projector from recording a v1-only receipt after a tenant rewraps.
func TestApplicationSecretRewrapGateBlocksOldAndPausedReceiptWriters(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	const operation = "a7770000-0000-4000-8000-000000009601"
	setGate := func(inProgress, v2Required bool) error {
		_, err := s.SystemPool().Exec(ctx, `INSERT INTO application_secret_rewrap_gates
				(tenant_id,tenant_epoch,operation_id,rewrap_in_progress,v2_required)
				VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (tenant_id) DO UPDATE SET
				  rewrap_in_progress=EXCLUDED.rewrap_in_progress,
				  v2_required=EXCLUDED.v2_required`,
			tenantA, epoch, operation, inProgress, v2Required)
		return err
	}
	insertReceipt := func(id string, v2 bool) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			var digest any
			if v2 {
				digest = strings.Repeat("c", 64)
			}
			_, err := tx.Exec(ctx, `INSERT INTO application_secret_mutation_receipts
				(tenant_id,event_id,semantic_sha256,semantic_sha256_v2,request_binding,
				 secret_name,action,result_version,result_created_at,result_updated_at,applied_at)
				VALUES ($1,$2,$3,$4,$5,'rewrap/gate','create',1,now(),now(),now())`,
				tenantA, id, strings.Repeat("a", 64), digest, strings.Repeat("b", 64))
			return err
		})
	}
	if err := setGate(true, true); err != nil {
		t.Fatalf("arm tenant gate: %v", err)
	}
	if err := insertReceipt("a7770000-0000-4000-8000-000000009602", false); err == nil {
		t.Fatal("v1-only receipt committed while rewrap was armed")
	}
	if err := insertReceipt("a7770000-0000-4000-8000-000000009603", true); err == nil {
		t.Fatal("new v2 receipt committed while rewrap was armed")
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "rewrap/gate-command", Operation: "create",
		EventID: "a7770000-0000-4000-8000-000000009606", EventType: "secret.created",
		SchemaVersion: 2, RequestBinding: strings.Repeat("b", 64),
		Payload: []byte(`{"action":"create","sealed":"test-container"}`),
	}); err == nil {
		t.Fatal("pending secret command committed while rewrap was armed")
	}
	if err := setGate(false, true); err != nil {
		t.Fatalf("complete tenant gate: %v", err)
	}
	if err := insertReceipt("a7770000-0000-4000-8000-000000009604", false); err == nil {
		t.Fatal("v1-only receipt committed after rewrap completed")
	}
	if err := insertReceipt("a7770000-0000-4000-8000-000000009605", true); err != nil {
		t.Fatalf("v2 receipt after rewrap completed: %v", err)
	}
}

func TestTenantRewrapCompletionWaitsForOrphanedProofCommitB(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	operationID, err := s.BeginTenantApplicationSecretRewrap(ctx, tenantA, "migrate")
	if err != nil {
		t.Fatal(err)
	}
	var proofTx pgx.Tx
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		var beginErr error
		proofTx, beginErr = s.SystemPool().Begin(admitted)
		if beginErr != nil {
			return beginErr
		}
		return s.LockGlobalKeyStateCommitTx(admitted, proofTx, store.KeyStateShared)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proofTx.Rollback(context.Background()) })
	completed := make(chan error, 1)
	go func() { completed <- s.CompleteTenantApplicationSecretRewrap(ctx, tenantA, operationID) }()
	select {
	case err := <-completed:
		t.Fatalf("tenant rewrap completion crossed uncommitted proof: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	if err := proofTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("complete after proof transaction ended: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("tenant completion did not finish after proof transaction ended")
	}
}

func TestRewrapCoordinatorOwnRestoreActivityCanArmItsGate(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	ctx := t.Context()
	if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	err := s.WithRestoreActivity(ctx, tenantA, "a7770000-0000-4000-8000-000000009621",
		"maintenance", "tenant-domain-migrate", func(admitted context.Context) error {
			return s.WithGlobalKeyStateAdmission(admitted, store.KeyStateExclusive, func(locked context.Context) error {
				operationID, err := s.BeginTenantApplicationSecretRewrap(locked, tenantA, "migrate")
				if err != nil {
					return err
				}
				return s.CompleteTenantApplicationSecretRewrap(locked, tenantA, operationID)
			})
		})
	if err != nil {
		t.Fatalf("coordinator's own durable activity blocked its gate: %v", err)
	}
}

func TestRestoreMarkerRefusesArmedTenantRewrapGateBetweenSteps(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	ctx := t.Context()
	if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginTenantApplicationSecretRewrap(ctx, tenantA, "rotate"); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "a7770000-0000-4000-8000-000000009622",
		ArtifactSHA256: strings.Repeat("d", 64), EventCut: 1, DeploymentID: "rewrap-gate-restore-check",
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 AND operation_id=$2`,
			store.RestoreControlTenantID, marker.OperationID)
	})
	if err := s.BeginFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreActivityUnresolved) {
		t.Fatalf("restore marker crossed a durable rewrap gate between steps: %v", err)
	}
}

// CR-045: a deployment rotation must not arm one tenant and continue when a
// second tenant still has a pending application-secret command.
func TestDeploymentRewrapGateActivationIsAtomicAcrossTenants(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	ctx := context.Background()
	for _, tenantID := range []string{tenantA, tenantB} {
		if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	const operation = "a7770000-0000-4000-8000-000000009611"
	const name = "rewrap/pending-second-tenant"
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantB, Name: name, Operation: "create",
		EventID: "a7770000-0000-4000-8000-000000009612", EventType: "secret.created",
		SchemaVersion: 2, RequestBinding: strings.Repeat("b", 64),
		Payload: []byte(`{"action":"create","sealed":"test-container"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeploymentApplicationSecretRewrap(ctx, operation, []string{tenantB, tenantA}); !errors.Is(err, store.ErrApplicationSecretRewrapPendingCommand) {
		t.Fatalf("pending second tenant allowed deployment gate: %v", err)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		if _, found, err := s.GetTenantApplicationSecretRewrapGate(ctx, tenantID); err != nil || found {
			t.Fatalf("failed deployment gate left a tenant armed: tenant=%s found=%t err=%v", tenantID, found, err)
		}
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM application_secret_mutation_fences WHERE tenant_id=$1 AND secret_name=$2`, tenantB, name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeploymentApplicationSecretRewrap(ctx, operation, []string{tenantB, tenantA}); err != nil {
		t.Fatalf("settled deployment gate: %v", err)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		gate, found, err := s.GetTenantApplicationSecretRewrapGate(ctx, tenantID)
		if err != nil || !found || !gate.InProgress || !gate.V2Required || gate.OperationID != operation {
			t.Fatalf("tenant deployment gate=%+v found=%t err=%v", gate, found, err)
		}
	}
	if err := s.CompleteDeploymentApplicationSecretRewrap(ctx, operation); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		gate, found, err := s.GetTenantApplicationSecretRewrapGate(ctx, tenantID)
		if err != nil || !found || gate.InProgress || !gate.V2Required || gate.Generation != 1 {
			t.Fatalf("completed deployment gate=%+v found=%t err=%v", gate, found, err)
		}
	}
}

func TestDeploymentRewrapGateCoversRegistrationRaceAndExactInventory(t *testing.T) {
	s := newOperationApprovalRewrapStore(t)
	ctx := context.Background()
	const newcomer = "a7770000-0000-4000-8000-000000009621"
	const operation = "a7770000-0000-4000-8000-000000009622"
	for _, id := range []string{tenantA, tenantB} {
		if _, err := s.ApplicationSecretTenantEpoch(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.BeginDeploymentApplicationSecretRewrap(ctx, operation, []string{tenantA, tenantB}); err != nil {
		t.Fatalf("arm inventoried tenants: %v", err)
	}
	register := func() error {
		return s.UpsertTenant(ctx, store.Tenant{TenantID: newcomer, Name: "rewrap-newcomer",
			CreatedAt: time.Now().UTC(), EventSeq: 1})
	}
	if err := register(); err == nil {
		t.Fatal("tenant registered while the deployment inventory was frozen")
	}
	appErr := s.WithTenant(ctx, newcomer, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenants (tenant_id,name,event_seq)
			VALUES ($1,'rewrap-app-role',1)`, newcomer)
		return err
	})
	if appErr == nil || !strings.Contains(appErr.Error(), "tenant registration waits for deployment key rewrap") {
		t.Fatalf("app-role registration during another tenant's deployment gate=%v, want global gate refusal", appErr)
	}
	if err := s.CompleteDeploymentApplicationSecretRewrap(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := register(); err != nil {
		t.Fatalf("registration after deployment gate completion: %v", err)
	}
	if _, err := s.ApplicationSecretTenantEpoch(ctx, newcomer); err != nil {
		t.Fatal(err)
	}
	const nextOperation = "a7770000-0000-4000-8000-000000009623"
	if err := s.BeginDeploymentApplicationSecretRewrap(ctx, nextOperation, []string{tenantA, tenantB}); err == nil {
		t.Fatal("stale deployment inventory omitted a newly registered tenant")
	}
}

// A broker publish whose database session vanished is not proof that no event
// was written. Its durable start must block either rewrap coordinator.
func TestRewrapGateRefusesUnresolvedTenantIngressStart(t *testing.T) {
	for _, kind := range []string{"tenant", "deployment"} {
		t.Run(kind, func(t *testing.T) {
			s := newOperationApprovalRewrapStore(t)
			ctx := context.Background()
			for _, tenantID := range []string{tenantA, tenantB} {
				if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantID); err != nil {
					t.Fatal(err)
				}
			}
			const operation = "a7770000-0000-4000-8000-000000009624"
			const gateOperation = "a7770000-0000-4000-8000-000000009625"
			err := s.WithRestoreActivity(ctx, tenantA, operation, "ingress", "event-append",
				func(context.Context) error { return errors.New("broker outcome unknown") })
			if err == nil {
				t.Fatal("ambiguous ingress returned success")
			}
			t.Cleanup(func() {
				_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM trstctl_recovery.restore_activity_tokens
					WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation)
			})
			if kind == "tenant" {
				_, err = s.BeginTenantApplicationSecretRewrap(ctx, tenantA, "migrate")
			} else {
				err = s.BeginDeploymentApplicationSecretRewrap(ctx, gateOperation, []string{tenantA, tenantB})
			}
			if !errors.Is(err, store.ErrRestoreActivityUnresolved) {
				t.Errorf("%s rewrap with unresolved ingress=%v, want refusal", kind, err)
			}
		})
	}
}
