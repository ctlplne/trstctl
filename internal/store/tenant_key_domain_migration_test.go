// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

func TestTenantKeyDomainCiphertextMigrationStagesAreFixed(t *testing.T) {
	want := []string{
		"credentials.sealed",
		"secret_store.sealed",
		"secret_store_versions.sealed",
		"secret_store_tombstone_versions.sealed",
		"secret_shares.sealed",
		"vault_cubbyhole.sealed",
		"slack_installs.sealed_bot_token",
		"pam_recording_uploads.sealed",
		"dynamic_secret_leases.sealed_preparation",
		"dynamic_secret_leases.sealed_credential",
		"dynamic_secret_leases.revocation_sealed_credential",
		"secret_static_rotation_commands.sealed_new",
		"secret_static_rotation_commands.sealed_old",
		"secret_static_rotation_commands.sealed_preparation",
		"code_signing_operations.sealed_command",
		"idempotency_keys.result",
		"outbox.payload",
		"transit_keyrings.sealed",
	}
	if got := store.TenantKeyDomainCiphertextMigrationStages(); !reflect.DeepEqual(got, want) {
		t.Fatalf("migration stages = %v, want %v", got, want)
	}
	got := store.TenantKeyDomainCiphertextMigrationStages()
	got[0] = "mutated"
	if store.TenantKeyDomainCiphertextMigrationStages()[0] != want[0] {
		t.Fatal("caller mutated the tenant ciphertext inventory")
	}
}

// A new sealed bytea column must be included in tenant migration, tenant
// rotation, and deployment KEK verification before old keys can be retired.
func TestCR031EverySealedPostgresColumnHasRewrapStage(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	rows, err := st.SystemPool().Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type = 'bytea'
		AND (column_name = 'sealed' OR column_name LIKE 'sealed_%' OR column_name LIKE '%_sealed_%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, stage := range store.TenantKeyDomainCiphertextMigrationStages() {
		want[stage] = true
	}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		if !want[table+"."+column] {
			t.Errorf("sealed column %s.%s has no key-domain rewrap/verify stage", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestCR031StagedRecordingRewrapUpdatesSealedDigest(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "cr031-recording"}); err != nil {
		t.Fatal(err)
	}
	deployment := migrationTestKEK(t, 0x81)
	next := migrationTestKEK(t, 0x82)
	domain := []byte("tenant-key-domain:cr031")
	aad := []byte("recording-place:cr031")
	plain := []byte(`{"t":0,"d":"whoami"}`)
	sealed, err := seal.Seal(deployment, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid(tenantA, 310)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pam_recording_uploads
			(tenant_id,session_id,attempt,seq,ord,gateway_agent_id,sha256,sealed_sha256,chain,size,final,sealed,staged_at)
			VALUES ($1,$2,1,0,0,$3,$4,$5,$4,$6,false,$7,now())`,
			tenantA, sessionID, uuid(tenantA, 311), crypto.SHA256Hex(plain), crypto.SHA256Hex(sealed), len(plain), sealed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, next, domain)
	if err != nil {
		t.Fatal(err)
	}
	const stage = "pam_recording_uploads.sealed"
	changed, err := st.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, stage,
		func(before []byte) ([]byte, bool, error) { return rewriter.Transform("postgres."+stage, 1, before) })
	if err != nil || changed != 1 {
		t.Fatalf("staged recording rewrap changed=%d err=%v, want 1/nil", changed, err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var current []byte
		var digest string
		if err := tx.QueryRow(ctx, `SELECT sealed,sealed_sha256 FROM pam_recording_uploads WHERE tenant_id=$1 AND session_id=$2`, tenantA, sessionID).Scan(&current, &digest); err != nil {
			return err
		}
		if digest != crypto.SHA256Hex(current) {
			t.Fatal("staged upload digest still describes the pre-rewrap bytes")
		}
		opened, err := seal.OpenDomain(next, current, aad, domain)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("staged recording did not open after rewrap: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCR030SlackBotTokenRewrapsBeforeOldKEKRetires(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	const teamID = "TCR030"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "cr030-slack"}); err != nil {
		t.Fatal(err)
	}
	deployment := migrationTestKEK(t, 0x71)
	next := migrationTestKEK(t, 0x72)
	domain := []byte("tenant-key-domain:cr030")
	aad := []byte("trstctl/slack-bot-token/v1\x00" + tenantA + "\x00" + teamID)
	sealed, err := seal.Seal(deployment, []byte("xoxb-test-token"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO slack_installs
			(tenant_id, team_id, bot_user_id, sealed_bot_token, installed_by, installed_at, updated_at, event_sequence)
			VALUES ($1,$2,'UCR030',$3,'cr030-operator',now(),now(),1)`, tenantA, teamID, sealed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, next, domain)
	if err != nil {
		t.Fatal(err)
	}
	const stage = "slack_installs.sealed_bot_token"
	changed, err := st.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, stage,
		func(before []byte) ([]byte, bool, error) { return rewriter.Transform("postgres."+stage, 1, before) })
	if err != nil || changed != 1 {
		t.Fatalf("Slack token rewrap changed=%d err=%v, want 1/nil", changed, err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var current []byte
		if err := tx.QueryRow(ctx, `SELECT sealed_bot_token FROM slack_installs WHERE tenant_id=$1`, tenantA).Scan(&current); err != nil {
			return err
		}
		opened, err := seal.OpenDomain(next, current, aad, domain)
		if err != nil || !bytes.Equal(opened, []byte("xoxb-test-token")) {
			t.Fatalf("Slack bot token did not open after old KEK retirement: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCR029PendingRevocationCredentialRewrapsUnderTenantFence(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	deployment := migrationTestKEK(t, 0x61)
	domainKey := migrationTestKEK(t, 0x62)
	domain := []byte("tenant-key-domain:cr029")
	aad := []byte("dynamic-secret:revocation:cr029")
	original, err := seal.Seal(deployment, []byte("oauth-token-to-revoke"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for index, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO dynamic_secret_leases
				(tenant_id,id,tenant_epoch,idempotency_key,request_binding,provider,role,backend_ref,
				sealed_credential,revocation_sealed_credential,state,issue_outbox_id,
				revocation_status,revoke_outbox_id,issued_at,expires_at,hard_expires_at,revoked_at,updated_at)
				VALUES ($1,$2,'cr029-epoch',$3,$3,'oauth','reader','provider-token',
				''::bytea,$4,'revoked',2901,'pending',2902,now(),now()+interval '1 hour',
				now()+interval '2 hours',now(),now())`, tenant, uuid(tenant, index+290), "cr029-"+tenant, original)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, domainKey, domain)
	if err != nil {
		t.Fatal(err)
	}
	const stage = "dynamic_secret_leases.revocation_sealed_credential"
	for pass, want := range []int64{1, 0} {
		changed, err := st.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, stage,
			func(before []byte) ([]byte, bool, error) {
				return rewriter.Transform("postgres."+stage, 1, before)
			})
		if err != nil || changed != want {
			t.Fatalf("pass %d rewrap changed=%d err=%v, want %d/nil", pass, changed, err, want)
		}
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			var current []byte
			if err := tx.QueryRow(ctx, `SELECT revocation_sealed_credential FROM dynamic_secret_leases
				WHERE tenant_id=$1 AND provider='oauth'`, tenant).Scan(&current); err != nil {
				return err
			}
			if tenant == tenantB {
				if !bytes.Equal(current, original) {
					t.Fatal("other tenant's pending provider credential changed")
				}
				return nil
			}
			opened, err := seal.OpenDomain(domainKey, current, aad, domain)
			if err != nil || !bytes.Equal(opened, []byte("oauth-token-to-revoke")) {
				t.Fatalf("provider revocation credential did not open after rewrap: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDirectTenantCiphertextStageRefusesFullRestore(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "restore-stage-tenant"}); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID: "11111111-1111-4111-8111-111111111802", ArtifactSHA256: strings.Repeat("e", 64),
		EventCut: 1, DeploymentID: "stage-restore-order",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 AND operation_id=$2`,
			store.RestoreControlTenantID, marker.OperationID)
	})
	if _, err := s.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, "credentials.sealed",
		func(before []byte) ([]byte, bool, error) { return before, false, nil }); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("direct ciphertext stage under restore marker = %v, want refusal", err)
	}
}

func TestTenantKeyDomainCiphertextMigrationIsRLSScopedAndResumable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantID}); err != nil {
			t.Fatal(err)
		}
	}
	deployment := migrationTestKEK(t, 0x41)
	domainKey := migrationTestKEK(t, 0x42)
	domain := []byte("tenant=11111111-1111-1111-1111-111111111111;domain=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;generation=1")
	aad := []byte("credential:aad")
	legacy, err := seal.Seal(deployment, []byte("credential-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	nested, err := json.Marshal(map[string]any{"sealed": legacy, "public": "unchanged"})
	if err != nil {
		t.Fatal(err)
	}
	for index, tenantID := range []string{tenantA, tenantB} {
		err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
				 VALUES ($1, $2, 'connector', 'target', 'token', $3)`,
				uuid(tenantID, index+80), tenantID, legacy); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
				 VALUES ($1, 'connector.deploy', $2, $3)`,
				tenantID, nested, "migration-"+tenantID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, domainKey, domain)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"credentials.sealed", "outbox.payload"} {
		changed, err := s.RewriteTenantKeyDomainCiphertextStage(
			ctx, tenantA, stage,
			func(before []byte) ([]byte, bool, error) {
				return rewriter.Transform("postgres."+stage, 1, before)
			},
		)
		if err != nil {
			t.Fatalf("rewrite %s: %v", stage, err)
		}
		if changed != 1 {
			t.Fatalf("rewrite %s changed %d rows, want 1", stage, changed)
		}
		changed, err = s.RewriteTenantKeyDomainCiphertextStage(
			ctx, tenantA, stage,
			func(before []byte) ([]byte, bool, error) {
				return rewriter.Transform("postgres."+stage, 1, before)
			},
		)
		if err != nil || changed != 0 {
			t.Fatalf("resumed rewrite %s changed=%d err=%v, want 0/nil", stage, changed, err)
		}
	}

	for _, tenantID := range []string{tenantA, tenantB} {
		err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var credential, payload []byte
			if err := tx.QueryRow(ctx,
				`SELECT sealed FROM credentials WHERE tenant_id = $1 AND name = 'token'`, tenantID).
				Scan(&credential); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx,
				`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
				tenantID, "migration-"+tenantID).Scan(&payload); err != nil {
				return err
			}
			if tenantID == tenantB {
				if !bytes.Equal(credential, legacy) || !bytes.Equal(payload, nested) {
					t.Fatal("tenant B ciphertext changed during tenant A migration")
				}
				return nil
			}
			if err := seal.ValidateDomain(domainKey, credential, domain); err != nil {
				t.Fatalf("tenant A credential domain: %v", err)
			}
			var body struct {
				Sealed []byte `json:"sealed"`
				Public string `json:"public"`
			}
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatal(err)
			}
			if body.Public != "unchanged" {
				t.Fatal("tenant A outbox public data changed")
			}
			if err := seal.ValidateDomain(domainKey, body.Sealed, domain); err != nil {
				t.Fatalf("tenant A outbox domain: %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func migrationTestKEK(t *testing.T, fill byte) *seal.LocalKEK {
	t.Helper()
	key, err := seal.NewLocalKEK(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func TestStaticPreparationCiphertextDomainMigrationA267(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	deployment := migrationTestKEK(t, 0x51)
	domainKey := migrationTestKEK(t, 0x52)
	domain := []byte("owned-native-static-preparation-domain")
	original, err := seal.Seal(deployment, []byte("owned-native-preparation"), []byte("native-preparation-aad"))
	if err != nil {
		t.Fatal(err)
	}
	for index, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO secret_static_rotation_commands (tenant_id,id,tenant_epoch,provider,secret_key,old_ref,phase,idempotency_key_digest,request_binding,created_at,updated_at,provider_binding,sealed_preparation,sealed_old) VALUES ($1,$2,'owned','directory','service','owned-account','prepared',$3,$3,now(),now(),$3,$4,$4)`, tenant, uuid(tenant, index+191), strings.Repeat("a", 64), original)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, domainKey, domain)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		changed, err := st.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, "secret_static_rotation_commands.sealed_preparation", func(before []byte) ([]byte, bool, error) {
			return rewriter.Transform("postgres.secret_static_rotation_commands.sealed_preparation", 1, before)
		})
		if err != nil || changed != int64(1-n) {
			t.Fatalf("native preparation domain migration changed=%d err=%v", changed, err)
		}
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			var current []byte
			if err := tx.QueryRow(ctx, `SELECT sealed_preparation FROM secret_static_rotation_commands WHERE tenant_id=$1 AND secret_key='service'`, tenant).Scan(&current); err != nil {
				return err
			}
			if tenant == tenantB {
				if !bytes.Equal(current, original) {
					t.Fatal("foreign tenant native preparation changed")
				}
				return nil
			}
			return seal.ValidateDomain(domainKey, current, domain)
		}); err != nil {
			t.Fatal(err)
		}
	}
}
