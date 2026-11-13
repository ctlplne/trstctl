// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

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
		"dynamic_secret_leases.sealed_preparation",
		"dynamic_secret_leases.sealed_credential",
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
