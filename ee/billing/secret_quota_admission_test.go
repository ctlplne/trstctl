// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

func seedQuotaSecret(t *testing.T, st *corestore.Store, tenantID, name string) {
	t.Helper()
	if err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO secret_store (tenant_id,name,sealed,version)
			VALUES ($1,$2,$3,1)`, tenantID, name, []byte("sealed-test-ciphertext"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoredSecretQuotaCountsApplicationAndConnectorSecrets(t *testing.T) {
	pg, st := newBillingStoreOn(t, "billing_secret_stock")
	seedBillingRegistration(t, st, quotaTenant)
	seedBillingRegistration(t, st, otherTenant)
	seedQuotaSecret(t, st, quotaTenant, "native-and-vault-stock")
	seedQuotaSecret(t, st, otherTenant, "foreign-stock")
	// This test owns the stock query, not the credential writer. Seed its
	// projection directly so a process-global quota checker from another
	// installation cannot affect the fixture.
	if err := st.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO credentials (id,tenant_id,scope,ref,name,sealed)
			VALUES (gen_random_uuid(),$1,'connector','target-a','password',$2)`, quotaTenant, []byte("sealed-test-ciphertext"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	counts, err := billing.StoreTenantCounter(st)(t.Context(), quotaTenant)
	if err != nil || counts[usage.MeterSecretsStored] != 2 {
		t.Fatalf("tenant stored-secret gauge = %v, err %v; want two distinct stored objects", counts, err)
	}
	foreign, err := billing.StoreTenantCounter(st)(t.Context(), otherTenant)
	if err != nil || foreign[usage.MeterSecretsStored] != 1 {
		t.Fatalf("foreign tenant stored-secret gauge = %v, err %v", foreign, err)
	}
	limit := 2
	seedQuota(t, st, billing.Quota{TenantID: quotaTenant, MaxSecretsStored: &limit})
	checker := billing.NewQuotaChecker(pg, billing.StoreTenantAdmissionCounter(st), time.Minute)
	if err := checker.AllowCreate(t.Context(), quotaTenant, usage.MeterSecretsStored); !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("two stored objects bypassed cap two: %v", err)
	}
}

func TestStoredSecretQuotaReservesCrashWindowWithoutInflatingSignedGauge(t *testing.T) {
	pg, st := newBillingStoreOn(t, "billing_secret_reservation")
	seedBillingRegistration(t, st, quotaTenant)
	seedQuotaSecret(t, st, quotaTenant, "existing")
	limit := 2
	seedQuota(t, st, billing.Quota{TenantID: quotaTenant, MaxSecretsStored: &limit})
	checker := billing.NewQuotaChecker(pg, billing.StoreTenantAdmissionCounter(st), time.Minute)
	if err := checker.AllowCreate(t.Context(), quotaTenant, usage.MeterSecretsStored); err != nil {
		t.Fatalf("one of two slots refused before reservation: %v", err)
	}
	const pendingName = "pending-append"
	if err := st.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO application_secret_mutation_fences
			(tenant_id,secret_name,operation,event_id,event_type,schema_version,approval_required,
			 request_binding,command_payload,payload_sha256,event_time)
			VALUES ($1,$2,'create',$3,'secret.created',1,false,$4,$5,$6,now())`,
			quotaTenant, pendingName, "55555555-5555-5555-5555-555555555555",
			strings.Repeat("a", 64), []byte("sealed-command"), strings.Repeat("b", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	actual, err := billing.StoreTenantCounter(st)(t.Context(), quotaTenant)
	if err != nil || actual[usage.MeterSecretsStored] != 1 {
		t.Fatalf("signed stored-secret gauge counted an unmaterialized command: %v, err %v", actual, err)
	}
	if err := checker.AllowCreate(t.Context(), quotaTenant, usage.MeterSecretsStored); !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("crash-window reservation bypassed cap: %v", err)
	}
	seedQuotaSecret(t, st, quotaTenant, pendingName)
	admitted, err := billing.StoreTenantAdmissionCounter(st)(t.Context(), quotaTenant)
	if err != nil || admitted[usage.MeterSecretsStored] != 2 {
		t.Fatalf("materialized command double counted with its fence: %v, err %v", admitted, err)
	}
}

func TestStoredSecretQuotaCreationFenceSerializesReplicas(t *testing.T) {
	firstPG, first := newBillingStoreOn(t, "billing_secret_replica")
	seedBillingRegistration(t, first, quotaTenant)
	second, err := corestore.Open(t.Context(), strings.TrimSuffix(billingTestDSN, "/postgres")+"/billing_secret_replica",
		corestore.WithPoolSizes(corestore.PoolSizes{Lock: 1}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	limit := 1
	seedQuota(t, first, billing.Quota{TenantID: quotaTenant, MaxSecretsStored: &limit})
	firstChecker := billing.NewQuotaChecker(firstPG, billing.StoreTenantAdmissionCounter(first), time.Minute)
	secondChecker := billing.NewQuotaChecker(billing.NewPGStore(second), billing.StoreTenantAdmissionCounter(second), time.Minute)
	err = firstChecker.WithCreationFence(t.Context(), quotaTenant, usage.MeterSecretsStored, func(work context.Context) error {
		if err := firstChecker.AllowCreate(work, quotaTenant, usage.MeterSecretsStored); err != nil {
			return err
		}
		called := false
		racingErr := secondChecker.WithCreationFence(t.Context(), quotaTenant, usage.MeterSecretsStored, func(context.Context) error {
			called = true
			return nil
		})
		if !errors.Is(racingErr, corestore.ErrResourceAdmissionBusy) || called {
			t.Fatalf("racing replica admitted same final slot: %v, called=%t", racingErr, called)
		}
		return first.WithTenant(work, quotaTenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(work, `INSERT INTO secret_store (tenant_id,name,sealed,version)
				VALUES ($1,'first-winner',$2,1)`, quotaTenant, []byte("sealed-test-ciphertext"))
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = secondChecker.WithCreationFence(t.Context(), quotaTenant, usage.MeterSecretsStored, func(work context.Context) error {
		return secondChecker.AllowCreate(work, quotaTenant, usage.MeterSecretsStored)
	})
	if !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("next replica after first commit = %v, want quota refusal", err)
	}
}

func TestConnectorCredentialFirstWriteRespectsStoredSecretQuota(t *testing.T) {
	pg, st := newBillingStoreOn(t, "billing_connector_secret_gate")
	seedBillingRegistration(t, st, quotaTenant)
	zero := 0
	seedQuota(t, st, billing.Quota{TenantID: quotaTenant, MaxSecretsStored: &zero})
	usage.SetQuotaChecker(billing.NewQuotaChecker(pg, billing.StoreTenantAdmissionCounter(st), time.Minute))
	t.Cleanup(func() { usage.SetQuotaChecker(nil) })
	credential := corestore.Credential{
		TenantID: quotaTenant, Scope: "connector", Ref: "target-a", Name: "password",
		Sealed: []byte("first-sealed-value"),
	}
	if err := st.PutCredential(t.Context(), credential); !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("new connector credential bypassed zero cap: %v", err)
	}
	if _, err := st.GetCredential(t.Context(), quotaTenant, credential.Scope, credential.Ref, credential.Name); !errors.Is(err, corestore.ErrCredentialNotFound) {
		t.Fatalf("refused connector credential materialized: %v", err)
	}
	setLimit := func(limit int) {
		t.Helper()
		if err := st.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE provider_tenant_quotas SET max_secrets_stored=$2
				WHERE tenant_id=$1`, quotaTenant, limit)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setLimit(1)
	if err := st.PutCredential(t.Context(), credential); err != nil {
		t.Fatalf("first connector credential under cap: %v", err)
	}
	setLimit(0)
	credential.Sealed = []byte("rotated-sealed-value")
	if err := st.PutCredential(t.Context(), credential); err != nil {
		t.Fatalf("existing connector credential update under reduced cap: %v", err)
	}
	got, err := st.GetCredential(t.Context(), quotaTenant, credential.Scope, credential.Ref, credential.Name)
	if err != nil || !bytes.Equal(got.Sealed, credential.Sealed) {
		t.Fatalf("credential update did not survive cap reduction: err=%v", err)
	}
	credential.Ref = "target-b"
	if err := st.PutCredential(t.Context(), credential); !errors.Is(err, usage.ErrQuotaExhausted) {
		t.Fatalf("second connector credential bypassed reduced cap: %v", err)
	}
}
