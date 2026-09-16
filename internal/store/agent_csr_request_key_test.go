// SPDX-License-Identifier: MPL-2.0
package store_test

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Metadata-only SQL fixtures exercise key matching and RLS; the served regression
// separately proves actual signing, waiting and recovery with the same CSR.
func TestAgentJobCSRMatcherKeepsAuthorityAndTenantExact(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "csr-key-fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, authority, rowSuffix, otherTenant    string
		differentCSR, otherJob, otherAttempt, want bool
	}{
		{name: "same-base"},
		{name: "same-external", authority: "approved", rowSuffix: ":external-ca:approved"},
		{name: "other-base-csr", differentCSR: true, want: true},
		{name: "other-external-csr", authority: "approved", rowSuffix: ":external-ca:approved", differentCSR: true, want: true},
		{name: "other-authority", authority: "approved", rowSuffix: ":external-ca:other", want: true},
		{name: "near-authority", authority: "approved", rowSuffix: ":external-ca:approved-extra", want: true},
		{name: "platform-cannot-ignore-external", rowSuffix: ":external-ca:approved", want: true},
		{name: "other-job", differentCSR: true, otherJob: true},
		{name: "other-attempt", differentCSR: true, otherAttempt: true},
		{name: "other-tenant", differentCSR: true, otherTenant: tenantB},
		{name: "literal-authority-metacharacters", authority: "ca_%:name", rowSuffix: ":external-ca:ca_%:name"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := int64(800 + i)
			attempt := 4
			base := fmt.Sprintf("agentcsr:%d:%d:currentdigest", job, attempt)
			storedJob, storedAttempt, digest := job, attempt, "currentdigest"
			if tc.otherJob {
				storedJob += 1000
			}
			if tc.otherAttempt {
				storedAttempt++
			}
			if tc.differentCSR {
				digest = "anotherdigest"
			}
			key := fmt.Sprintf("agentcsr:%d:%d:%s%s", storedJob, storedAttempt, digest, tc.rowSuffix)
			tenant := tenantA
			if tc.otherTenant != "" {
				tenant = tc.otherTenant
			}
			err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO certificates (id,tenant_id,subject,fingerprint,issuance_idempotency_key) VALUES ($1,$2,'CN=matcher.fixture',$3,$4)`, fmt.Sprintf("00000000-0000-0000-0000-%012x", i+1), tenant, fmt.Sprintf("matcher-fingerprint-%d", i), key)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := st.AgentJobAttemptSignedOtherCSR(ctx, tenantA, job, attempt, base, tc.authority)
			if err != nil || got != tc.want {
				t.Fatalf("other CSR=%v want=%v err=%v", got, tc.want, err)
			}
		})
	}
}
