// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestSCIMIdentifiersAreExportedAndRemovedByPrivacy(t *testing.T) {
	for _, mode := range []string{"erasure", "retention"} {
		t.Run(mode, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			const subject = "privacy-opaque-subject"
			for _, tenant := range []string{tenantA, tenantB} {
				if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
					t.Fatal(err)
				}
				at := time.Now().UTC().AddDate(-10, 0, 0)
				if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
					return s.ApplyTenantMemberOffboardedTx(ctx, tx, store.TenantMember{TenantID: tenant, Subject: subject, UpdatedAt: at, SCIM: &store.SCIMIdentity{UserName: "private-alias@example.test", ExternalID: subject, SubjectAttribute: "externalId"}})
				}); err != nil {
					t.Fatal(err)
				}
			}
			exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
			if err != nil || len(exported.Members) != 1 || exported.Members[0].SCIM == nil || exported.Members[0].SCIM.UserName != "private-alias@example.test" {
				t.Fatalf("SCIM export=%+v err=%v", exported.Members, err)
			}
			if mode == "erasure" {
				plan, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, plan) }); err != nil {
					t.Fatal(err)
				}
			} else {
				plan, err := s.SelectPrivacyRetention(ctx, tenantA, uuid(tenantA, 2200), privacy.DefaultRetentionPolicy(), time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, plan) }); err != nil {
					t.Fatal(err)
				}
			}
			member, err := s.GetTenantMember(ctx, tenantA, privacy.Placeholder(privacy.SubjectRef(tenantA, subject)))
			if err != nil || member.SCIM != nil || member.Status != "offboarded" {
				t.Fatalf("privacy left identifiers/access: %+v err=%v", member, err)
			}
			other, err := s.GetTenantMember(ctx, tenantB, subject)
			if err != nil || other.SCIM == nil || other.SCIM.ExternalID != subject {
				t.Fatalf("privacy touched other tenant: %+v err=%v", other, err)
			}
		})
	}
}

// An API's inline projector and the durable tail can apply one event together.
// Replays with the same subject and SCIM alias must converge for both creation
// and inactive-first provisioning, while the other tenant remains independent.
func TestSCIMMemberSimultaneousProjectionConverges(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("inactive=%t", inactive), func(t *testing.T) {
			s := newStore(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)
			for _, tenant := range []string{tenantA, tenantB} {
				if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
					t.Fatal(err)
				}
			}
			const writers = 12
			for round := 0; round < 20; round++ {
				subject := fmt.Sprintf("replayed-subject-%d", round)
				at := time.Now().UTC().Truncate(time.Microsecond)
				member := store.TenantMember{Subject: subject, DisplayName: "Replay", Source: "scim", CreatedAt: at, UpdatedAt: at,
					SCIM: &store.SCIMIdentity{UserName: subject + "@example.test", ExternalID: subject, SubjectAttribute: "externalId"}}
				start := make(chan struct{})
				errs := make(chan error, writers)
				var wg sync.WaitGroup
				for i := 0; i < writers; i++ {
					m := member
					m.TenantID = []string{tenantA, tenantB}[i%2]
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						errs <- s.WithTenant(ctx, m.TenantID, func(tx pgx.Tx) error {
							if inactive {
								return s.ApplyTenantMemberOffboardedTx(ctx, tx, m)
							}
							return s.ApplyTenantMemberUpsertedTx(ctx, tx, m)
						})
					}()
				}
				close(start)
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						t.Fatalf("round %d: replay did not converge: %v", round, err)
					}
				}
				for _, tenant := range []string{tenantA, tenantB} {
					got, err := s.GetTenantMember(ctx, tenant, subject)
					status := "active"
					if inactive {
						status = "offboarded"
					}
					if err != nil || got.Status != status || got.SCIM == nil || *got.SCIM != *member.SCIM || !got.UpdatedAt.Equal(at) {
						t.Fatalf("round %d tenant %s: member=%+v err=%v", round, tenant, got, err)
					}
				}
			}
		})
	}
}
