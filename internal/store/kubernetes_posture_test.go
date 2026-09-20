// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestKubernetesControllerPostureRepositoryEnforcesTenantRLS(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	report := store.KubernetesControllerPosture{
		TenantID: tenantA, ControllerID: "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), Capability: store.KubernetesPostureCertificateSigningRequests,
		ReportID: "33333333-3333-3333-3333-333333333333", ReconcileComplete: true,
		ReconcileIntervalSeconds: 30, ReportedAt: time.Now().UTC(), EventSequence: 12,
		Resources: []store.KubernetesPostureResource{{Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64)}},
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return st.ApplyKubernetesControllerPostureTx(ctx, tx, report) }); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListKubernetesControllerPosture(ctx, tenantA, report.Capability)
	if err != nil || len(rows) != 1 || rows[0].Resources[0].Name != "web-csr" {
		t.Fatalf("tenant A posture = %+v err=%v", rows, err)
	}
	newer := report
	newer.ControllerID = "55555555-5555-5555-5555-555555555555"
	newer.ReportID = "66666666-6666-6666-6666-666666666666"
	newer.EventSequence = 13
	newer.Resources = []store.KubernetesPostureResource{{Name: "web-csr", UID: "csr-uid", ResourceVersion: "18", State: "pending", Reason: "approval_pending", PublicHash: strings.Repeat("b", 64)}}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return st.ApplyKubernetesControllerPostureTx(ctx, tx, newer) }); err != nil {
		t.Fatal(err)
	}
	older := report
	older.EventSequence = 11
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return st.ApplyKubernetesControllerPostureTx(ctx, tx, older) }); err != nil {
		t.Fatal(err)
	}
	rows, err = st.ListKubernetesControllerPosture(ctx, tenantA, report.Capability)
	if err != nil || len(rows) != 1 || rows[0].ControllerID != newer.ControllerID || rows[0].Resources[0].ResourceVersion != "18" {
		t.Fatalf("cluster posture did not retain latest controller event: %+v err=%v", rows, err)
	}
	rows, err = st.ListKubernetesControllerPosture(ctx, tenantB, report.Capability)
	if err != nil || len(rows) != 0 {
		t.Fatalf("tenant B saw tenant A posture = %+v err=%v", rows, err)
	}

	err = st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return st.ApplyKubernetesControllerPostureTx(ctx, tx, report)
	})
	if err == nil {
		t.Fatal("tenant B projected a tenant A posture row; FORCE RLS must reject it")
	}
}
