// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestSecretRotationScheduleControlPreservesDueEdgeAndReference(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 10, 11, 15, 0, 0, 0, time.UTC)
	const id = "25800000-0000-4000-8000-000000000001"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: id, TenantID: tenantA, Name: "schedule-control", Provider: "connector:ci",
		Key: "qa/control", OldRef: "version:3", IntervalSeconds: 3600,
		ConfigEventSequence: 10, Enabled: true, NextRunAt: dueAt,
	})
	control := func(tenant, action string, sequence uint64) error {
		return s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplySecretRotationScheduleControlTx(ctx, tx, tenant, id, action,
				sequence, dueAt.Add(time.Second))
		})
	}
	if err := control(tenantB, "pause", 11); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("other tenant control = %v, want not found", err)
	}
	for _, step := range []struct {
		action  string
		seq     uint64
		enabled bool
		retired bool
	}{
		{"pause", 11, false, false},
		{"pause", 11, false, false}, // replay must be inert
		{"resume", 12, true, false},
		{"retire", 13, false, true},
		{"resume", 14, false, true}, // retirement is terminal
	} {
		if err := control(tenantA, step.action, step.seq); err != nil {
			t.Fatalf("control %s sequence %d: %v", step.action, step.seq, err)
		}
		got, err := s.GetSecretRotationSchedule(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Enabled != step.enabled || (got.RetiredAt != nil) != step.retired ||
			got.OldRef != "version:3" || !got.NextRunAt.Equal(dueAt) ||
			got.ConfigEventSequence != 10 {
			t.Fatalf("control %s changed due edge, reference, or state: %+v", step.action, got)
		}
	}
	// A replayed original configuration may run during projection recovery. It
	// must not resurrect a retired schedule or rewind its due/reference tuple.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(ctx, tx, store.SecretRotationSchedule{
			ID: id, TenantID: tenantA, Name: "schedule-control", Provider: "connector:ci",
			Key: "qa/control", OldRef: "version:1", IntervalSeconds: 3600,
			ConfigEventSequence: 10, Enabled: true, NextRunAt: dueAt.Add(-time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSecretRotationSchedule(ctx, tenantA, id)
	if err != nil || got.RetiredAt == nil || got.Enabled || got.OldRef != "version:3" || !got.NextRunAt.Equal(dueAt) {
		t.Fatalf("configuration replay resurrected retired schedule: %+v err=%v", got, err)
	}
}

func TestSecretRotationScheduleControlDoesNotLoseClaimedTerminalReceipt(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 10, 11, 16, 0, 0, 0, time.UTC)
	const id = "25800000-0000-4000-8000-000000000002"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: id, TenantID: tenantA, Name: "in-flight-control", Provider: "connector:ci",
		Key: "qa/in-flight", OldRef: "version:3", IntervalSeconds: 3600,
		ConfigEventSequence: 10, Enabled: true, NextRunAt: dueAt,
	})
	command := claimScheduleCommandForTest(t, s, tenantA, id,
		"connector:ci", "qa/in-flight", "version:3", dueAt, "control-pause")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleControlTx(ctx, tx, tenantA, id, "pause", 11, dueAt.Add(time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleControlTx(ctx, tx, tenantA, id, "retire", 12, dueAt.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	run := terminalScheduleRunForTest(command, "queued", "version:4", dueAt.Add(3*time.Second), 13, strings.Repeat("c", 64))
	applyScheduleRunForTest(t, s, run)
	got, err := s.GetSecretRotationSchedule(ctx, tenantA, id)
	if err != nil || got.Enabled || got.RetiredAt == nil || got.OldRef != "version:4" || got.LastRunStatus != "queued" ||
		!got.NextRunAt.Equal(dueAt.Add(time.Hour)) {
		t.Fatalf("controlled in-flight terminal lost successor or resurrected schedule: %+v err=%v", got, err)
	}
}
