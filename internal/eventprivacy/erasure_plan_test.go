// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type planFixtureTenantGuard struct{}

func (planFixtureTenantGuard) WithTenantEventProtection(ctx context.Context, _ string, visit func(context.Context) error) error {
	return visit(ctx)
}

type alteredPlanReceipt struct {
	eventprivacy.ErasurePlanCustody
}

func (c alteredPlanReceipt) DestructionReceipt(ctx context.Context, ref eventprotect.KeyRef) (string, bool, error) {
	receipt, erased, err := c.ErasurePlanCustody.DestructionReceipt(ctx, ref)
	return receipt + "changed", erased, err
}

// Component evidence only: real NATS, encryption, signed removal, current
// custody and exact raw source transfer; local fixture locks/authority. This
// does not qualify PostgreSQL reconstruction, full backup, process isolation,
// snapshots or production dispatcher authority.
func TestErasurePlanUsesCurrentReceiptForOlderSourceCutAndPreservesNewLifetime(t *testing.T) {
	base := t.TempDir()
	key, err := jose.GenerateRSASigningKey("erasure-plan-fixture")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &sourceReadDestructionAuthority{}
	custody, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{
		Directory:   filepath.Join(base, "independent-keys"),
		BackupRoots: []string{filepath.Join(base, "events"), filepath.Join(base, "restored-events")},
		Locker:      &sourceFixtureLocker{}, EvidenceKey: key, DestructionAuthority: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	policy := eventprivacy.SourcePolicy{Trust: key.JWKS()}
	admission := &eventprivacy.SourceAdmission{Policy: policy, Guard: planFixtureTenantGuard{}, Custody: custody}
	reader := &eventprivacy.SourceKeys{Policy: policy, Custody: custody}
	open := func(path string) *events.Log {
		log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: path},
			func(log *events.Log) {
				policy.Log = log
				admission.Policy.Log = log
				reader.Policy.Log = log
				admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: policy}
			},
			events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = log.Close() })
		return log
	}
	source := open(filepath.Join(base, "events"))
	registration := appendSource(t, source, "erasure-plan-registration", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"old fixture"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, source, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, time.Now().UTC(), request)
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
	if err := custody.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := custody.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	appendSource(t, source, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	appendSource(t, source, "erasure-plan-rename", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"renamed protected fixture"})
	private := appendSource(t, source, "erasure-plan-private", sourcePrivateType, time.Now().UTC(), struct {
		Email string `json:"email"`
	}{"old-private@example.invalid"})
	const neighbor = "0e2312f8-fb7a-460e-ac70-30fdc10c4d1e"
	neighborWire := []byte(`{"name":"neighbor fixture"}`)
	other, err := source.Append(t.Context(), events.Event{ID: "erasure-plan-neighbor", Type: "tenant.registered", TenantID: neighbor, Data: neighborWire})
	if err != nil {
		t.Fatal(err)
	}
	cut, err := source.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var old []events.BackupHistoryRecord
	var raw bytes.Buffer
	if err := source.ExportBackupHistoryThrough(t.Context(), cut, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		old = append(old, record)
		raw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Bytes(), []byte("old-private@example.invalid")) {
		t.Fatal("fixture source did not encrypt private data")
	}
	appendSource(t, source, "erasure-plan-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.Destroy(t.Context(), authorizer.want); err != nil {
		t.Fatal(err)
	}
	newest := appendSource(t, source, "erasure-plan-new-lifetime", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"current fixture"})
	checkedCustody := &changingPlanCustody{ErasurePlanCustody: custody}
	planner := eventprivacy.ErasurePlanner{Policy: policy, Custody: checkedCustody}
	if err := planner.WithPlan(t.Context(), func(_ context.Context, plan *eventprivacy.ErasurePlan) error {
		if !planSkips(t, plan, private) || !planSkips(t, plan, registration) || planSkips(t, plan, newest) || planSkips(t, plan, other) {
			t.Fatal("current erasure range crossed lifetime/tenant boundaries")
		}
		forged := other
		forged.SensitiveErased = true
		if planSkips(t, plan, forged) {
			t.Fatal("caller erased flag granted plan membership")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	restored := open(filepath.Join(base, "restored-events"))
	if _, err := restored.RestoreBackupHistory(t.Context(), cut, crypto.SHA256Hex(raw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
		for _, record := range old {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	original, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || original.Offboard != nil || original.Completion != nil || original.HoldClearance != nil {
		t.Fatalf("old cut contains later source authority: %v", err)
	}
	planner.Policy = policy
	if err := planner.WithPlan(t.Context(), func(_ context.Context, plan *eventprivacy.ErasurePlan) error {
		if plan.Head() != cut || !planSkips(t, plan, registration) || !planSkips(t, plan, private) || planSkips(t, plan, other) {
			t.Fatal("old-cut current receipt did not select exact old lifetime")
		}
		future := private
		future.Sequence = cut + 1
		if planSkips(t, plan, future) {
			t.Fatal("plan accepted an event beyond the finite cut")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var escaped *eventprivacy.ErasurePlan
	if err := planner.WithPlan(t.Context(), func(ctx context.Context, plan *eventprivacy.ErasurePlan) error {
		escaped = plan
		checkedCustody.reject.Store(true)
		called := false
		err := plan.WithSource(ctx, private, func(context.Context, bool) error { called = true; return nil })
		checkedCustody.reject.Store(false)
		if err == nil || called {
			t.Fatal("cached plan omitted after current custody changed")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := plan.WithSource(canceled, other, func(context.Context, bool) error { t.Fatal("canceled plan callback ran"); return nil }); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
		return plan.WithSource(ctx, private, func(_ context.Context, omit bool) error {
			if !omit || checkedCustody.depth.Load() != 1 {
				t.Fatal("omission escaped independent custody fence")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := escaped.WithSource(t.Context(), private, func(context.Context, bool) error { t.Fatal("expired plan callback ran"); return nil }); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("escaped plan accepted: %v", err)
	}
	// No SQL/source event is invented to make the old artifact look newer.
	after, err := restored.LastSequence(t.Context())
	if err != nil || after != cut {
		t.Fatal("read-only plan appended history")
	}
	index := 0
	if err := restored.ExportBackupHistoryThrough(t.Context(), cut, func(record events.BackupHistoryRecord) error {
		if index >= len(old) || !bytes.Equal(record.Stored, old[index].Stored) {
			t.Fatal("read-only erasure plan rewrote source bytes")
		}
		index++
		return nil
	}); err != nil || index != len(old) {
		t.Fatalf("source prefix differs: %v", err)
	}
	for name, bad := range map[string]eventprivacy.ErasurePlanCustody{"missing": nil, "altered-receipt": alteredPlanReceipt{custody}} {
		t.Run(name, func(t *testing.T) {
			called := false
			invalid := planner
			invalid.Custody = bad
			if err := invalid.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error { called = true; return nil }); err == nil || called {
				t.Fatal("unverified erasure exposed a partial plan")
			}
		})
	}
	got, found, err := restored.EventByID(t.Context(), private.ID)
	if err != nil || !found || !got.SensitiveErased || len(got.Data) != 0 {
		t.Fatalf("current destruction did not erase logical fields: %v", err)
	}
	got, found, err = restored.EventByID(t.Context(), other.ID)
	if err != nil || !found || !bytes.Equal(got.Data, neighborWire) {
		t.Fatalf("neighbor source changed: %v", err)
	}
	if receipt, erased, err := custody.DestructionReceipt(t.Context(), ref); err != nil || !erased || receipt == "" {
		t.Fatalf("current receipt disappeared: %v", err)
	}
}

func planSkips(t *testing.T, plan *eventprivacy.ErasurePlan, event events.Event) bool {
	t.Helper()
	var skipped bool
	err := plan.WithSource(t.Context(), event, func(_ context.Context, omit bool) error { skipped = omit; return nil })
	if event.Sequence > plan.Head() {
		if !errors.Is(err, eventprivacy.ErrSource) {
			t.Fatalf("out-of-cut event accepted: %v", err)
		}
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return skipped
}

type changingPlanCustody struct {
	eventprivacy.ErasurePlanCustody
	reject atomic.Bool
	depth  atomic.Int64
}

func (c *changingPlanCustody) WithCustodyFence(ctx context.Context, ref eventprotect.KeyRef, visit func(context.Context) error) error {
	return c.ErasurePlanCustody.WithCustodyFence(ctx, ref, func(fenced context.Context) error { c.depth.Add(1); defer c.depth.Add(-1); return visit(fenced) })
}
func (c *changingPlanCustody) DestructionReceipt(ctx context.Context, ref eventprotect.KeyRef) (string, bool, error) {
	if c.reject.Load() {
		return "", false, eventprotect.ErrKey
	}
	return c.ErasurePlanCustody.DestructionReceipt(ctx, ref)
}
