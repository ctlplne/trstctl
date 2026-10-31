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
		BackupRoots: []string{filepath.Join(base, "events"), filepath.Join(base, "restored-events"), filepath.Join(base, "before-activation-events")},
		Locker:      &sourceFixtureLocker{}, EvidenceKey: key, DestructionAuthority: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	checkedCustody := &changingPlanCustody{ErasurePlanCustody: custody}
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
	var earliest []events.BackupHistoryRecord
	var earliestRaw bytes.Buffer
	if err := source.ExportBackupHistoryThrough(t.Context(), registration.Sequence, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		earliest = append(earliest, record)
		earliestRaw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
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
	livePlanner := eventprivacy.ErasurePlanner{Policy: policy, Custody: checkedCustody}
	activeFlag := private
	activeFlag.SensitiveErased = true
	if err := livePlanner.WithRetainedSource(t.Context(), activeFlag, func(_ context.Context, omit bool) error {
		if omit || checkedCustody.depth.Load() != 0 {
			t.Fatal("active source was omitted or callback held extra custody lock")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
	for _, check := range []struct {
		name  string
		event events.Event
		want  bool
	}{
		{"private", private, true}, {"plaintext-registration", registration, true}, {"new-lifetime", newest, false}, {"neighbor", other, false},
	} {
		t.Run("retained-"+check.name, func(t *testing.T) {
			called := false
			if err := planner.WithRetainedSource(t.Context(), check.event, func(_ context.Context, omit bool) error {
				called = true
				if omit != check.want {
					t.Fatal("retained source crossed lifetime or tenant boundary")
				}
				if omit && checkedCustody.depth.Load() != 1 {
					t.Fatal("retained omission escaped custody fence")
				}
				return nil
			}); err != nil || !called {
				t.Fatalf("retained source callback missing: %v", err)
			}
		})
	}
	flagOnly := other
	flagOnly.SensitiveErased = true
	if err := planner.WithRetainedSource(t.Context(), flagOnly, func(_ context.Context, omit bool) error {
		if omit {
			t.Fatal("caller erased flag granted omission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*events.Event){
		"id":     func(e *events.Event) { e.ID += "changed" },
		"type":   func(e *events.Event) { e.Type = "fixture.changed" },
		"time":   func(e *events.Event) { e.Time = e.Time.Add(time.Nanosecond) },
		"schema": func(e *events.Event) { e.SchemaVersion++ },
		"tenant": func(e *events.Event) { e.TenantID = neighbor },
		"key": func(e *events.Event) {
			p := *e.Protection
			p.KeyID = "a6fa418b-7358-4601-92b2-5c67d24d6556"
			e.Protection = &p
		},
		"sequence": func(e *events.Event) { e.Sequence = newest.Sequence + 1 },
	} {
		t.Run("changed-retained-"+name, func(t *testing.T) {
			candidate := private
			change(&candidate)
			called := false
			if err := planner.WithRetainedSource(t.Context(), candidate, func(context.Context, bool) error { called = true; return nil }); err == nil || called {
				t.Fatal("changed or unavailable source reached omission callback")
			}
		})
	}
	checkedCustody.reject.Store(true)
	called := false
	err = planner.WithRetainedSource(t.Context(), private, func(context.Context, bool) error { called = true; return nil })
	checkedCustody.reject.Store(false)
	if err == nil || called {
		t.Fatal("retained source accepted unavailable current custody")
	}
	canceledRetained, cancelRetained := context.WithCancel(t.Context())
	cancelRetained()
	if err := planner.WithRetainedSource(canceledRetained, private, func(context.Context, bool) error { t.Fatal("canceled retained callback ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("retained source lost cancellation: %v", err)
	}
	missingRetained := planner
	missingRetained.Custody = nil
	called = false
	if err := missingRetained.WithRetainedSource(t.Context(), private, func(context.Context, bool) error { called = true; return nil }); err == nil || called {
		t.Fatal("missing retained custody granted omission")
	}
	visitorErr := errors.New("retained visitor refused")
	if err := planner.WithRetainedSource(t.Context(), private, func(context.Context, bool) error { return visitorErr }); !errors.Is(err, visitorErr) {
		t.Fatalf("retained source hid callback failure: %v", err)
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
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	beforeActivation := open(filepath.Join(base, "before-activation-events"))
	if _, err := beforeActivation.RestoreBackupHistory(t.Context(), registration.Sequence, crypto.SHA256Hex(earliestRaw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
		for _, record := range earliest {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	planner.Policy = policy
	if err := planner.WithPlan(t.Context(), func(_ context.Context, plan *eventprivacy.ErasurePlan) error {
		if !planSkips(t, plan, registration) {
			t.Fatal("current signed first-registration floor omitted no old lifetime")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	badTrust, err := jose.GenerateRSASigningKey("unrelated-registration-floor")
	if err != nil {
		t.Fatal(err)
	}
	wrongTrust := planner
	wrongTrust.Policy.Trust = badTrust.JWKS()
	called = false
	if err := wrongTrust.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error { called = true; return nil }); err == nil || called {
		t.Fatal("wrong public trust selected old registration erasure")
	}
	for name, change := range map[string]func(*eventprotect.CurrentKeyState){
		"creation": func(state *eventprotect.CurrentKeyState) {
			state.Creation.Probe = bytes.Clone(state.Creation.Probe)
			state.Creation.Probe[0] ^= 1
		},
		"pending": func(state *eventprotect.CurrentKeyState) {
			state.Phase = eventprotect.CustodyKeyPending
			state.Receipt = ""
		},
		"ref": func(state *eventprotect.CurrentKeyState) { state.Creation.Ref.TenantID = neighbor },
	} {
		t.Run("registration-floor-"+name, func(t *testing.T) {
			invalid := planner
			invalid.Custody = &floorLookupOverride{FileAuthority: custody, change: change}
			called := false
			if err := invalid.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error { called = true; return nil }); err == nil || called {
				t.Fatal("unverified registration state exposed erasure plan")
			}
		})
	}
	var preserved bytes.Buffer
	if err := beforeActivation.ExportBackupHistoryThrough(t.Context(), registration.Sequence, func(record events.BackupHistoryRecord) error { preserved.Write(record.Stored); return nil }); err != nil || !bytes.Equal(preserved.Bytes(), earliestRaw.Bytes()) {
		t.Fatalf("registration floor changed raw legacy source: %v", err)
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

func (c *changingPlanCustody) LookupKeyState(ctx context.Context, ref eventprotect.KeyRef) (eventprotect.CurrentKeyState, bool, error) {
	if c.reject.Load() {
		return eventprotect.CurrentKeyState{}, false, eventprotect.ErrKey
	}
	reader, ok := c.ErasurePlanCustody.(interface {
		LookupKeyState(context.Context, eventprotect.KeyRef) (eventprotect.CurrentKeyState, bool, error)
	})
	if !ok {
		return eventprotect.CurrentKeyState{}, false, eventprivacy.ErrSource
	}
	return reader.LookupKeyState(ctx, ref)
}

type floorLookupOverride struct {
	*eventprotect.FileAuthority
	change func(*eventprotect.CurrentKeyState)
}

func (c *floorLookupOverride) LookupKeyState(ctx context.Context, ref eventprotect.KeyRef) (eventprotect.CurrentKeyState, bool, error) {
	state, found, err := c.FileAuthority.LookupKeyState(ctx, ref)
	if err == nil && found {
		c.change(&state)
	}
	return state, found, err
}
