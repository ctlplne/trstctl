// SPDX-License-Identifier: BUSL-1.1
package eventprivacy_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type branchedErasureCustody struct {
	*eventprotect.FileAuthority
	change func(*eventprotect.CurrentKeyState, *bool) error
}

func (c branchedErasureCustody) LookupKeyState(ctx context.Context, ref eventprotect.KeyRef) (eventprotect.CurrentKeyState, bool, error) {
	state, found, err := c.FileAuthority.LookupKeyState(ctx, ref)
	if err == nil && c.change != nil {
		err = c.change(&state, &found)
	}
	return state, found, err
}

// This adapter deliberately lacks current identity lookup. A signed receipt
// alone keeps the existing finite-cut rule even after an unrelated branch grows.
type receiptOnlyBranchCustody struct {
	eventprivacy.ErasurePlanCustody
}

func TestBranchedErasureRequiresExactCurrentCreationAndReceipt(t *testing.T) {
	reader, original, custody, _, ref, authorizer := currentCustodyFixture(t)
	cut, err := original.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var records []events.BackupHistoryRecord
	var raw bytes.Buffer
	if err := original.ExportBackupHistoryThrough(t.Context(), cut, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		records = append(records, record)
		raw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	offboard := appendSource(t, original, "branch-original-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := reader.Policy.LatestLifetime(t.Context(), ref.TenantID)
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
	branch, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "branch")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = branch.Close() })
	if _, err := branch.RestoreBackupHistory(t.Context(), cut, crypto.SHA256Hex(raw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
		for _, record := range records {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const neighbor = "18109e65-9b03-458f-8e72-799b4497ca54"
	for i := 0; i < 2; i++ {
		if _, err := branch.Append(t.Context(), events.Event{Type: "tenant.registered", TenantID: neighbor, Data: []byte(`{"name":"independent branch"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	head, err := branch.LastSequence(t.Context())
	if err != nil || head <= offboard.Sequence {
		t.Fatalf("fixture did not cross original position: %d %v", head, err)
	}
	policy := reader.Policy
	policy.Log = branch
	registration, err := events.DecodeBackupHistoryEvent(records[0])
	if err != nil {
		t.Fatal(err)
	}
	planner := eventprivacy.ErasurePlanner{Policy: policy, Custody: custody}
	if err := planner.WithPlan(t.Context(), func(ctx context.Context, plan *eventprivacy.ErasurePlan) error {
		return plan.WithSource(ctx, registration, func(_ context.Context, omitted bool) error {
			if !omitted {
				t.Error("old registration was resurrected on the neighboring branch")
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("current exact custody did not retain erased registration: %v", err)
	}
	if err := planner.WithRetainedSource(t.Context(), registration, func(_ context.Context, omitted bool) error {
		if !omitted {
			t.Error("retained source lost the current erasure floor")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	provider := eventprivacy.SourcePostgresProtection{Policy: policy, Custody: custody, Cut: head}
	if row, erased, err := provider.RestorePlainPostgresRow(t.Context(), 1, head, ref.TenantID, []byte(`{"subject":"branch-sql@example.invalid"}`)); err != nil || !erased || len(row) != 0 {
		t.Fatalf("branched legacy SQL import lost current erasure: %v", err)
	}
	for name, change := range map[string]func(*eventprotect.CurrentKeyState, *bool) error{
		"missing": func(_ *eventprotect.CurrentKeyState, found *bool) error { *found = false; return nil },
		"active": func(state *eventprotect.CurrentKeyState, _ *bool) error {
			state.Phase = eventprotect.CustodyKeyActive
			return nil
		},
		"pending": func(state *eventprotect.CurrentKeyState, _ *bool) error {
			state.Phase = eventprotect.CustodyKeyPending
			return nil
		},
		"receipt": func(state *eventprotect.CurrentKeyState, _ *bool) error { state.Receipt += "changed"; return nil },
		"creation": func(state *eventprotect.CurrentKeyState, _ *bool) error {
			state.Creation.CreatedAt = state.Creation.CreatedAt.Add(time.Nanosecond)
			return nil
		},
		"reference": func(state *eventprotect.CurrentKeyState, _ *bool) error {
			state.Creation.Ref.ID = "72b3b3e7-14bf-48ae-889c-394ef09432e4"
			return nil
		},
		"lookup-error": func(_ *eventprotect.CurrentKeyState, _ *bool) error { return errors.New("lookup fixture unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := planner
			bad.Custody = branchedErasureCustody{FileAuthority: custody, change: change}
			called := false
			if err := bad.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error { called = true; return nil }); err == nil || called {
				t.Fatal("uncorroborated current identity admitted an erasure plan")
			}
			if err := bad.WithRetainedSource(t.Context(), registration, func(context.Context, bool) error { called = true; return nil }); err == nil || called {
				t.Fatal("uncorroborated current identity admitted a tail callback")
			}
			sql := provider
			sql.Custody = branchedErasureCustody{FileAuthority: custody, change: change}
			if _, erased, err := sql.RestorePlainPostgresRow(t.Context(), 1, head, ref.TenantID, []byte(`{}`)); err == nil || erased {
				t.Fatal("uncorroborated current identity admitted SQL omission")
			}
		})
	}
	uncorroborated := planner
	uncorroborated.Custody = receiptOnlyBranchCustody{custody}
	if err := uncorroborated.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error {
		t.Error("receipt alone bypassed the ordinal guard")
		return nil
	}); err == nil {
		t.Fatal("missing current identity lookup admitted the branched lifetime")
	}
	wrong, err := jose.GenerateRSASigningKey("branch-wrong-trust")
	if err != nil {
		t.Fatal(err)
	}
	invalid := planner
	invalid.Policy.Trust = wrong.JWKS()
	if err := invalid.WithPlan(t.Context(), func(context.Context, *eventprivacy.ErasurePlan) error {
		t.Error("wrong independent trust exposed a plan")
		return nil
	}); err == nil {
		t.Fatal("wrong independent trust accepted current erasure")
	}
}
