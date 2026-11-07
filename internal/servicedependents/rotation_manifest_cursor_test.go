// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"testing/quick"
	"trstctl.com/trstctl/internal/crypto"
)

func cursorFixture(t testing.TB, width int, empty bool) (RotationIntent, []RotationHostInput, RotationManifestResolver) {
	return cursorFixtureWithState(t, width, empty, false, false)
}
func cursorFixtureWithState(t testing.TB, width int, empty, inactive, nonpassword bool) (RotationIntent, []RotationHostInput, RotationManifestResolver) {
	t.Helper()
	legacy, inputs := workflowFixture(t)
	if inactive {
		inputs[0].Inventory.Services[0].WasRunning = false
		inputs[0].Inventory.Services[1].WasRunning = false
		inputs[0].Inventory.Tasks[0].Enabled = false
		inputs[0].Inventory.Pools[0].WasStarted = false
	}
	if nonpassword {
		inputs[0].Inventory.Tasks[0].LogonType = 2
	}
	raw, e := json.Marshal(inputs[0].Inventory)
	if e != nil {
		t.Fatal(e)
	}
	inputs[0].InventoryDigest = crypto.SHA256Hex(raw)
	legacy.Plan, e = NewRotationPlan(legacy.Plan.ID, legacy.Plan.Account, legacy.Plan.SecretName, inputs, legacy.Plan.Order, legacy.Plan.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	h, entry := manifestFixture(t)
	// Use one exact native inventory for both the old and paged algorithms.
	h.ID = legacy.Plan.ID
	h.Account = legacy.Plan.Account
	h.CreatedAt = legacy.Plan.CreatedAt
	h.ExpiresAt = legacy.Plan.ExpiresAt
	entry.Host = RotationManifestHost{Binding: inputs[0].Binding, InventoryRunID: inputs[0].Inventory.RunID, InventoryDigest: inputs[0].InventoryDigest, ObservedAt: inputs[0].Inventory.ObservedAt}
	pages := []RotationManifestPage{}
	previous, err := h.Digest()
	if err != nil {
		t.Fatal(err)
	}
	add := func(entries []RotationManifestEntry) {
		page, e := NewRotationManifestPageWithHosts(h, int64(len(pages)), previous, []RotationManifestHost{entry.Host}, entries)
		if e != nil {
			t.Fatal(e)
		}
		pages = append(pages, page)
		previous = page.Digest
	}
	if empty {
		add(nil)
	}
	for i := 0; i < len(legacy.Plan.Order); i += width {
		end := min(i+width, len(legacy.Plan.Order))
		entries := []RotationManifestEntry{}
		for j := i; j < end; j++ {
			v := entry
			v.Ref = legacy.Plan.Order[j]
			v.ProbeID = legacy.Probes[j].ProbeID
			entries = append(entries, v)
		}
		add(entries)
		if empty {
			add(nil)
		}
	}
	seal, e := NewRotationManifestSeal(h, pages[len(pages)-1], int64(len(legacy.Plan.Order)), 1, h.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	intent, e := NewRotationIntentFromManifest(h, seal)
	if e != nil {
		t.Fatal(e)
	}
	resolver := RotationManifestResolver{Header: h, Seal: seal, Page: func(n int64) (RotationManifestPage, error) {
		if n < 0 || n >= int64(len(pages)) {
			return RotationManifestPage{}, fmt.Errorf("page outside fixture")
		}
		return pages[n], nil
	}}
	return intent, inputs, resolver
}
func TestManifestCursorPreservesGlobalNativeOrderAndExactSnapshotsA267(t *testing.T) {
	for width := 1; width <= 4; width++ {
		for _, empty := range []bool{false, true} {
			for _, direction := range []string{Forward, Inverse} {
				for _, inactive := range []bool{false, true} {
					for _, nonpassword := range []bool{false, true} {
						intent, inputs, r := cursorFixtureWithState(t, width, empty, inactive, nonpassword)
						legacy, _ := workflowFixture(t)
						// Recreate the comparison using the same exact input and plan identity/time.
						legacy.Plan.ID = intent.Plan.ID
						legacy.Plan.CreatedAt = intent.Plan.CreatedAt
						legacy.Plan.ExpiresAt = intent.Plan.ExpiresAt
						var err error
						legacy.Plan, err = NewRotationPlan(intent.Plan.ID, intent.Plan.Account, intent.Plan.SecretName, inputs, legacy.Plan.Order, intent.Plan.CreatedAt)
						if err != nil {
							t.Fatal(err)
						}
						expected, err := legacy.Steps(inputs, direction)
						if err != nil {
							t.Fatal(err)
						}
						cursor, err := r.Initial(direction)
						if err != nil {
							t.Fatal(err)
						}
						got := []RotationStep{}
						for visits := 0; cursor.Position.Stage != ManifestComplete; visits++ {
							if visits > 40 {
								t.Fatal("cursor failed to terminate")
							}
							step, applicable, e := r.Step(intent, cursor, inputs[0])
							if e != nil {
								t.Fatal(e)
							}
							if applicable {
								if step.ManifestPosition == nil || *step.ManifestPosition != cursor.Position || step.Validate() != nil {
									t.Fatal("native grant lost its exact page/stage location")
								}
								got = append(got, step)
							}
							cursor, e = r.Advance(cursor)
							if e != nil {
								t.Fatal(e)
							}
						}
						if len(got) != len(expected) {
							t.Fatalf("width=%d empty=%v dir=%s got=%d want=%d", width, empty, direction, len(got), len(expected))
						}
						for i := range got {
							a, b := got[i], expected[i]
							a.ManifestPosition = nil
							a.PlanDigest = b.PlanDigest
							a.ID = b.ID
							if !reflect.DeepEqual(a, b) {
								t.Fatalf("changed global effect %d: %+v != %+v", i, a, b)
							}
						}
					}
				}
			}
		}
	}
}
func TestManifestCursorRefusesSubstitutionAndMalformedPositionsA267(t *testing.T) {
	intent, inputs, r := cursorFixture(t, 1, true)
	cursor, err := r.Initial(Forward)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ordinal", "page", "index", "stage", "direction"} {
		changed := cursor
		switch field {
		case "ordinal":
			changed.Position.EntryOrdinal = -1
		case "page":
			changed.Position.PageNumber = r.Seal.PageCount
		case "index":
			changed.Position.EntryIndex = 100
		case "stage":
			changed.Position.Stage = "reset"
		case "direction":
			changed.Direction = "sideways"
		}
		if _, _, e := r.Step(intent, changed, inputs[0]); e == nil {
			t.Fatalf("malformed cursor accepted: %s", field)
		}
	}
	altered := inputs[0]
	altered.InventoryDigest = ""
	if _, _, e := r.Step(intent, cursor, altered); e == nil {
		t.Fatal("rewritten inventory selected native work")
	}
	first := r.Page
	r.Page = func(n int64) (RotationManifestPage, error) {
		p, e := first(n)
		if n == cursor.Position.PageNumber+1 {
			p.PreviousDigest = p.HeaderDigest
			p.Digest, _ = p.contentDigest()
		}
		return p, e
	}
	if _, err := r.Advance(cursor); err == nil {
		t.Fatal("cursor crossed rewritten adjacent chain link")
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 4096 {
		t.Fatal("root expanded into native arrays")
	}
	legacy, _ := workflowFixture(t)
	raw, _ = json.Marshal(legacy)
	if string(raw) == "" {
		t.Fatal("empty legacy intent")
	}
}
func TestManifestCursorNormalAdvanceReadsOnlyCurrentPageA267(t *testing.T) {
	property := func(v uint8) bool {
		intent, inputs, r := cursorFixture(t, 4, false)
		cursor, e := r.Initial(Forward)
		if e != nil {
			return false
		}
		// Position within the one bounded page; no chain rescans for ordinary work.
		cursor.Position.EntryOrdinal = int64(v % 3)
		cursor.Position.EntryIndex = int(v % 3)
		reads := 0
		load := r.Page
		r.Page = func(n int64) (RotationManifestPage, error) { reads++; return load(n) }
		step, ok, e := r.Step(intent, cursor, inputs[0])
		if e != nil || !ok || step.ManifestPosition == nil {
			return false
		}
		next, e := r.Advance(cursor)
		return e == nil && next.Position.EntryOrdinal == cursor.Position.EntryOrdinal+1 && reads == 2
	}
	if e := quick.Check(property, &quick.Config{MaxCount: 64}); e != nil {
		t.Fatal(e)
	}
}
