// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

// TestPendingWiring_NoStaleEntry is the RATCHET. The moment a recorded gap acquires a
// production caller the entry becomes stale and this test FAILS, forcing its removal.
// PendingWiring can therefore only ever shrink; it cannot quietly re-absorb a
// constructor that has since been wired, and it cannot be padded with entries that
// were never real.
func TestPendingWiring_NoStaleEntry(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	var stale []string
	for _, p := range PendingWiring {
		refs, err := NonTestCallers(root, Constructor{Pkg: p.Pkg, Name: p.Name, File: p.File}, defaultSearchRoots)
		if err != nil {
			t.Fatalf("scan callers of %s: %v", p.Qualified(), err)
		}
		if len(refs) > 0 {
			stale = append(stale, p.Qualified()+" (now called from "+refs[0].File+")")
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("PCAS-INT-CALL RATCHET: %d PendingWiring entr(y|ies) are STALE -- the constructor now has a production caller. Delete the entry from pending.go so the floor enforces it:\n  - %s",
			len(stale), joinLines(stale))
	}
	t.Logf("%d recorded wiring gap(s) still open; the list only shrinks", len(PendingWiring))
}

// TestPendingWiring_EntriesAreLiveConstructors rejects phantom entries: every recorded
// gap must name a constructor the enumeration actually finds, at the file it claims. A
// renamed or deleted constructor leaves a dead entry that would silently exempt nothing
// (or, worse, mask a future constructor of the same name), so it fails here.
func TestPendingWiring_EntriesAreLiveConstructors(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	ctors, err := LiveConstructors(root)
	if err != nil {
		t.Fatalf("enumerate PCAS constructors: %v", err)
	}
	live := map[string]string{}
	for _, c := range ctors {
		live[ctorKey(c.Pkg, c.Name)] = c.File
	}
	var phantom []string
	for _, p := range PendingWiring {
		file, ok := live[ctorKey(p.Pkg, p.Name)]
		if !ok {
			phantom = append(phantom, p.Qualified()+" (no such exported constructor under "+familyTree+")")
			continue
		}
		if file != p.File {
			phantom = append(phantom, p.Qualified()+" (recorded file "+p.File+", actual "+file+")")
		}
	}
	if len(phantom) > 0 {
		sort.Strings(phantom)
		t.Fatalf("PCAS-INT-CALL RATCHET: %d PendingWiring entr(y|ies) do not match a live constructor:\n  - %s",
			len(phantom), joinLines(phantom))
	}
}
