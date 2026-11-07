// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func manifestFixture(t testing.TB) (RotationManifestHeader, RotationManifestEntry) {
	t.Helper()
	intent, inputs := workflowFixture(t)
	input := inputs[0]
	header := RotationManifestHeader{Version: 1, ID: intent.Plan.ID, Account: intent.Plan.Account, SecretName: intent.Plan.SecretName, ExpectedVersion: intent.ExpectedVersion, ProviderBinding: intent.ProviderBinding, CreatedAt: intent.Plan.CreatedAt, ExpiresAt: intent.Plan.CreatedAt.Add(RotationInventoryMaxAge)}
	entry := RotationManifestEntry{Host: RotationManifestHost{Binding: input.Binding, InventoryRunID: input.Inventory.RunID, InventoryDigest: input.InventoryDigest, ObservedAt: input.Inventory.ObservedAt}, Ref: intent.Plan.Order[0], ProbeID: intent.Probes[0].ProbeID}
	return header, entry
}
func TestPagedDependentReviewExceedsOneEventWithoutIncreasingPageBoundA267(t *testing.T) {
	header, entry := manifestFixture(t)
	previousDigest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var previous *RotationManifestPage
	total := 0
	for number := int64(0); number < 100; number++ {
		entries := make([]RotationManifestEntry, 32)
		for i := range entries {
			entries[i] = entry
			entries[i].Ref.Name = fmt.Sprintf("owned-%d-%d-%s", number, i, strings.Repeat("a", 100))
		}
		page, err := NewRotationManifestPage(header, number, previousDigest, entries)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRotationManifestLink(header, page, previous); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > MaxRotationManifestPageBytes {
			t.Fatal("large account raised individual event bound")
		}
		decoded, err := DecodeRotationManifestPage(header, raw)
		if err != nil || decoded.Digest != page.Digest {
			t.Fatal("bounded page did not round trip", err)
		}
		total += len(raw)
		previous = &page
		previousDigest = page.Digest
	}
	if total <= MaxRotationPlanBytes {
		t.Fatalf("fixture did not exceed the original whole-plan limit: %d", total)
	}
	raw, err := json.Marshal(header)
	if err != nil || len(raw) > 16<<10 {
		t.Fatal("root summary grew with native object count", err)
	}
}
func TestManifestChainRefusesChangedAuthorityAndAmbiguousWireA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`,"unreviewed":true}`, `,"page_number":0}`} {
		raw := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(suffix)...)
		if _, err := DecodeRotationManifestPage(header, raw); err == nil {
			t.Fatal("ambiguous or extended manifest source accepted")
		}
	}
	if _, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry, entry}); err == nil {
		t.Fatal("duplicate native reference in page")
	}
	other := header
	other.ExpectedVersion++
	if page.Validate(other) == nil {
		t.Fatal("another vault generation retained manifest authority")
	}
	changed := page
	changed.Number++
	if ValidateRotationManifestLink(header, changed, nil) == nil {
		t.Fatal("missing first page accepted")
	}
	next, err := NewRotationManifestPage(header, 1, page.Digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if ValidateRotationManifestLink(header, next, &page) != nil {
		t.Fatal("exact second page refused")
	}
	next.PreviousDigest = strings.Repeat("0", 64)
	if ValidateRotationManifestLink(header, next, &page) == nil {
		t.Fatal("changed predecessor accepted")
	}
	tooLarge := make([]RotationManifestEntry, 1024)
	for i := range tooLarge {
		tooLarge[i] = entry
		tooLarge[i].Ref.Name = fmt.Sprintf("owned-%d", i)
	}
	if _, err := NewRotationManifestPage(header, 0, digest, tooLarge); err == nil {
		t.Fatal("oversized native page accepted")
	}
}
func TestManifestHeaderMutationChangesEveryPageAuthorityPropertyA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	property := func(version uint16, seconds uint16) bool {
		changed := header
		changed.ExpectedVersion += int(version) + 1
		changed.CreatedAt = changed.CreatedAt.Add(time.Duration(seconds) * time.Second)
		changed.ExpiresAt = changed.CreatedAt.Add(RotationInventoryMaxAge)
		return page.Validate(changed) != nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func FuzzRotationManifestPageA267(f *testing.F) {
	header, entry := manifestFixture(f)
	digest, err := header.Digest()
	if err != nil {
		f.Fatal(err)
	}
	page, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		f.Fatal(err)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"page_number":0,"page_number":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxRotationManifestPageBytes+1 {
			return
		}
		value, err := DecodeRotationManifestPage(header, raw)
		if err != nil {
			return
		}
		if value.Validate(header) != nil {
			t.Fatal("decoder accepted invalid authority")
		}
		value.HeaderDigest = strings.Repeat("0", 64)
		if value.Validate(header) == nil {
			t.Fatal("changed header retained authority")
		}
	})
}

func TestManifestSealBindsCountsTailAndEarliestExpiryA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	expires := header.ExpiresAt.Add(-time.Second)
	seal, err := NewRotationManifestSeal(header, page, 1, 1, expires)
	if err != nil || seal.Validate(header) != nil || seal.PageCount != 1 || seal.TailDigest != page.Digest || !seal.ExpiresAt.Equal(expires) {
		t.Fatal("exact complete summary was not bound", err)
	}
	for _, field := range []string{"entries", "hosts", "pages", "tail", "expiry"} {
		changed := seal
		switch field {
		case "entries":
			changed.EntryCount++
		case "hosts":
			changed.HostCount++
		case "pages":
			changed.PageCount++
		case "tail":
			changed.TailDigest = strings.Repeat("0", 64)
		case "expiry":
			changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
		}
		if changed.Validate(header) == nil {
			t.Fatalf("changed sealed %s retained authority", field)
		}
	}
	if _, err := NewRotationManifestSeal(header, page, 1, 2, expires); err == nil {
		t.Fatal("host count exceeded complete native references")
	}
}

func TestManifestKeepsSelectedHostsThatHaveNoNativeDependentsA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	empty := entry.Host
	empty.Binding.AgentID = "57900000-0000-4000-8000-000000000001"
	empty.InventoryRunID = "57900000-0000-4000-8000-000000000002"
	last, err := NewRotationManifestPageWithHosts(header, 1, first.Digest, []RotationManifestHost{empty}, nil)
	if err != nil || ValidateRotationManifestLink(header, last, &first) != nil {
		t.Fatal("selected host with an empty complete scan was omitted", err)
	}
	seal, err := NewRotationManifestSeal(header, last, 1, 2, header.ExpiresAt)
	if err != nil || seal.HostCount != 2 || seal.EntryCount != 1 {
		t.Fatal("host-only page invented an object or lost selected-host coverage", err)
	}
}

func TestManifestPageInputRejectsAliasesAndUnknownAuthorityA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	input := RotationManifestPageInput{HeaderDigest: digest, PreviousDigest: digest, Entries: []RotationManifestEntry{entry}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeRotationManifestPageInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Page(header, 0); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`,"Header_Digest":"other"}`, `,"unreviewed_reset":true}`} {
		changed := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(suffix)...)
		if _, err := DecodeRotationManifestPageInput(changed); err == nil {
			t.Fatal("ambiguous or unknown manifest request accepted")
		}
	}
}
func FuzzRotationManifestPageInputA267(f *testing.F) {
	header, entry := manifestFixture(f)
	digest, err := header.Digest()
	if err != nil {
		f.Fatal(err)
	}
	raw, err := json.Marshal(RotationManifestPageInput{HeaderDigest: digest, PreviousDigest: digest, Entries: []RotationManifestEntry{entry}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(append(append([]byte(nil), raw[:len(raw)-1]...), []byte(",\"unknown\":\"\xff\"}")...))
	f.Add([]byte(`{"header_digest":"a","Header_Digest":"b"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxRotationManifestPageBytes+1 {
			return
		}
		input, err := DecodeRotationManifestPageInput(raw)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRotationManifestPageInput(encoded); err != nil {
			t.Fatal("accepted request changed interpretation after encoding", err)
		}
	})
}
