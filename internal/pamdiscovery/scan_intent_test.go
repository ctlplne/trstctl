// SPDX-License-Identifier: BUSL-1.1
package pamdiscovery

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func scanIntentFixtureA267() ScanIntent {
	return ScanIntent{RunID: "57000000-0000-4000-8000-000000000001", CompletionEventID: "57000000-0000-4000-8000-000000000002", ProviderID: "owned-ad", SourceSavedAt: time.Date(2026, 11, 6, 1, 0, 0, 0, time.UTC), RequestedBy: "operator@example.test", QueuedAt: time.Date(2026, 11, 6, 1, 1, 0, 0, time.UTC)}
}
func TestScanIntentNeedsExactPublicBindingA267(t *testing.T) {
	valid := scanIntentFixtureA267()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ScanIntent){
		func(i *ScanIntent) { i.RunID = i.CompletionEventID },
		func(i *ScanIntent) { i.ProviderID = "" },
		func(i *ScanIntent) { i.ProviderID = "owned\nad" },
		func(i *ScanIntent) { i.RequestedBy = "\x00" },
		func(i *ScanIntent) { i.RequestedBy = strings.Repeat("x", 1025) },
		func(i *ScanIntent) { i.SourceSavedAt = time.Time{} },
		func(i *ScanIntent) { i.QueuedAt = time.Time{} },
	} {
		changed := valid
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("incomplete source intent accepted")
		}
	}
	property := func(seed uint16) bool {
		intent := valid
		intent.SourceSavedAt = intent.SourceSavedAt.Add(time.Duration(seed) * time.Microsecond)
		raw, err := json.Marshal(intent)
		if err != nil {
			return false
		}
		var decoded ScanIntent
		return json.Unmarshal(raw, &decoded) == nil && decoded.Validate() == nil && decoded.SourceSavedAt.Equal(intent.SourceSavedAt) && decoded.RunID == intent.RunID && decoded.CompletionEventID == intent.CompletionEventID
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func FuzzDiscoveryScanIntentA267(f *testing.F) {
	valid, err := json.Marshal(scanIntentFixtureA267())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		var intent ScanIntent
		if json.Unmarshal(raw, &intent) != nil || intent.Validate() != nil {
			return
		}
		canonical, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		var reopened ScanIntent
		if json.Unmarshal(canonical, &reopened) != nil || reopened.Validate() != nil || !reopened.QueuedAt.Equal(intent.QueuedAt) || !reopened.SourceSavedAt.Equal(intent.SourceSavedAt) || reopened.ProviderID != intent.ProviderID || reopened.RequestedBy != intent.RequestedBy {
			t.Fatal("valid queued source changed on canonical round trip")
		}
	})
}
