// SPDX-License-Identifier: BUSL-1.1

package secretmigrate

import (
	"strings"
	"testing"
)

func TestJSONSourceRejectsNestingPastThirtyTwoLevels(t *testing.T) {
	valid := strings.Repeat(`{"a":`, 32) + `"value"` + strings.Repeat("}", 32)
	if entries, err := parseJSON([]byte(valid)); err != nil || len(entries) != 1 {
		t.Fatalf("32-level source rejected: entries=%d err=%v", len(entries), err)
	}
	tooDeep := strings.Repeat(`{"a":`, 33) + `"value"` + strings.Repeat("}", 33)
	if _, err := parseJSON([]byte(tooDeep)); err == nil || !strings.Contains(err.Error(), "32 levels") {
		t.Fatalf("33-level source admitted: %v", err)
	}
}

func TestJSONSourceBoundsNodeCountDuringParse(t *testing.T) {
	values := make([]string, MaxObjects*64+1)
	for i := range values {
		values[i] = "null"
	}
	raw := "[" + strings.Join(values, ",") + "]"
	if _, err := parseJSON([]byte(raw)); err == nil || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("oversized JSON node tree admitted: %v", err)
	}
}

func TestJSONSourceRejectsDeepRequestWithoutWalkingEachSubtree(t *testing.T) {
	// The old RawMessage parser copied the unconsumed source at every level.
	// Keep this near the REST body limit so a regression is caught promptly.
	raw := strings.Repeat("[", 9999) + `"` + strings.Repeat("x", 900_000) + `"` + strings.Repeat("]", 9999)
	if _, err := parseJSON([]byte(raw)); err == nil || !strings.Contains(err.Error(), "32 levels") {
		t.Fatalf("deep request admitted: %v", err)
	}
}

func FuzzJSONSourceBounds(f *testing.F) {
	for _, seed := range []string{
		`{"a":"secret"}`,
		`[{"key":"a","value":"v"}]`,
		`{"a":[null,true,4.2]}`,
		`{"a":"\\u0000\\\""}`,
		`{`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		entries, err := parseJSON(raw)
		if err == nil {
			wipeEntries(entries)
		}
	})
}
