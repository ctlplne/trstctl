// SPDX-License-Identifier: BUSL-1.1

package switchkit

import (
	"fmt"
	"strings"
	"testing"
)

// The cap must fire while parsing. Reporting the full attacker's row count
// means all of its maps were allocated before the check.
func TestParseStopsAtFirstExcessRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"csv", "common_name\n" + strings.Repeat("a\n", 2*MaxRows)},
		{"json", "[" + strings.Repeat("{},", 2*MaxRows-1) + "{}]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.data), nil)
			want := fmt.Sprintf("%d rows, more than %d", MaxRows+1, MaxRows)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Parse error = %v, want early limit %q", err, want)
			}
		})
	}
}

func TestParseCapsFieldsPerRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"csv", strings.Repeat("x,", 256) + "x\na\n"},
		{"json", "[{" + strings.TrimSuffix(strings.Repeat(`"x":0,`, 257), ",") + "}]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.data), nil); err == nil || !strings.Contains(err.Error(), "fields") {
				t.Fatalf("Parse error = %v, want fields limit", err)
			}
		})
	}
}

func FuzzParseSwitchingExport(f *testing.F) {
	for _, seed := range []string{
		"common_name,folder\nexample.test,prod\n",
		`[{"common_name":"example.test","sans":["a.test","b.test"]}]`,
		`{"certificates":[{"common_name":"example.test"}]}`,
		`[{"common_name":null},null]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := Parse(data, nil)
		if err != nil {
			return
		}
		if len(rows) > MaxRows {
			t.Fatalf("accepted %d rows", len(rows))
		}
		for _, row := range rows {
			if len(row.Fields) > MaxFieldsPerRow {
				t.Fatalf("accepted %d fields in row %d", len(row.Fields), row.Number)
			}
		}
	})
}
