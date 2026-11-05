// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestClickHouseSQLClassesExcludeValuesAndComments(t *testing.T) {
	for _, tc := range []struct {
		sql       string
		truncates bool
	}{{"TRUNCATE TABLE notes", true}, {"/* outer /* inner */ end */ tRuNcAtE TABLE notes", true}, {"SELECT 'TRUNCATE value'", false}, {"SELECT `TRUNCATE` FROM notes", false}, {"SELECT $tag$TRUNCATE value$tag$", false}, {"// TRUNCATE hidden\nSELECT 1", false}, {"#! TRUNCATE hidden\nSELECT 1", false}, {"# TRUNCATE hidden\nSELECT 1", false}, {"SELECT 1; TRUNCATE TABLE notes", true}, {"ALTER TABLE notes DELETE WHERE id=1", false}} {
		ops, err := ClickHouseOperations([]byte(tc.sql))
		if err != nil || slices.Contains(ops, "TRUNCATE") != tc.truncates {
			t.Fatalf("%q = %v %v", tc.sql, ops, err)
		}
	}
	for _, raw := range [][]byte{[]byte("SELECT 'unterminated"), []byte("/* unterminated"), []byte("SELECT\x00 1"), {0xff}, bytes.Repeat([]byte{'x'}, MaxStatementBytes+1)} {
		if _, err := ClickHouseOperations(raw); err == nil {
			t.Fatal("uninspectable input accepted")
		}
	}
	for _, sql := range []string{"INSERT INTO notes FORMAT CSV", "EXECUTE AS someone"} {
		ops, err := ClickHouseOperations([]byte(sql))
		if err != nil || !UnsupportedClickHouseControl(ops) {
			t.Fatal("encoded data or identity switch was inspectable")
		}
	}
	raw := []byte(strings.Repeat("TRUNCATE ", MaxStatementBytes/9))
	if n := testing.AllocsPerRun(3, func() {
		ops, err := ClickHouseOperations(raw)
		if err != nil || !slices.Contains(ops, "TRUNCATE") {
			panic("lost operation")
		}
	}); n > 8 {
		t.Fatalf("allocations grow with repeated traffic: %v", n)
	}
}
func FuzzClickHouseOperationMetadata(f *testing.F) {
	for _, raw := range []string{"TRUNCATE TABLE notes", "SELECT 'TRUNCATE value'", "/* a /* b */ c */ TRUNCATE notes", "INSERT INTO notes FORMAT CSV", "SELECT $tag$value$tag$"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		ops, err := ClickHouseOperations(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("classifier changed traffic")
		}
		if err != nil {
			return
		}
		if !slices.IsSorted(ops) || len(ops) > len(clickhouseClassifierNames) {
			t.Fatal("unbounded facts")
		}
		for i, op := range ops {
			if !slices.Contains(clickhouseClassifierNames, op) || i > 0 && op == ops[i-1] {
				t.Fatal("value reached public metadata")
			}
		}
	})
}
