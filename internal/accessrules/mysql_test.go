// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestMySQLRulesInspectExecutableCommentsAndKeepValuesOut(t *testing.T) {
	for _, tc := range []struct {
		sql     string
		deleted bool
	}{
		{"DELETE FROM notes", true}, {"/* ordinary */ dElEtE FROM notes", true},
		{"/*!80000 DELETE FROM notes */", true}, {"/*! DELETE FROM notes */", true},
		{"# DELETE hidden\nSELECT 1", false}, {"-- DELETE hidden\nSELECT 1", false},
		{"SELECT 'DELETE credential-shaped-value'", false}, {"SELECT `DELETE` FROM notes", false},
		{"CALL clear_notes()", false}, {"SELECT 1; DELETE FROM notes", true},
		{"SELECT 'escaped \\' DELETE hidden'", false},
	} {
		got, err := MySQLOperations([]byte(tc.sql))
		if err != nil || slices.Contains(got, "DELETE") != tc.deleted {
			t.Fatalf("%q = %v %v; DELETE %v", tc.sql, got, err, tc.deleted)
		}
	}
	for variant := 0; variant < 64; variant++ {
		word := []byte("DELETE")
		for i := range word {
			if variant>>i&1 != 0 {
				word[i] += 'a' - 'A'
			}
		}
		got, err := MySQLOperations(append(append([]byte("/*!80000 "), word...), []byte(" FROM notes */")...))
		if err != nil || !slices.Contains(got, "DELETE") {
			t.Fatal("executable comment hid a direct operation")
		}
	}
	for _, raw := range [][]byte{[]byte("SELECT 'unterminated"), []byte("/* unterminated"), {0xff}, []byte("SELECT\x00 1"), bytes.Repeat([]byte{'x'}, MaxStatementBytes+1)} {
		if _, err := MySQLOperations(raw); err == nil {
			t.Fatal("uninspectable MySQL accepted")
		}
	}
	for _, sql := range []string{"PREPARE a FROM 'DELETE FROM notes'", "EXECUTE a", "DEALLOCATE PREPARE a", "LOAD DATA LOCAL INFILE 'owned' INTO TABLE notes"} {
		ops, err := MySQLOperations([]byte(sql))
		if err != nil || !UnsupportedMySQLControl(ops) {
			t.Fatalf("unsupported execution control escaped: %v %v", ops, err)
		}
	}
}

func TestMySQLClassifierAllocationBoundDependsOnFacts(t *testing.T) {
	for _, sql := range []string{"DELETE FROM notes", strings.Repeat("DELETE ", MaxStatementBytes/7), strings.Repeat("/*! DELETE */ ", MaxStatementBytes/14)} {
		raw := []byte(sql)
		allocations := testing.AllocsPerRun(3, func() {
			ops, err := MySQLOperations(raw)
			if err != nil || !slices.Contains(ops, "DELETE") {
				panic("classifier lost operation")
			}
		})
		if allocations > 8 {
			t.Fatalf("allocation count grew with traffic: %v", allocations)
		}
	}
}

func FuzzMySQLOperationMetadata(f *testing.F) {
	for _, raw := range []string{"DELETE FROM notes", "/*!80000 DELETE FROM notes */", "SELECT 'DELETE value'", "PREPARE a FROM 'DELETE FROM notes'", "SELECT `DELETE`", strings.Repeat("/*! DELETE */ ", 50)} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		ops, err := MySQLOperations(raw)
		if !bytes.Equal(before, raw) {
			t.Fatal("classifier changed held traffic")
		}
		if err != nil {
			return
		}
		if !slices.IsSorted(ops) || len(ops) > len(mysqlClassifierNames) {
			t.Fatal("unbounded operation facts")
		}
		for i, op := range ops {
			if !slices.Contains(mysqlClassifierNames, op) || i > 0 && op == ops[i-1] {
				t.Fatal("value escaped public vocabulary")
			}
		}
	})
}
