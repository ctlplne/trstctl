// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestPostgresClassifierKeepsValuesOutOfRuleInput(t *testing.T) {
	for _, test := range []struct {
		sql      string
		truncate bool
	}{
		{"TRUNCATE public.notes", true},
		{"/* before /* nested */ after */ tRuNcAtE /* split */ public.notes", true},
		{"SELECT 1; TRUNCATE public.notes", true},
		{"SELECT 'TRUNCATE secret-shaped-value'", false},
		{`SELECT "TRUNCATE" FROM public.notes`, false},
		{"SELECT $$TRUNCATE secret-shaped-value$$", false},
		{"SELECT $tag_262$TRUNCATE secret-shaped-value$tag_262$", false},
		{"SELECT E'TRUNCATE \\' quote'", false},
		{"-- TRUNCATE public.notes\nSELECT 1", false},
		{"DO $$ BEGIN EXECUTE 'TRUNCATE public.notes'; END $$", false},
		{"SELECT truncater FROM public.notes", false},
		{"SELECT 'a\\b'", false},
	} {
		t.Run(test.sql, func(t *testing.T) {
			ops, err := PostgresOperations([]byte(test.sql))
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(ops, "TRUNCATE"); got != test.truncate {
				t.Fatalf("operations = %v, want truncate %v", ops, test.truncate)
			}
			for _, op := range ops {
				if !knownPostgresOperation(op) {
					t.Fatalf("traffic value escaped the classifier: %q", op)
				}
			}
		})
	}
	for _, bad := range [][]byte{[]byte("SELECT 'unterminated"), []byte("/* unterminated"), []byte("SELECT $$unterminated"), {0xff}, []byte("SELECT\x00 1"), bytes.Repeat([]byte{'x'}, MaxStatementBytes+1)} {
		if _, err := PostgresOperations(bad); err == nil {
			t.Fatal("uninspectable input accepted")
		}
	}
}

func TestDirectOperationSurvivesOrdinaryCaseCommentsAndBatches(t *testing.T) {
	for variant := range 256 {
		word := []byte("TRUNCATE")
		for i := range word {
			if variant>>i&1 == 1 {
				word[i] += 'a' - 'A'
			}
		}
		sql := "/* prefix */ SELECT 'not a command'; \n\t" + string(word) + " /* target */ public.notes; -- trailer"
		ops, err := PostgresOperations([]byte(sql))
		if err != nil || !slices.Contains(ops, "TRUNCATE") {
			t.Fatalf("direct statement lost = %v, %v", ops, err)
		}
		quoted := "SELECT '" + string(word) + " public.notes'"
		ops, err = PostgresOperations([]byte(quoted))
		if err != nil || slices.Contains(ops, "TRUNCATE") {
			t.Fatalf("a value became an operation = %v, %v", ops, err)
		}
	}
}

func FuzzPostgresOperationMetadata(f *testing.F) {
	for _, sql := range []string{"TRUNCATE notes", "SELECT 'TRUNCATE'", "DO $$ BEGIN EXECUTE 'DROP TABLE notes'; END $$", "/* a /* b */ c */ DROP TABLE notes", "SELECT E'a\\\\b'", strings.Repeat("$", 300)} {
		f.Add([]byte(sql))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		original := bytes.Clone(raw)
		ops, err := PostgresOperations(raw)
		if !bytes.Equal(raw, original) {
			t.Fatal("classifier changed traffic bytes")
		}
		if err != nil {
			return
		}
		if !slices.IsSorted(ops) || len(ops) > 32 {
			t.Fatalf("unbounded or unordered metadata = %v", ops)
		}
		for i, op := range ops {
			if !knownPostgresOperation(op) || i > 0 && ops[i-1] == op {
				t.Fatalf("unsafe or repeated metadata = %q", op)
			}
		}
	})
}

// The input bound is not permission to allocate one policy fact per token.
// Repeated operation words must retain only the finite operation vocabulary.
func TestOperationMetadataAllocationStaysBoundedForRepeatedKeywords(t *testing.T) {
	small := bytes.Repeat([]byte("DO "), 4)
	large := bytes.Repeat([]byte("DO "), MaxStatementBytes/3)
	measure := func(raw []byte) float64 {
		return testing.AllocsPerRun(3, func() {
			ops, err := PostgresOperations(raw)
			if err != nil || len(ops) != 1 || ops[0] != "DO" {
				panic("invalid operation metadata")
			}
		})
	}
	smallCount, largeCount := measure(small), measure(large)
	t.Logf("repeated-keyword allocations small=%.0f maximum-input=%.0f", smallCount, largeCount)
	if largeCount > smallCount+32 {
		t.Fatalf("metadata allocations scale with repeated untrusted words: small=%.0f large=%.0f", smallCount, largeCount)
	}
}
