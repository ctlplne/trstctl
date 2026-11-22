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

func TestCR004PostgresLexerDivergenceFailsClosed(t *testing.T) {
	longTag := strings.Repeat("t", 300)
	for _, tc := range []struct{ name, sql string }{
		{"non-ASCII dollar tag", "SELECT $ä$'$ä$; DELETE FROM victim; --'"},
		{"comment nesting beyond classifier limit", "SELECT 'a\\' AS x; DELETE FROM victim; " + strings.Repeat("/*", 65) + strings.Repeat("*/", 65) + " -- '\n"},
		{"dollar tag beyond classifier limit", "SELECT 'a\\' AS x; DELETE FROM victim WHERE $" + longTag + "$x$" + longTag + "$ <> '' -- '"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops, err := PostgresRuleOperations([]byte(tc.sql))
			if err == nil && !slices.Contains(ops, "DELETE") {
				t.Fatalf("PostgreSQL executes DELETE but classifier accepted %v without review", ops)
			}
		})
	}
}

func TestCR004PostgresEncodingControlsAreUnsupported(t *testing.T) {
	for _, sql := range []string{"SET client_encoding TO 'SJIS'", "RESET client_encoding", "DISCARD ALL"} {
		ops, err := PostgresRuleOperations([]byte(sql))
		if err != nil || !UnsupportedPostgresControl(ops) {
			t.Errorf("encoding control %q = %v, %v; want refused control", sql, ops, err)
		}
	}
}

func TestA262UpdateSetDoesNotBypassOrTriggerSessionControlFence(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		refuse    bool
	}{
		{"ordinary update", "UPDATE public.a262_counter SET value=$1::integer WHERE $2::text IS NOT NULL RETURNING value", false},
		{"quoted control name", `UPDATE public.notes SET "set"=$1`, false},
		{"session control after update", "UPDATE public.notes SET value=1; /* between */ SET client_encoding TO 'SJIS'", true},
		{"session control before update", "/* before */ SET client_encoding TO 'SJIS'; UPDATE public.notes SET value=1", true},
		{"prepare control", "PREPARE hidden AS UPDATE public.notes SET value=1", true},
		{"other control after update", "UPDATE public.notes SET value=1; EXECUTE hidden", true},
		{"reset control", "RESET client_encoding", true},
		{"discard control", "DISCARD ALL", true},
		{"uninspectable input", "UPDATE public.notes SET value='unterminated", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operations, err := PostgresRuleOperations([]byte(tc.sql))
			if err != nil && tc.name != "uninspectable input" {
				t.Fatal(err)
			}
			if got := UnsupportedPostgresControlStatement([]byte(tc.sql), operations); got != tc.refuse {
				t.Fatalf("control fence = %t for %q (%v), want %t", got, tc.sql, operations, tc.refuse)
			}
		})
	}
}

func TestA275OnlyAuditedLogStatementSettingMayReachACommandRule(t *testing.T) {
	for _, tc := range []struct {
		sql             string
		auditable, deny bool
	}{
		{"SET log_statement = 'none'", true, false},
		{"SeT /* reviewed */ log_statement TO 'none'", true, false},
		{"SET log_statement = 'none'; SET client_encoding TO 'SJIS'", false, true},
		{"SET client_encoding TO 'SJIS'", false, true},
		{"SET search_path TO public", false, true},
		{"SET log_min_duration_statement TO -1", false, true},
		{"UPDATE public.notes SET log_statement='none'", false, false},
	} {
		ops, err := PostgresRuleOperations([]byte(tc.sql))
		if err != nil {
			t.Fatalf("classify %q: %v", tc.sql, err)
		}
		if got := PostgresAuditedLogSetting([]byte(tc.sql), ops); got != tc.auditable {
			t.Errorf("audited setting %q = %t, want %t", tc.sql, got, tc.auditable)
		}
		if got := UnsupportedPostgresControlStatement([]byte(tc.sql), ops); got != tc.deny {
			t.Errorf("control refusal %q = %t, want %t", tc.sql, got, tc.deny)
		}
	}
}

func FuzzPostgresOperationMetadata(f *testing.F) {
	for _, sql := range []string{"TRUNCATE notes", "SELECT 'TRUNCATE'", "DO $$ BEGIN EXECUTE 'DROP TABLE notes'; END $$", "/* a /* b */ c */ DROP TABLE notes", "SELECT E'a\\\\b'", "UPDATE notes SET value=1", "UPDATE notes SET value=1; SET client_encoding TO 'SJIS'", strings.Repeat("$", 300)} {
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
		ruleOps, err := PostgresRuleOperations(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, control := range []string{"PREPARE", "EXECUTE", "RESET", "DISCARD"} {
			if slices.Contains(ruleOps, control) && !UnsupportedPostgresControlStatement(raw, ruleOps) {
				t.Fatalf("control %s escaped the statement fence", control)
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
