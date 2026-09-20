// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every certificate read must select through certificateColumns.
//
// This guard exists because the alternative already failed once. The column
// list was written out longhand in eight places across three files; adding the
// custody columns (epic B5) meant finding all eight, and missing one is not a
// compile error. It is a 500 on whichever read path nobody exercised locally —
// in that instance the plain certificate list, the most-used page in the
// product, discovered by a load harness rather than by a unit test.
//
// The scan and the column list now live beside each other and are used by
// reference. This test is what keeps the next person from re-introducing a
// literal copy, which would compile, pass review, and break one query.
func TestCertificateReadsUseTheSharedColumnList(t *testing.T) {
	// A literal certificate column list is recognizable by two columns that
	// appear together nowhere else in the schema.
	literal := regexp.MustCompile(`certificate_der,\s*issuance_idempotency_key`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !literal.MatchString(line) {
				continue
			}
			// The constant's own declaration is the one place it belongs.
			if withinConstDeclaration(string(src), line) {
				continue
			}
			t.Errorf("%s:%d writes the certificate column list out longhand:\n\t%s\n"+
				"Use `SELECT `+certificateColumns+` instead. A copy here compiles, and "+
				"then fails at runtime the next time a column is added to scanCertificate.",
				name, i+1, strings.TrimSpace(line))
		}
	}
}

// withinConstDeclaration reports whether the matched line belongs to the
// certificateColumns declaration rather than to a query.
func withinConstDeclaration(src, line string) bool {
	start := strings.Index(src, "const certificateColumns")
	if start < 0 {
		return false
	}
	end := strings.Index(src[start:], "`\n")
	if end < 0 {
		return false
	}
	return strings.Contains(src[start:start+end], strings.TrimSpace(line))
}

// The constant and the scanner must agree on how many columns there are.
//
// Counting is crude and deliberately so: it catches the specific mistake this
// package has already made — adding a column to one side only — without
// pretending to verify that the ORDER matches, which no static check can do.
// Order is caught by the store tests, which read real rows back.
func TestCertificateColumnCountMatchesScanner(t *testing.T) {
	src, err := os.ReadFile("certificate.go")
	if err != nil {
		t.Fatalf("read certificate.go: %v", err)
	}
	body := string(src)

	start := strings.Index(body, "const certificateColumns = `")
	if start < 0 {
		t.Fatal("certificateColumns declaration not found")
	}
	rest := body[start+len("const certificateColumns = `"):]
	end := strings.Index(rest, "`")
	if end < 0 {
		t.Fatal("certificateColumns declaration is unterminated")
	}
	columns := len(strings.Split(rest[:end], ","))

	scanStart := strings.Index(body, "func scanCertificate(")
	if scanStart < 0 {
		t.Fatal("scanCertificate not found")
	}
	scanBody := body[scanStart:]
	if stop := strings.Index(scanBody, "\n}"); stop > 0 {
		scanBody = scanBody[:stop]
	}
	destinations := strings.Count(scanBody, "&c.")

	if columns != destinations {
		t.Errorf("certificateColumns selects %d columns but scanCertificate reads %d destinations.\n"+
			"Every SELECT sharing this list will fail at runtime with "+
			"\"number of field descriptions must equal number of destinations\".",
			columns, destinations)
	}
}
