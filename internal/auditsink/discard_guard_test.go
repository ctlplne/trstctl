// SPDX-License-Identifier: MPL-2.0

package auditsink_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bareAuditDiscard matches a silently-discarded audit/event-emit write —
// `_ = <expr>.Audit(...)` — the exact anti-pattern CODE-001 found at 46 sites. It
// does NOT match the sanctioned non-discarding idiom `_ = auditsink.Emit(...)`
// (which counts + logs the drop) because that call is `.Emit(`, not `.Audit(`.
var bareAuditDiscard = regexp.MustCompile(`_\s*=\s*[A-Za-z_][A-Za-z0-9_.]*\.Audit\(`)

// TestNoSilentAuditErrorDiscard is the CODE-001 regression guard: no production
// (non-test) Go file under internal/ may silently discard an audit/event-emit
// error with `_ = x.Audit(...)`. A failed AN-2 event-log append is a lost
// source-of-truth/audit record; it must be either propagated (fail closed on a
// source-of-truth path) or recorded via auditsink.Emit (which increments the
// dropped-event metric and logs at WARN) — never dropped. Re-adding a bare
// discard trips this test.
//
// The test walks internal/ from this package directory (cwd = internal/auditsink,
// so ".." is internal/).
func TestNoSilentAuditErrorDiscard(t *testing.T) {
	root := ".." // internal/
	var offenders []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		for i, line := range strings.Split(src, "\n") {
			// Skip comment lines (the doc comments in auditsink.go/audit/sink.go
			// reference the anti-pattern by name).
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if bareAuditDiscard.MatchString(line) {
				offenders = append(offenders, path+":"+itoa(i+1)+":  "+trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("CODE-001: %d silently-discarded audit/event-emit write(s) found — propagate the error (fail closed on source-of-truth paths) or use auditsink.Emit, never `_ = x.Audit(...)`:\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
