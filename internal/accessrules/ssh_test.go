// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestSSHCommandPositionsExcludeArgumentsAndExposeGuardrailLimits(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"rm /owned/file", []string{"rm"}},
		{"/bin/rm -- /owned/file", []string{"rm"}},
		{"r\\m /owned/file", []string{"rm"}},
		{"'rm' /owned/file", []string{"rm"}},
		{"X='credential-shaped-value' rm /owned/file", []string{"rm"}},
		{"2>/dev/null rm /owned/file", []string{"rm"}},
		{"echo 'rm hidden'; rm /owned/file | sh", []string{"rm", "sh"}},
		{"if test -f /owned/file; then rm /owned/file; fi", []string{"rm"}},
		{"# rm hidden\necho rm", []string{}},
		{"sh -c 'rm /owned/file'", []string{"sh"}},
		{"echo 'credential-shaped-value rm'", []string{}},
		{"RM /owned/file", []string{}},
	} {
		got, err := SSHOperations([]byte(tc.raw))
		if err != nil || !slices.Equal(got, tc.want) {
			t.Fatalf("%q = %v, %v; want %v", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range [][]byte{[]byte("cat <<EOF\nrm file\nEOF"), []byte("rm 'unterminated"), {0xff}, []byte("rm\x00 file"), bytes.Repeat([]byte{'x'}, MaxSSHCommandBytes+1), []byte(strings.Repeat("x", 4097))} {
		if _, err := SSHOperations(raw); err == nil {
			t.Fatal("uninspectable SSH command accepted")
		}
	}
	// Property: changing arbitrary argument bytes cannot turn them into a selector.
	for n := 0; n < 256; n++ {
		arg := strings.Repeat("a", n) + " rm credential-shaped-value"
		got, err := SSHOperations([]byte("printf '" + arg + "'"))
		if err != nil || len(got) != 0 {
			t.Fatalf("argument escaped classifier: %v %v", got, err)
		}
	}
}

func FuzzSSHOperationMetadata(f *testing.F) {
	for _, raw := range []string{"rm /owned/file", "sh -c 'rm file'", "X='value' rm file", "echo $(rm file)", "cat <<EOF\nrm file\nEOF", "'unterminated"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		original := bytes.Clone(raw)
		ops, err := SSHOperations(raw)
		if !bytes.Equal(original, raw) {
			t.Fatal("classifier changed held traffic")
		}
		if err != nil {
			return
		}
		if !slices.IsSorted(ops) || len(ops) > MaxOperations {
			t.Fatal("unbounded facts")
		}
		for i, op := range ops {
			if !KnownOperation("ssh", op) || i > 0 && ops[i-1] == op {
				t.Fatal("nonpublic fact escaped classifier")
			}
		}
	})
}
