// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"testing"
)

// Q6-L4: a finding's line, or a line beside it, that holds a known value is
// that value; one further away is not, a value too short to tell from text is
// never matched, and the file is read only inside the scanned tree: not by a
// path outside it and not through a link that leaves it.
func TestMatchKnownValueStaysInTheScannedTreeQ6L4(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	const bait = "trstctl-bait-0123456789abcdef" // #nosec G101 -- fabricated decoy fixture; no value is real (CWE-798)
	files := map[string]string{
		"app.env":       "# payments\nKEY=" + bait + "\nREGION=eu\n",
		"far.env":       "KEY=one\nA=1\nB=2\nC=3\nKEY2=" + bait + "\n",
		"short.env":     "PIN=1234567\n",
		"nested/ci.yml": "env:\n  TOKEN: " + bait + "\n",
	}
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte("KEY="+bait+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(root, "linked.env")); err != nil {
		t.Fatal(err)
	}
	known := []KnownValue{{ID: "d-1", Name: "lure", Value: []byte(bait)}, {ID: "d-2", Name: "pin", Value: []byte("1234567")}}
	for _, tc := range []struct {
		name, file string
		line       int
		want       string
	}{
		{"on the line", "app.env", 2, "d-1"},
		{"beside the line", "app.env", 1, "d-1"},
		{"absolute path in the tree", filepath.Join(root, "nested", "ci.yml"), 2, "d-1"},
		{"three lines away", "far.env", 1, ""},
		{"too short to tell", "short.env", 1, ""},
		{"a path outside the tree", filepath.Join(outside, "secret.env"), 1, ""},
		{"a relative path out of the tree", "../" + filepath.Base(outside) + "/secret.env", 1, ""},
		{"a link that leaves the tree", "linked.env", 1, ""},
		{"no such line", "app.env", 40, ""},
	} {
		got, ok := MatchKnownValue(root, tc.file, tc.line, known)
		if (tc.want != "") != ok || got.ID != tc.want {
			t.Fatalf("%s: matched %q (%v), want %q", tc.name, got.ID, ok, tc.want)
		}
	}
	if _, ok := MatchKnownValue(root, "app.env", 2, nil); ok {
		t.Fatal("matched with no known values")
	}
	WipeKnownValues(known)
	for _, b := range known[0].Value {
		if b != 0 {
			t.Fatal("WipeKnownValues left the value")
		}
	}
}
