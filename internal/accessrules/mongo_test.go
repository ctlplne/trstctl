// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"testing"
)

func TestMongoCommandClassesHaveExplicitAliasLimits(t *testing.T) {
	for _, tc := range []struct{ name, op string }{{"delete", "delete"}, {"findAndModify", "findandmodify"}, {"aggregate", "aggregate"}, {"atlasVersion", "atlasversion"}, {"endSessions", "endsessions"}, {"find", "find"}} {
		if got := MongoOperation([]byte(tc.name)); got != tc.op {
			t.Fatalf("command class %q = %q", tc.name, got)
		}
	}
	for _, raw := range [][]byte{[]byte("delete notes"), []byte("password-canary"), {}, []byte("delete\x00"), bytes.Repeat([]byte{'d'}, 65)} {
		if MongoOperation(raw) != "" {
			t.Fatal("arbitrary value became a command class")
		}
	}
}
func FuzzMongoOperationName(f *testing.F) {
	for _, name := range []string{"delete", "findAndModify", "aggregate", "password-canary", "delete\x00"} {
		f.Add([]byte(name))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		op := MongoOperation(raw)
		if !bytes.Equal(before, raw) {
			t.Fatal("classifier changed bytes")
		}
		if op != "" && !slices.Contains(mongoOperationNames, op) {
			t.Fatal("arbitrary value reached command facts")
		}
	})
}
