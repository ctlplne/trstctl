// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"testing"
)

func TestRedisOperationNameNeverBecomesAnArgument(t *testing.T) {
	for _, name := range [][]byte{[]byte("DEL"), []byte("del"), []byte("dEl")} {
		if RedisOperation(name) != "DEL" {
			t.Fatal("direct command lost its public class")
		}
	}
	for _, name := range [][]byte{[]byte("DEL key"), []byte("password-canary"), {}, bytes.Repeat([]byte{'D'}, 65), []byte("DEL\x00")} {
		if RedisOperation(name) != "" {
			t.Fatal("arbitrary input became public facts")
		}
	}
	for _, op := range []string{"GET", "SET", "DEL", "EVAL"} {
		if RedisOperation([]byte(op)) != op {
			t.Fatalf("supported direct operation lost: %s", op)
		}
	}
	if RedisOperation([]byte("EVAL")) != "EVAL" {
		t.Fatal("script wrapper class lost")
	}
}
func FuzzRedisOperationName(f *testing.F) {
	for _, raw := range []string{"DEL", "del", "EVAL", "password-canary", "DEL\x00"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		op := RedisOperation(raw)
		if !bytes.Equal(before, raw) {
			t.Fatal("name classifier changed bytes")
		}
		if op != "" && !slices.Contains(redisOperationNames, op) {
			t.Fatal("arbitrary value became operation")
		}
	})
}
