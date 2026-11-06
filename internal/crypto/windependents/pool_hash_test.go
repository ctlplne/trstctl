// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"bytes"
	"strings"
	"testing"
)

func TestPoolPrivateHashFramingAndBoundA267(t *testing.T) {
	first, err := newPoolHashBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer first.destroy()
	second, err := newPoolHashBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer second.destroy()
	for _, value := range [][]byte{[]byte("ab"), []byte("c")} {
		if err := first.field(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range [][]byte{[]byte("a"), []byte("bc")} {
		if err := second.field(value); err != nil {
			t.Fatal(err)
		}
	}
	if first.digest() == second.digest() || len(first.digest()) != 64 {
		t.Fatal("private configuration framing is ambiguous")
	}
	private := []byte("owned-private-environment-canary")
	if err := first.field(private); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(first.digest(), string(private)) {
		t.Fatal("private configuration escaped its digest")
	}
	if err := first.field(bytes.Repeat([]byte{'x'}, 2<<20)); err == nil {
		t.Fatal("oversized private configuration accepted")
	}
	first.destroy()
	if first.held != nil {
		t.Fatal("private configuration buffer remained available")
	}
}
