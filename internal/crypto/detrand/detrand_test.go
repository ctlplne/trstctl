package detrand_test

import (
	"bytes"
	"io"
	"testing"

	"trstctl.com/trstctl/internal/crypto/detrand"
)

// The stream is a pure function of the seed: identical seeds produce identical
// bytes.
func TestSameSeedSameStream(t *testing.T) {
	a := make([]byte, 96)
	b := make([]byte, 96)
	if _, err := io.ReadFull(detrand.New([]byte("trstctl"), []byte("seed")), a); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(detrand.New([]byte("trstctl"), []byte("seed")), b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("same seed must produce the same stream")
	}
}

// Different seeds produce different streams; length-prefixing prevents boundary
// collisions (["ab","c"] != ["a","bc"]).
func TestDifferentSeedDifferentStream(t *testing.T) {
	read := func(parts ...[]byte) []byte {
		out := make([]byte, 64)
		_, _ = io.ReadFull(detrand.New(parts...), out)
		return out
	}
	if bytes.Equal(read([]byte("x")), read([]byte("y"))) {
		t.Error("different seeds must differ")
	}
	if bytes.Equal(read([]byte("ab"), []byte("c")), read([]byte("a"), []byte("bc"))) {
		t.Error("part boundaries must affect the stream (length-prefixing)")
	}
}

// Read never returns a short read regardless of buffer size, and is stable
// across chunked reads.
func TestReadIsChunkStable(t *testing.T) {
	whole := make([]byte, 100)
	if _, err := io.ReadFull(detrand.New([]byte("s")), whole); err != nil {
		t.Fatal(err)
	}
	r := detrand.New([]byte("s"))
	chunked := make([]byte, 0, 100)
	for len(chunked) < 100 {
		buf := make([]byte, 7)
		n, _ := r.Read(buf)
		if n != 7 {
			t.Fatalf("short read: %d", n)
		}
		chunked = append(chunked, buf...)
	}
	if !bytes.Equal(whole, chunked[:100]) {
		t.Error("chunked reads must match a single read of the same stream")
	}
}
