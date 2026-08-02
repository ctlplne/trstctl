// SPDX-License-Identifier: LicenseRef-trstctl-EE

package proptest

import "testing"

// TestSameSeedSameStream is the property the whole package exists for. If this
// ever fails, every property test in ee/ has silently stopped being reproducible
// and their printed seeds are worthless.
func TestSameSeedSameStream(t *testing.T) {
	for _, seed := range []int64{0, 1, -1, 0xA61D04B, 1 << 62, -(1 << 62)} {
		a, b := New(seed), New(seed)
		for i := 0; i < 64; i++ {
			if x, y := a.Uint64(), b.Uint64(); x != y {
				t.Fatalf("seed %d diverged at draw %d: %d != %d", seed, i, x, y)
			}
		}
	}
}

// TestDistinctSeedsDistinctStreams guards the seed mixing: a negative seed must
// not collide with a positive one, which a naive narrowing would allow.
func TestDistinctSeedsDistinctStreams(t *testing.T) {
	seen := map[uint64]int64{}
	for _, seed := range []int64{0, 1, -1, 2, -2, 1 << 62, -(1 << 62), 0x7FFFFFFFFFFFFFFF} {
		first := New(seed).Uint64()
		if prev, dup := seen[first]; dup {
			t.Errorf("seeds %d and %d produce the same first draw %d", prev, seed, first)
		}
		seen[first] = seed
	}
}

// TestIntnStaysInRange checks the bound that replaced a narrowing conversion.
func TestIntnStaysInRange(t *testing.T) {
	r := New(42)
	for _, n := range []int{1, 2, 3, 7, 256, 1 << 20} {
		for i := 0; i < 2000; i++ {
			if v := r.Intn(n); v < 0 || v >= n {
				t.Fatalf("Intn(%d) = %d, out of range", n, v)
			}
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("Intn(0) must panic, matching math/rand")
		}
	}()
	r.Intn(0)
}

// TestPermAndShuffleAreTotal proves Perm returns a permutation (not just numbers
// in range) and Shuffle touches the whole slice.
func TestPermAndShuffleAreTotal(t *testing.T) {
	r := New(7)
	for _, n := range []int{0, 1, 2, 5, 50} {
		seen := make([]bool, n)
		for _, v := range r.Perm(n) {
			if v < 0 || v >= n || seen[v] {
				t.Fatalf("Perm(%d) is not a permutation: repeated or out-of-range %d", n, v)
			}
			seen[v] = true
		}
	}
	// A shuffle of a large slice must move something; a no-op Shuffle would let a
	// test that depends on ordering pass for the wrong reason.
	in := make([]int, 64)
	for i := range in {
		in[i] = i
	}
	out := append([]int(nil), in...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	same := true
	for i := range in {
		if in[i] != out[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Shuffle left a 64-element slice untouched")
	}
}

// TestReadFillsEveryByte covers the partial-word path at the end of a buffer.
func TestReadFillsEveryByte(t *testing.T) {
	for _, n := range []int{0, 1, 7, 8, 9, 33} {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = 0xAA
		}
		got, err := New(3).Read(buf)
		if got != n || err != nil {
			t.Fatalf("Read(%d bytes) = %d, %v", n, got, err)
		}
		if n >= 8 {
			all := true
			for _, b := range buf {
				if b != 0xAA {
					all = false
					break
				}
			}
			if all {
				t.Errorf("Read(%d) left the buffer untouched", n)
			}
		}
	}
}
