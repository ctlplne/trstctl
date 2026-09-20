// SPDX-License-Identifier: BUSL-1.1

// Package proptest provides the deterministic pseudo-random source the ee/
// property and fuzz tests draw from.
//
// It exists because the two obvious options are both wrong for property testing:
//
//   - math/rand is what these tests used, and gosec rejects it (G404). The
//     rejection is right in general — math/rand must never seed anything
//     security-relevant — but the finding cannot be waived away either, because a
//     waiver per site is 13 sticky notes saying "this one is fine, trust me".
//   - crypto/rand satisfies the linter and DESTROYS the tests. A property test
//     earns its keep by being reproducible: when the CI run that fails prints
//     seed 0xA61D04B, you re-run that seed and get the same counterexample. Seed
//     it from crypto/rand and a failure is a one-off anecdote nobody can chase.
//
// So this is a third option: an explicit, documented, deterministic generator
// that is nobody's idea of a CSPRNG and cannot be mistaken for one. The name of
// the package is the safety argument — proptest.New(seed) at a call site says
// "test data" the way rand.New(rand.NewSource(seed)) never quite did.
//
// The algorithm is splitmix64 (Steele, Lea & Flood 2014), the same generator Go's
// own math/rand/v2 uses to seed its state. It is chosen for being tiny enough to
// read in one sitting, having no hidden state beyond a single uint64, and
// producing an identical stream on every platform and Go version — which matters,
// because a golden counterexample that only reproduces on the machine that found
// it is not reproducible.
//
// NEVER use this for key material, nonces, tokens, or anything an adversary sees.
// It is trivially predictable from two outputs. For those, use
// internal/crypto (AN-3).
package proptest

// Rand is a deterministic source of test data. The zero value is not usable;
// construct one with New.
//
// The method set deliberately mirrors the subset of *math/rand.Rand these tests
// used (Intn, Perm, Shuffle, Read), so converting a test is a one-line change to
// the constructor and nothing else moves.
type Rand struct {
	state uint64
}

// New returns a Rand that produces the same stream for the same seed, on every
// platform and every Go version.
func New(seed int64) *Rand {
	// The seed is reinterpreted, not narrowed: the eight bytes of the int64 become
	// the eight bytes of the state, so every seed maps to a distinct stream and a
	// negative seed cannot collide with a positive one. Taking it a byte at a time
	// keeps the whole conversion a widening (byte -> uint64), which is safe by
	// construction rather than by a comment claiming it is.
	var state uint64
	for i := 0; i < 8; i++ {
		state = state<<8 | uint64(byte(seed>>(56-8*i)&0xFF))
	}
	return &Rand{state: state}
}

// Uint64 returns the next value in the stream.
func (r *Rand) Uint64() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// Int63 returns a non-negative value in [0, 1<<63).
//
// The shift is what makes the result non-negative by construction rather than by
// assertion: clearing the top bit leaves a value that always fits int64.
func (r *Rand) Int63() int64 { return int64(r.Uint64() >> 1) }

// Intn returns a value in [0, n). It panics for n <= 0, matching math/rand.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic("proptest: Intn requires n > 0")
	}
	// Both operands are int64 and n is positive, so the remainder is in [0, n)
	// and therefore fits an int on every platform. No narrowing occurs.
	return int(r.Int63() % int64(n))
}

// Perm returns a random permutation of [0, n), like math/rand.Perm.
func (r *Rand) Perm(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	r.Shuffle(n, func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Shuffle permutes n elements using swap, like math/rand.Shuffle. It is a
// Fisher-Yates shuffle, so every permutation is reachable.
func (r *Rand) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.Intn(i+1))
	}
}

// Read fills p with bytes from the stream and always returns len(p), nil. The
// signature matches io.Reader so it drops into the same call sites; the error is
// always nil because there is nothing here that can fail.
func (r *Rand) Read(p []byte) (int, error) {
	for i := 0; i < len(p); {
		v := r.Uint64()
		for b := 0; b < 8 && i < len(p); b++ {
			p[i] = byte(v >> (8 * b) & 0xFF)
			i++
		}
	}
	return len(p), nil
}
