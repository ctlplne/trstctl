// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"hash/fnv"
	"math"
	"math/bits"
	"net/netip"
)

// clientSketchPrecision sets the client sketch's size: 2^10 one-byte
// registers (1 KiB per item), a standard error of about 1.04/sqrt(1024),
// 3.25% (X1-L7).
const clientSketchPrecision = 10

// clientSketch estimates how many distinct client addresses an item has seen
// once the exact set is full (HyperLogLog, Flajolet et al. 2007, with linear
// counting for small counts). Its memory is fixed, whatever the traffic.
type clientSketch struct {
	registers [1 << clientSketchPrecision]uint8
}

// add records one client address.
func (s *clientSketch) add(addr netip.Addr) {
	h := clientHash(addr)
	idx := h >> (64 - clientSketchPrecision)
	// The remaining bits, with a guard bit so the run is bounded.
	w := h<<clientSketchPrecision | 1<<(clientSketchPrecision-1)
	if rho := uint8(bits.LeadingZeros64(w) + 1); rho > s.registers[idx] { // #nosec G115 -- LeadingZeros64 is at most 64 (CWE-190)
		s.registers[idx] = rho
	}
}

// estimate is the sketch's count of distinct addresses.
func (s *clientSketch) estimate() int {
	m := float64(len(s.registers))
	sum, zeros := 0.0, 0
	for _, r := range s.registers {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	alpha := 0.7213 / (1 + 1.079/m)
	e := alpha * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return int(math.Round(e))
}

// clientHash is a deterministic 64-bit hash of an address: FNV-1a over its
// 16-byte form, then a mixing finalizer (splitmix64) so every bit depends on
// every input bit, which the sketch's register choice needs.
func clientHash(addr netip.Addr) uint64 {
	h := fnv.New64a()
	b := addr.As16()
	_, _ = h.Write(b[:])
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}
