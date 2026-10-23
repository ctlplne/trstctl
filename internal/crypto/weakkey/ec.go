// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
)

// The EC check finds a public key Q = k·G whose private scalar k is small, or
// is n − k for a small k (the same x-coordinate, so the same weakness). The
// eMudhra intermediates of October 2026 were all of this kind, with k below
// 256. It covers every |k| ≤ ecSmallScalarBound with baby-step giant-step and
// never a linear scan: a table of the x-coordinates of 1·G … m·G, built once
// per curve, and 2·giantSteps point additions per key.
const (
	babySteps  = 1 << 16
	giantSteps = 1 << 8
)

// ecSmallScalarBound is the coverage of one search: k = j·m ± i for
// 0 ≤ j ≤ giantSteps and 0 ≤ i ≤ m.
const ecSmallScalarBound = giantSteps*babySteps + babySteps

// ecCurve holds one NIST curve (a = −3) and its baby-step table.
type ecCurve struct {
	name   string
	params *elliptic.CurveParams
	once   sync.Once
	baby   map[uint64]uint32 // low 64 bits of x(i·G) → i, for 1 ≤ i ≤ m
	mx, my *big.Int          // m·G, affine
}

var ecCurves = []*ecCurve{
	{name: "P-224", params: elliptic.P224().Params()},
	{name: "P-256", params: elliptic.P256().Params()},
	{name: "P-384", params: elliptic.P384().Params()},
	{name: "P-521", params: elliptic.P521().Params()},
}

func curveFor(params *elliptic.CurveParams) *ecCurve {
	for _, c := range ecCurves {
		if c.params.Name == params.Name {
			return c
		}
	}
	return nil
}

// jpoint is a point in Jacobian coordinates (X/Z², Y/Z³); Z = 0 is the point
// at infinity.
type jpoint struct{ x, y, z *big.Int }

type field struct{ p *big.Int }

func (f field) mod(a *big.Int) *big.Int            { return a.Mod(a, f.p) }
func (f field) mul(a, b *big.Int) *big.Int         { return f.mod(new(big.Int).Mul(a, b)) }
func (f field) sqr(a *big.Int) *big.Int            { return f.mod(new(big.Int).Mul(a, a)) }
func (f field) add(a, b *big.Int) *big.Int         { return f.mod(new(big.Int).Add(a, b)) }
func (f field) sub(a, b *big.Int) *big.Int         { return f.mod(new(big.Int).Sub(a, b)) }
func (f field) small(a *big.Int, k int64) *big.Int { return f.mod(new(big.Int).Mul(a, big.NewInt(k))) }

func infinity() jpoint { return jpoint{x: big.NewInt(1), y: big.NewInt(1), z: new(big.Int)} }

func affinePoint(x, y *big.Int) jpoint {
	return jpoint{x: new(big.Int).Set(x), y: new(big.Int).Set(y), z: big.NewInt(1)}
}

// double is dbl-2001-b for a = −3.
func (f field) double(p jpoint) jpoint {
	if p.z.Sign() == 0 || p.y.Sign() == 0 {
		return infinity()
	}
	delta := f.sqr(p.z)
	gamma := f.sqr(p.y)
	beta := f.mul(p.x, gamma)
	alpha := f.small(f.mul(f.sub(p.x, delta), f.add(p.x, delta)), 3)
	x3 := f.sub(f.sqr(alpha), f.small(beta, 8))
	z3 := f.sub(f.sub(f.sqr(f.add(p.y, p.z)), gamma), delta)
	y3 := f.sub(f.mul(alpha, f.sub(f.small(beta, 4), x3)), f.small(f.sqr(gamma), 8))
	return jpoint{x: x3, y: y3, z: z3}
}

// addAffine adds the affine point (qx, qy) to p (mixed Jacobian addition),
// including the doubling and inverse cases.
func (f field) addAffine(p jpoint, qx, qy *big.Int) jpoint {
	if p.z.Sign() == 0 {
		return affinePoint(qx, qy)
	}
	z1z1 := f.sqr(p.z)
	u2 := f.mul(qx, z1z1)
	s2 := f.mul(qy, f.mul(p.z, z1z1))
	h := f.sub(u2, p.x)
	r := f.sub(s2, p.y)
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return f.double(p)
		}
		return infinity()
	}
	hh := f.sqr(h)
	hhh := f.mul(h, hh)
	v := f.mul(p.x, hh)
	x3 := f.sub(f.sub(f.sqr(r), hhh), f.add(v, v))
	y3 := f.sub(f.mul(r, f.sub(v, x3)), f.mul(p.y, hhh))
	z3 := f.mul(p.z, h)
	return jpoint{x: x3, y: y3, z: z3}
}

// inverses returns 1/z for every z (all non-zero) with one modular inversion
// (Montgomery's trick).
func (f field) inverses(zs []*big.Int) []*big.Int {
	out := make([]*big.Int, len(zs))
	if len(zs) == 0 {
		return out
	}
	prefix := make([]*big.Int, len(zs))
	prefix[0] = new(big.Int).Set(zs[0])
	for i := 1; i < len(zs); i++ {
		prefix[i] = f.mul(prefix[i-1], zs[i])
	}
	inv := new(big.Int).ModInverse(prefix[len(zs)-1], f.p)
	for i := len(zs) - 1; i > 0; i-- {
		out[i] = f.mul(inv, prefix[i-1])
		inv = f.mul(inv, zs[i])
	}
	out[0] = inv
	return out
}

// affine converts p (z ≠ 0) with a precomputed 1/z.
func (f field) affine(p jpoint, zinv *big.Int) (x, y *big.Int) {
	zinv2 := f.sqr(zinv)
	return f.mul(p.x, zinv2), f.mul(p.y, f.mul(zinv2, zinv))
}

// scalarBaseMult computes k·G for k ≥ 1 by double-and-add. It is used for the
// table's giant step and to confirm a candidate scalar exactly; both scalars
// are small, so this is not a general-purpose (or constant-time) routine.
func (c *ecCurve) scalarBaseMult(k *big.Int) (x, y *big.Int, ok bool) {
	f := field{p: c.params.P}
	acc := infinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = f.double(acc)
		if k.Bit(i) == 1 {
			acc = f.addAffine(acc, c.params.Gx, c.params.Gy)
		}
	}
	if acc.z.Sign() == 0 {
		return nil, nil, false
	}
	x, y = f.affine(acc, new(big.Int).ModInverse(acc.z, c.params.P))
	return x, y, true
}

func low64(x *big.Int) uint64 {
	var buf [8]byte
	b := x.Bytes()
	if len(b) >= 8 {
		copy(buf[:], b[len(b)-8:])
	} else {
		copy(buf[8-len(b):], b)
	}
	return binary.BigEndian.Uint64(buf[:])
}

func (c *ecCurve) table() {
	c.once.Do(func() {
		f := field{p: c.params.P}
		points := make([]jpoint, babySteps)
		zs := make([]*big.Int, babySteps)
		p := affinePoint(c.params.Gx, c.params.Gy)
		for i := 0; i < babySteps; i++ {
			points[i] = p
			zs[i] = p.z
			p = f.addAffine(p, c.params.Gx, c.params.Gy)
		}
		invs := f.inverses(zs)
		c.baby = make(map[uint64]uint32, babySteps)
		for i := range points {
			x, y := f.affine(points[i], invs[i])
			key := low64(x)
			if _, taken := c.baby[key]; !taken {
				c.baby[key] = uint32(i + 1) // #nosec G115 -- the baby-step index is below 2^16, so it fits a uint32 (CWE-190)
			}
			if i == babySteps-1 {
				c.mx, c.my = x, y
			}
		}
	})
}

// smallScalar returns s with Q = s·G and 0 < |s| ≤ ecSmallScalarBound, or 0
// when the key is not of that form. A negative s means the private key is
// n − |s|.
func (c *ecCurve) smallScalar(qx, qy *big.Int) int64 {
	c.table()
	f := field{p: c.params.P}
	negMy := new(big.Int).Sub(c.params.P, c.my)
	type step struct {
		pt   jpoint
		j    int64
		down bool // Q − j·M (true) or Q + j·M (false)
	}
	steps := make([]step, 0, 2*giantSteps+1)
	down := affinePoint(qx, qy)
	up := affinePoint(qx, qy)
	steps = append(steps, step{pt: down, j: 0, down: true})
	for j := int64(1); j <= giantSteps; j++ {
		down = f.addAffine(down, c.mx, negMy)
		up = f.addAffine(up, c.mx, c.my)
		steps = append(steps, step{pt: down, j: j, down: true}, step{pt: up, j: j, down: false})
	}
	m := int64(babySteps)
	var candidates []int64
	var zs []*big.Int
	var finite []step
	for _, s := range steps {
		if s.pt.z.Sign() == 0 {
			// Q − j·M = O → Q = j·m·G; Q + j·M = O → Q = −j·m·G.
			if s.down {
				candidates = append(candidates, s.j*m)
			} else {
				candidates = append(candidates, -s.j*m)
			}
			continue
		}
		finite = append(finite, s)
		zs = append(zs, s.pt.z)
	}
	invs := f.inverses(zs)
	for i, s := range finite {
		x, _ := f.affine(s.pt, invs[i])
		baby, ok := c.baby[low64(x)]
		if !ok {
			continue
		}
		b := int64(baby)
		if s.down { // Q − j·M = ±i·G
			candidates = append(candidates, s.j*m+b, s.j*m-b)
		} else { // Q + j·M = ±i·G
			candidates = append(candidates, b-s.j*m, -b-s.j*m)
		}
	}
	for _, s := range candidates {
		if s == 0 {
			continue
		}
		abs := s
		if abs < 0 {
			abs = -abs
		}
		x, y, ok := c.scalarBaseMult(big.NewInt(abs))
		if !ok || x.Cmp(qx) != 0 {
			continue
		}
		if s > 0 && y.Cmp(qy) == 0 {
			return s
		}
		if s < 0 && new(big.Int).Sub(c.params.P, y).Cmp(qy) == 0 {
			return s
		}
	}
	return 0
}

// checkEC reports a small private scalar.
func checkEC(params *elliptic.CurveParams, qx, qy *big.Int) []Finding {
	c := curveFor(params)
	if c == nil {
		return nil
	}
	s := c.smallScalar(qx, qy)
	if s == 0 {
		return nil
	}
	if s > 0 {
		return []Finding{{Check: CheckECSmallScalar, Reason: fmt.Sprintf("the %s public key is %d·G: its private key is %d, which anyone can recover", c.name, s, s)}}
	}
	return []Finding{{Check: CheckECSmallScalar, Reason: fmt.Sprintf("the %s public key is −%d·G: its private key is n − %d, which anyone can recover", c.name, -s, -s)}}
}
