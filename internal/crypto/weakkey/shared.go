// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
)

// MaxSharedFactorModuli bounds one batch-GCD run. The product tree of n
// 2048-bit moduli holds about n·256 bytes per level; 20,000 distinct moduli
// stay under about 80 MB. A caller with more runs the most recent first and
// records what it left out.
const MaxSharedFactorModuli = 20000

// SharedFactor names one key (by its index in the caller's slice) whose
// modulus shares a prime with at least one other distinct modulus in the set,
// so both can be factored by anyone holding the two public keys.
type SharedFactor struct {
	Index    int   `json:"index"`
	Partners []int `json:"partners"`
}

// SharedFactorReport is what one run did.
type SharedFactorReport struct {
	Keys     int            `json:"keys"`     // keys given
	RSA      int            `json:"rsa"`      // RSA keys among them
	Distinct int            `json:"distinct"` // distinct moduli checked (a reused key counts once)
	Skipped  int            `json:"skipped"`  // keys that did not parse
	Shared   []SharedFactor `json:"shared,omitempty"`
}

// SharedFactorFinding is the finding recorded for a key in Shared.
func SharedFactorFinding(partners int) Finding {
	return Finding{Check: CheckRSASharedFactor, Reason: fmt.Sprintf("the RSA modulus shares a prime with %d other key(s) in this inventory, so each of them can be factored", partners)}
}

// SharedFactors runs Bernstein's batch GCD over the RSA keys among keys (DER
// SubjectPublicKeyInfo or DER certificates; anything else is skipped). The
// same key used by several certificates is one modulus, not a shared factor.
// It is a background-job routine: never call it in a request path.
func SharedFactors(ctx context.Context, keys [][]byte) (SharedFactorReport, error) {
	rep := SharedFactorReport{Keys: len(keys)}
	byModulus := map[string][]int{}
	var moduli []*big.Int
	for i, der := range keys {
		n, ok := rsaModulus(der)
		if !ok {
			rep.Skipped++
			continue
		}
		rep.RSA++
		k := string(n.Bytes())
		if _, seen := byModulus[k]; !seen {
			moduli = append(moduli, n)
		}
		byModulus[k] = append(byModulus[k], i)
	}
	rep.Distinct = len(moduli)
	if len(moduli) > MaxSharedFactorModuli {
		return rep, fmt.Errorf("weakkey: %d distinct moduli exceed the bound of %d for one run", len(moduli), MaxSharedFactorModuli)
	}
	if len(moduli) < 2 {
		return rep, nil
	}
	flagged, err := batchGCD(ctx, moduli)
	if err != nil {
		return rep, err
	}
	if len(flagged) == 0 {
		return rep, nil
	}
	// Partners among the flagged moduli: pairwise GCD over the few that share.
	partners := map[int][]int{}
	g := new(big.Int)
	one := big.NewInt(1)
	for a := 0; a < len(flagged); a++ {
		for b := a + 1; b < len(flagged); b++ {
			if g.GCD(nil, nil, moduli[flagged[a]], moduli[flagged[b]]).Cmp(one) > 0 {
				partners[flagged[a]] = append(partners[flagged[a]], flagged[b])
				partners[flagged[b]] = append(partners[flagged[b]], flagged[a])
			}
		}
	}
	for _, m := range flagged {
		var others []int
		for _, p := range partners[m] {
			others = append(others, byModulus[string(moduli[p].Bytes())]...)
		}
		for _, idx := range byModulus[string(moduli[m].Bytes())] {
			rep.Shared = append(rep.Shared, SharedFactor{Index: idx, Partners: others})
		}
	}
	return rep, nil
}

func rsaModulus(der []byte) (*big.Int, bool) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if k, ok := pub.(*rsa.PublicKey); ok {
			return k.N, true
		}
		return nil, false
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return k.N, true
		}
	}
	return nil, false
}

// batchGCD returns the indexes of moduli that share a prime with another
// modulus in the set: z_i = (∏N mod N_i²) / N_i, flagged when gcd(z_i, N_i) > 1.
func batchGCD(ctx context.Context, moduli []*big.Int) ([]int, error) {
	levels := [][]*big.Int{moduli}
	for len(levels[len(levels)-1]) > 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		prev := levels[len(levels)-1]
		next := make([]*big.Int, (len(prev)+1)/2)
		for i := range next {
			if 2*i+1 < len(prev) {
				next[i] = new(big.Int).Mul(prev[2*i], prev[2*i+1])
			} else {
				next[i] = prev[2*i]
			}
		}
		levels = append(levels, next)
	}
	rems := levels[len(levels)-1]
	for l := len(levels) - 2; l >= 0; l-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cur := levels[l]
		next := make([]*big.Int, len(cur))
		for i, v := range cur {
			sq := new(big.Int).Mul(v, v)
			next[i] = new(big.Int).Mod(rems[i/2], sq)
		}
		rems = next
		levels[l+1] = nil // release the level above as the tree is walked down
	}
	var flagged []int
	one := big.NewInt(1)
	for i, n := range moduli {
		z := new(big.Int).Quo(rems[i], n)
		if new(big.Int).GCD(nil, nil, z, n).Cmp(one) > 0 {
			flagged = append(flagged, i)
		}
	}
	return flagged, nil
}
