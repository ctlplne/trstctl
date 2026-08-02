// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation_test

import (
	"bytes"
	"math/rand"
	"testing"

	"trstctl.com/trstctl/ee/agentid/delegation"
)

// reg is a small tool registry that resolves aliases to canonical tool ids so the
// comparator compares tools by resolved identity, not raw spelling (card §3.3).
var reg = delegation.NewToolRegistry(map[string]string{
	"fs.read":         "tool:fs.read",
	"filesystem.read": "tool:fs.read", // alias resolves to the same canonical id
	"fs.write":        "tool:fs.write",
	"net.http":        "tool:net.http",
	"db.query":        "tool:db.query",
})

// TestAuthority_PartialOrderSubsetAndNumeric exercises the comparator across every
// dimension: subset on scope/tool/resource/class sets after canonical normalization,
// <= on spend/rate/depth, and nested validity ceilings (AGID-claim-3 / INV-A2).
func TestAuthority_PartialOrderSubsetAndNumeric(t *testing.T) {
	parent := delegation.Authority{
		Scopes:    []string{"read", "write", "admin"},
		Tools:     []string{"fs.read", "fs.write", "net.http"},
		Resources: []delegation.ResourceSelector{{Kind: "path", Value: "/data"}},
		Classes:   []string{"pii", "internal"},
		Spend:     delegation.Budget{Amount: 1000, Currency: "USD"},
		Rate:      delegation.Rate{Limit: 100, Per: "minute"},
		Depth:     5,
		Validity:  delegation.Window{NotBefore: 100, NotAfter: 900},
	}

	cases := []struct {
		name  string
		child delegation.Authority
		leq   bool // want child within parent
	}{
		{
			name: "narrower on every dimension is within",
			child: delegation.Authority{
				Scopes:    []string{"read"},
				Tools:     []string{"fs.read"},
				Resources: []delegation.ResourceSelector{{Kind: "path", Value: "/data/reports"}},
				Classes:   []string{"internal"},
				Spend:     delegation.Budget{Amount: 500, Currency: "USD"},
				Rate:      delegation.Rate{Limit: 50, Per: "minute"},
				Depth:     3,
				Validity:  delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: true,
		},
		{
			name:  "identical is within (reflexive)",
			child: parent,
			leq:   true,
		},
		{
			name: "scope not in parent widens",
			child: delegation.Authority{
				Scopes:   []string{"root"}, // not a subset
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "tool not in parent widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"db.query"}, // not in parent
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "data class not in parent widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Classes:  []string{"secret"}, // not in parent
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "resource outside parent containment widens",
			child: delegation.Authority{
				Scopes:    []string{"read"},
				Tools:     []string{"fs.read"},
				Resources: []delegation.ResourceSelector{{Kind: "path", Value: "/etc"}}, // not under /data
				Spend:     delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:      delegation.Rate{Limit: 1, Per: "minute"},
				Depth:     1,
				Validity:  delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "higher spend widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 2000, Currency: "USD"}, // > parent
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "higher rate widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 500, Per: "minute"}, // > parent
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "greater depth widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    9, // > parent depth 5
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
		{
			name: "validity window escaping the ceiling widens",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 1, Currency: "USD"},
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 50, NotAfter: 800}, // starts before parent
			},
			leq: false,
		},
		{
			name: "spend currency mismatch is incomparable and treated as widening",
			child: delegation.Authority{
				Scopes:   []string{"read"},
				Tools:    []string{"fs.read"},
				Spend:    delegation.Budget{Amount: 1, Currency: "EUR"}, // different currency
				Rate:     delegation.Rate{Limit: 1, Per: "minute"},
				Depth:    1,
				Validity: delegation.Window{NotBefore: 200, NotAfter: 800},
			},
			leq: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := delegation.WithinParent(tc.child, parent, reg)
			if got != tc.leq {
				t.Fatalf("WithinParent = %v, want %v", got, tc.leq)
			}
		})
	}
}

// TestAuthority_CanonicalNormalizationStable asserts that normalization is stable
// (same input -> identical bytes), idempotent (normalize of normalize == normalize),
// and that comparator verdicts are invariant under semantically-equal spellings
// (AGID-claim-3 / INV-A2).
func TestAuthority_CanonicalNormalizationStable(t *testing.T) {
	// Two spellings of the same authority: different order, duplicates, mixed case
	// and whitespace on scope strings, and a tool alias that resolves to the same id.
	a := delegation.Authority{
		Scopes:    []string{"Write", " read ", "read", "ADMIN"},
		Tools:     []string{"filesystem.read", "fs.write", "fs.read"},
		Resources: []delegation.ResourceSelector{{Kind: "path", Value: "/data"}, {Kind: "path", Value: "/data"}},
		Classes:   []string{"internal", "pii", "internal"},
		Spend:     delegation.Budget{Amount: 1000, Currency: "usd"},
		Rate:      delegation.Rate{Limit: 100, Per: "Minute"},
		Depth:     5,
		Validity:  delegation.Window{NotBefore: 100, NotAfter: 900},
	}
	b := delegation.Authority{
		Scopes:    []string{"read", "write", "admin"},
		Tools:     []string{"fs.read", "fs.write"},
		Resources: []delegation.ResourceSelector{{Kind: "path", Value: "/data"}},
		Classes:   []string{"pii", "internal"},
		Spend:     delegation.Budget{Amount: 1000, Currency: "USD"},
		Rate:      delegation.Rate{Limit: 100, Per: "minute"},
		Depth:     5,
		Validity:  delegation.Window{NotBefore: 100, NotAfter: 900},
	}

	ca, err := delegation.CanonicalBytes(a, reg)
	if err != nil {
		t.Fatalf("CanonicalBytes(a): %v", err)
	}
	cb, err := delegation.CanonicalBytes(b, reg)
	if err != nil {
		t.Fatalf("CanonicalBytes(b): %v", err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("semantically-equal authorities produced different canonical bytes:\n a=%s\n b=%s", ca, cb)
	}

	// Stable across repeated calls.
	ca2, _ := delegation.CanonicalBytes(a, reg)
	if !bytes.Equal(ca, ca2) {
		t.Fatalf("CanonicalBytes not stable across runs")
	}

	// Idempotent: normalize(normalize(x)) == normalize(x).
	na := delegation.Normalize(a, reg)
	nna := delegation.Normalize(na, reg)
	nab, _ := delegation.CanonicalBytes(na, reg)
	nnab, _ := delegation.CanonicalBytes(nna, reg)
	if !bytes.Equal(nab, nnab) {
		t.Fatalf("normalize is not idempotent")
	}

	// Comparator verdict invariant under spelling: a within b and b within a (equal).
	if !delegation.WithinParent(a, b, reg) || !delegation.WithinParent(b, a, reg) {
		t.Fatalf("comparator verdict not invariant under semantically-equal spellings")
	}
}

// TestAuthority_EffectiveBudgetIsMinAlongChain asserts the derived effective spend
// and rate budgets equal the minimum of the respective budgets along a multi-hop
// chain (AGID-claim-4).
func TestAuthority_EffectiveBudgetIsMinAlongChain(t *testing.T) {
	chain := []delegation.Authority{
		{Spend: delegation.Budget{Amount: 1000, Currency: "USD"}, Rate: delegation.Rate{Limit: 100, Per: "minute"}},
		{Spend: delegation.Budget{Amount: 300, Currency: "USD"}, Rate: delegation.Rate{Limit: 250, Per: "minute"}},
		{Spend: delegation.Budget{Amount: 700, Currency: "USD"}, Rate: delegation.Rate{Limit: 40, Per: "minute"}},
		{Spend: delegation.Budget{Amount: 500, Currency: "USD"}, Rate: delegation.Rate{Limit: 90, Per: "minute"}},
	}
	spend, rate, err := delegation.EffectiveBudgets(chain)
	if err != nil {
		t.Fatalf("EffectiveBudgets: %v", err)
	}
	if spend.Amount != 300 {
		t.Fatalf("effective spend = %d, want min 300", spend.Amount)
	}
	if rate.Limit != 40 {
		t.Fatalf("effective rate = %d, want min 40", rate.Limit)
	}

	// A currency mismatch anywhere in the chain makes the spend budget incomparable
	// and must be reported, not silently folded.
	bad := append([]delegation.Authority(nil), chain...)
	bad = append(bad, delegation.Authority{Spend: delegation.Budget{Amount: 10, Currency: "EUR"}, Rate: delegation.Rate{Limit: 10, Per: "minute"}})
	if _, _, err := delegation.EffectiveBudgets(bad); err == nil {
		t.Fatalf("EffectiveBudgets accepted a mixed-currency chain; want error")
	}

	// Empty chain is an error (no budget to derive).
	if _, _, err := delegation.EffectiveBudgets(nil); err == nil {
		t.Fatalf("EffectiveBudgets(nil) = nil error; want error")
	}
}

// --- property tests -------------------------------------------------------------

// randAuthority builds a random authority set drawn from a small fixed universe so
// that subset relationships actually occur with useful frequency.
func randAuthority(r *rand.Rand) delegation.Authority {
	scopeU := []string{"read", "write", "admin", "root"}
	toolU := []string{"fs.read", "fs.write", "net.http", "db.query"}
	classU := []string{"pii", "internal", "secret"}
	pick := func(u []string) []string {
		var out []string
		for _, s := range u {
			if r.Intn(2) == 0 {
				out = append(out, s)
			}
		}
		return out
	}
	nb := int64(r.Intn(100))
	dur := int64(r.Intn(100) + 1)
	return delegation.Authority{
		Scopes:   pick(scopeU),
		Tools:    pick(toolU),
		Classes:  pick(classU),
		Spend:    delegation.Budget{Amount: uint64(r.Intn(1000)), Currency: "USD"},
		Rate:     delegation.Rate{Limit: uint64(r.Intn(1000)), Per: "minute"},
		Depth:    uint32(r.Intn(10)),
		Validity: delegation.Window{NotBefore: nb, NotAfter: nb + dur},
	}
}

// TestAuthority_PartialOrderProperties checks that the comparator is a partial order
// over random authority sets: reflexive, antisymmetric under canonical form, and
// transitive (AGID-claim-3 / INV-A2 — the comparator is a genuine partial order).
func TestAuthority_PartialOrderProperties(t *testing.T) {
	r := rand.New(rand.NewSource(0xA61D01))
	const iters = 4000
	for i := 0; i < iters; i++ {
		a := randAuthority(r)
		b := randAuthority(r)
		c := randAuthority(r)

		// Reflexive: a within a.
		if !delegation.WithinParent(a, a, reg) {
			t.Fatalf("reflexivity failed for %+v", a)
		}

		// Antisymmetric under canonical form.
		if delegation.WithinParent(a, b, reg) && delegation.WithinParent(b, a, reg) {
			ca, _ := delegation.CanonicalBytes(a, reg)
			cb, _ := delegation.CanonicalBytes(b, reg)
			if !bytes.Equal(ca, cb) {
				t.Fatalf("antisymmetry failed: a<=b and b<=a but canonical bytes differ\n a=%+v\n b=%+v", a, b)
			}
		}

		// Transitive: a within b and b within c => a within c.
		if delegation.WithinParent(a, b, reg) && delegation.WithinParent(b, c, reg) {
			if !delegation.WithinParent(a, c, reg) {
				t.Fatalf("transitivity failed\n a=%+v\n b=%+v\n c=%+v", a, b, c)
			}
		}
	}
}

// TestAuthority_MinBudgetFoldProperty checks that EffectiveBudgets returns the min
// spend and min rate over random chains (AGID-claim-4), cross-checked against a naive
// scan.
func TestAuthority_MinBudgetFoldProperty(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for i := 0; i < 2000; i++ {
		n := r.Intn(6) + 1
		chain := make([]delegation.Authority, n)
		wantSpend, wantRate := ^uint64(0), ^uint64(0)
		for j := 0; j < n; j++ {
			s := uint64(r.Intn(10000))
			rt := uint64(r.Intn(10000))
			chain[j] = delegation.Authority{Spend: delegation.Budget{Amount: s, Currency: "USD"}, Rate: delegation.Rate{Limit: rt, Per: "minute"}}
			if s < wantSpend {
				wantSpend = s
			}
			if rt < wantRate {
				wantRate = rt
			}
		}
		spend, rate, err := delegation.EffectiveBudgets(chain)
		if err != nil {
			t.Fatalf("EffectiveBudgets: %v", err)
		}
		if spend.Amount != wantSpend {
			t.Fatalf("spend fold = %d, want %d", spend.Amount, wantSpend)
		}
		if rate.Limit != wantRate {
			t.Fatalf("rate fold = %d, want %d", rate.Limit, wantRate)
		}
	}
}

// TestAuthority_ComparatorVersioned asserts the comparator records a version, so a
// later verifier can reproduce the exact verdict semantics (card §3.3: deterministic
// and versioned).
func TestAuthority_ComparatorVersioned(t *testing.T) {
	if delegation.ComparatorVersion == "" {
		t.Fatalf("ComparatorVersion is empty; the comparator must be versioned")
	}
}
