package policy_test

import (
	"context"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"trstctl.com/trstctl/internal/policy"
)

// Property-based tests for the policy engine (TEST-003 / CLAUDE.md §6). The
// example/table-driven tests in policy_test.go pin specific decisions; these pin
// the *invariants* the base policy must hold over generated inputs — default-deny,
// the profile precondition's monotonicity, and the fail-closed contract — which a
// fixed example set cannot cover. They use the stdlib testing/quick generator
// (always available under -mod=readonly; no new dependency) and run under
// `make test` (race + coverage).

// genInput is the shared random-Input generator. testing/quick cannot synthesize
// the unexported-friendly mix we want (a bounded action set, an occasionally-empty
// profile), so we implement quick.Generator on a wrapper.
type genInput struct{ policy.Input }

// actions is the closed set the generator draws from: the three real lifecycle
// actions plus deliberately-unknown ones, so default-deny is exercised.
var actions = []policy.Action{
	policy.ActionIssue, policy.ActionDeploy, policy.ActionRevoke,
	"frobnicate", "", "ISSUE", "delete", "issue ", "rotate",
}

func (genInput) Generate(r *rand.Rand, _ int) reflect.Value {
	in := policy.Input{
		Action:   actions[r.Intn(len(actions))],
		TenantID: randToken(r),
		Subject:  randToken(r),
		Actor:    randToken(r),
	}
	// The profile is empty ~1/3 of the time so the profile precondition is hit on
	// both sides; otherwise a random token (only its emptiness matters to the base
	// policy, but a real value guards against accidental special-casing).
	if r.Intn(3) != 0 {
		in.Profile = randToken(r)
	}
	// Occasionally attach arbitrary attrs to confirm extra input never flips a deny
	// into an allow or panics the marshal path.
	if r.Intn(2) == 0 {
		in.Attrs = map[string]any{randToken(r): randToken(r), "n": r.Intn(1 << 20)}
	}
	return reflect.ValueOf(genInput{in})
}

// randToken returns a short, occasionally-empty, sometimes Rego-hostile string so
// the JSON→Rego input path is exercised with awkward keys/values.
func randToken(r *rand.Rand) string {
	n := r.Intn(8)
	const alphabet = "abc-_. 0\"{}\\\n"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

// TestPolicyInvariantsBaseModule asserts the base-policy invariants over generated
// inputs:
//
//   - default-deny: an action outside {issue, deploy, revoke} is ALWAYS denied,
//     whatever the other fields are (catches an accidental open default);
//   - profile precondition: issue/deploy are allowed iff a non-empty profile is
//     bound, and the deny reason names the profile (the S8.1 precondition);
//   - revoke is always allowed;
//   - fail-closed: a deny never carries Allow==true, an allow always carries
//     Allow==true, and Evaluate never returns an error for a well-formed Input
//     (the base policy compiles and evaluates).
func TestPolicyInvariantsBaseModule(t *testing.T) {
	e := newEngine(t, nil)
	ctx := context.Background()

	prop := func(g genInput) bool {
		in := g.Input
		d, err := e.Evaluate(ctx, in)
		if err != nil {
			t.Logf("unexpected eval error for %+v: %v", in, err)
			return false
		}
		hasProfile := in.Profile != ""
		var want bool
		switch in.Action {
		case policy.ActionRevoke:
			want = true
		case policy.ActionIssue, policy.ActionDeploy:
			want = hasProfile
		default:
			// Default-deny: anything not in the known set must be denied.
			want = false
		}
		if d.Allow != want {
			t.Logf("decision mismatch: action=%q profile=%q got Allow=%v want %v (reason=%q)",
				in.Action, in.Profile, d.Allow, want, d.Reason)
			return false
		}
		// Fail-closed reason contract: a denied issue/deploy missing a profile must
		// explain the profile requirement (so the caller can act, not guess).
		if !d.Allow && (in.Action == policy.ActionIssue || in.Action == policy.ActionDeploy) && !hasProfile {
			if !strings.Contains(d.Reason, "profile") {
				t.Logf("deny reason should mention the missing profile, got %q", d.Reason)
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("policy base-module invariant violated: %v", err)
	}
}

// TestPolicyNeverPanicsOnArbitraryInput is the fail-closed robustness property: no
// generated Input (including Rego-hostile profile/tenant strings and arbitrary
// attrs) may panic the engine, and a deny is never reported as an allow. A panic
// or an allow-with-error is a guard breach.
func TestPolicyNeverPanicsOnArbitraryInput(t *testing.T) {
	e := newEngine(t, nil)
	ctx := context.Background()

	prop := func(g genInput) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Evaluate panicked on %+v: %v", g.Input, r)
				ok = false
			}
		}()
		d, err := e.Evaluate(ctx, g.Input)
		// The fail-closed contract: any error must come with a deny.
		if err != nil && d.Allow {
			t.Logf("fail-closed breach: Allow==true alongside error %v for %+v", err, g.Input)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("policy robustness property violated: %v", err)
	}
}

// TestPolicyProfileMonotonicity pins the precondition's monotonicity directly:
// for issue/deploy, binding a profile can only ever turn a deny into an allow,
// never the reverse — i.e. adding the required precondition never removes
// permission. Generated over random tenants/actors/attrs.
func TestPolicyProfileMonotonicity(t *testing.T) {
	e := newEngine(t, nil)
	ctx := context.Background()

	prop := func(g genInput) bool {
		for _, act := range []policy.Action{policy.ActionIssue, policy.ActionDeploy} {
			base := g.Input
			base.Action = act
			base.Profile = ""
			withProfile := base
			withProfile.Profile = "tls-server"

			dNo, err1 := e.Evaluate(ctx, base)
			dYes, err2 := e.Evaluate(ctx, withProfile)
			if err1 != nil || err2 != nil {
				t.Logf("unexpected eval error: %v / %v", err1, err2)
				return false
			}
			// No profile must deny; a bound profile must allow.
			if dNo.Allow {
				t.Logf("%s without a profile must be denied", act)
				return false
			}
			if !dYes.Allow {
				t.Logf("%s with a bound profile must be allowed (got deny: %q)", act, dYes.Reason)
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("policy profile-monotonicity property violated: %v", err)
	}
}
