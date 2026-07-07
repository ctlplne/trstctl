// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"errors"
	"fmt"
)

// vectors.go is the CONFORMANCE-VECTOR runner. AGID-12 publishes canonical
// cross-implementation vectors (the release gate); this runner defines the vector
// SHAPE and a RunVectors entrypoint so those published vectors drop in unchanged,
// and it ships a small SELF-GENERATED vector set (built in the tests via
// BuildSelfVectors) the runner consumes today. A vector is a fully-materialized,
// OFFLINE case: a presented credential + trust root + local policy + requested
// action + evaluation instant, and the EXPECTED outcome (accept, or a named
// fail-closed refusal). The runner drives Verify and asserts the outcome matches,
// so a future implementation (or the WASM build) is conformant iff it produces the
// same accept/refuse decision for every vector.

// Outcome is a vector's expected decision.
type Outcome int

const (
	// Accept means Verify must return a nil error.
	Accept Outcome = iota
	// Refuse means Verify must return a non-nil error; when a vector sets
	// ExpectErr, the returned error must also errors.Is-match it.
	Refuse
)

func (o Outcome) String() string {
	if o == Accept {
		return "accept"
	}
	return "refuse"
}

// Vector is one offline conformance case. Every field is caller-materialized
// (nothing is fetched); UnixNow fixes the evaluation instant so validity is
// deterministic across implementations.
type Vector struct {
	Name       string
	Credential Credential
	TrustRoot  TrustRoot
	Policy     LocalPolicy
	Action     Action
	UnixNow    int64
	Expect     Outcome
	// ExpectErr, when non-nil and Expect is Refuse, is the sentinel the refusal must
	// match with errors.Is. It lets a vector pin WHICH fail-closed reason applies
	// (e.g. ErrToolAbsentFromManifest), not merely that some refusal occurred.
	ExpectErr error
}

// VectorResult reports one vector's outcome under Verify.
type VectorResult struct {
	Name   string
	Passed bool
	// Detail explains a failure (expected vs. got), empty when Passed.
	Detail string
	// Err is the error Verify returned (nil on accept).
	Err error
}

// RunVector evaluates a single vector with Verify at its fixed instant and reports
// whether the observed decision matches the expectation. It constructs no network
// client (Verify does not) and performs no I/O.
func RunVector(v Vector) VectorResult {
	_, err := Verify(v.Credential, v.TrustRoot, v.Policy, v.Action, FixedClock(unixToTime(v.UnixNow)))
	switch v.Expect {
	case Accept:
		if err != nil {
			return VectorResult{Name: v.Name, Passed: false, Err: err,
				Detail: fmt.Sprintf("expected accept, got refuse: %v", err)}
		}
		return VectorResult{Name: v.Name, Passed: true}
	case Refuse:
		if err == nil {
			return VectorResult{Name: v.Name, Passed: false,
				Detail: "expected refuse, got accept"}
		}
		if v.ExpectErr != nil && !errors.Is(err, v.ExpectErr) {
			return VectorResult{Name: v.Name, Passed: false, Err: err,
				Detail: fmt.Sprintf("expected refuse %v, got %v", v.ExpectErr, err)}
		}
		return VectorResult{Name: v.Name, Passed: true, Err: err}
	default:
		return VectorResult{Name: v.Name, Passed: false, Detail: "unknown expected outcome"}
	}
}

// RunVectors runs every vector and returns the per-vector results plus whether ALL
// passed. AGID-12's published vector set is consumed the same way. It performs no
// I/O and constructs no network client.
func RunVectors(vs []Vector) (results []VectorResult, allPassed bool) {
	allPassed = true
	results = make([]VectorResult, 0, len(vs))
	for _, v := range vs {
		r := RunVector(v)
		if !r.Passed {
			allPassed = false
		}
		results = append(results, r)
	}
	return results, allPassed
}
