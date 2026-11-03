// SPDX-License-Identifier: BUSL-1.1

package rehearsal

import (
	"errors"
	"strings"
	"testing"
)

func TestEveryKindHasStepsTheMockReproduces(t *testing.T) {
	for _, kind := range Kinds() {
		steps, ok := Template(kind)
		if !ok || len(steps) == 0 {
			t.Fatalf("%s has no template", kind)
		}
		if verdict, detail := Compare(ModeMockedRehearsal, steps, Mock(steps)); verdict != VerdictMatched {
			t.Errorf("%s: the mock does not reproduce its own template: %s", kind, detail)
		}
	}
}

// A mocked success is never labeled live, and a live label needs every
// observation to be a live receipt.
func TestAMockSuccessIsNeverLabeledLive(t *testing.T) {
	steps, _ := Template(KindRetry)
	mocked := Mock(steps)
	verdict, _ := Compare(ModeMockedRehearsal, steps, mocked)
	if got := Label(ModeMockedRehearsal, verdict, mocked); got != "mocked: matched" {
		t.Fatalf("a mocked success is labeled %q", got)
	}
	// Mock observations presented as a live observation are not live.
	if verdict, _ := Compare(ModeLiveObservation, steps, mocked); verdict != VerdictDiverged {
		t.Fatalf("mock observations passed as live: %s", verdict)
	}
	if got := Label(ModeLiveObservation, VerdictMatched, mocked); strings.HasPrefix(got, "live") {
		t.Fatalf("mock observations are labeled %q", got)
	}
	live := []Observation{{Step: 1, Effect: "one_effect", Source: SourceLiveReceipt, Receipt: "idempotency:abc"}}
	if got := Label(ModeLiveObservation, VerdictMatched, live); got != "live: matched" {
		t.Fatalf("live receipts are labeled %q", got)
	}
}

// By default a sandbox replay cannot reach production or read stored
// secrets; environments come from the product's records, not the scenario.
func TestASandboxReplayCannotReachProductionOrReuseSecrets(t *testing.T) {
	recorded := map[string]string{"target-staging": "staging", "target-prod": "production", "target-unclassified": "", "id-qa": "qa", "id-prod": "prod"}
	env := Environments{
		Target:   func(id string) (string, error) { return recorded[id], nil },
		Identity: func(id string) (string, error) { return recorded[id], nil },
	}
	step := func(target string) []Step {
		return []Step{{Action: "deliver_to_unreachable_target", Target: target, Expect: "retried_with_backoff"}}
	}
	if err := Guard(ModeSandboxExecution, step("target-staging"), DataSet{Kind: "identities", IdentityIDs: []string{"id-qa"}}, env); err != nil {
		t.Fatalf("a staging target and a qa identity: %v", err)
	}
	for name, c := range map[string]struct {
		steps []Step
		data  DataSet
	}{
		"a production target":    {step("target-prod"), DataSet{Kind: "identities"}},
		"an unclassified target": {step("target-unclassified"), DataSet{Kind: "identities"}},
		"a production identity":  {step("target-staging"), DataSet{Kind: "identities", IdentityIDs: []string{"id-prod"}}},
		"a stored secret":        {step("target-staging"), DataSet{Kind: "scrubbed_failure", SecretRefs: []string{"payments/db-password"}}},
	} {
		if err := Guard(ModeSandboxExecution, c.steps, c.data, env); !errors.Is(err, ErrUnsafeReplay) {
			t.Errorf("%s: %v; want a refusal", name, err)
		}
	}
	// Nothing real runs in the other modes.
	for _, mode := range []Mode{ModeStaticPreview, ModeMockedRehearsal, ModeLiveObservation} {
		if err := Guard(mode, step("target-prod"), DataSet{}, env); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
	}
}

func TestAWrongExpectationDiverges(t *testing.T) {
	steps := []Step{{Action: "repeat_request_with_same_key", Expect: "two_effects"}, {Action: "invented_action", Expect: "x"}}
	verdict, detail := Compare(ModeMockedRehearsal, steps, Mock(steps))
	if verdict != VerdictDiverged || !strings.Contains(detail, "expected two_effects, observed one_effect") || !strings.Contains(detail, "step 2 (invented_action) was not observed") {
		t.Fatalf("verdict %s: %s", verdict, detail)
	}
}

func TestTheDataSetDigestIgnoresOrder(t *testing.T) {
	a, err := DataSetDigest(DataSet{Kind: "identities", IdentityIDs: []string{"b", "a"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DataSetDigest(DataSet{Kind: "identities", IdentityIDs: []string{"a", "b"}})
	c, _ := DataSetDigest(DataSet{Kind: "identities", IdentityIDs: []string{"a", "c"}})
	if a != b || a == c || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("digests %s %s %s", a, b, c)
	}
}

// A static preview observes documented effects only where the configuration
// resolves the step's references.
func TestAStaticPreviewObservesWhatTheConfigurationResolves(t *testing.T) {
	steps := []Step{{Action: "deliver_to_unreachable_target", Target: "t-1", Expect: "retried_with_backoff"},
		{Action: "exhaust_retries", Target: "t-gone", Expect: "dead_lettered_and_alerted"}}
	observed := Preview(steps, func(s Step) error {
		if s.Target == "t-gone" {
			return errors.New("target t-gone does not exist")
		}
		return nil
	})
	verdict, detail := Compare(ModeStaticPreview, steps, observed)
	if verdict != VerdictDiverged || !strings.Contains(detail, "observed unresolved: target t-gone does not exist") {
		t.Fatalf("verdict %s: %s", verdict, detail)
	}
	if got := Label(ModeStaticPreview, verdict, observed); got != "preview: diverged" {
		t.Fatalf("label %q", got)
	}
}
