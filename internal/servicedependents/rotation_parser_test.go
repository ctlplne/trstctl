// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestDependentStepAuthorityMutationPropertyA267(t *testing.T) {
	intent, inputs := workflowFixture(t)
	steps, err := intent.Steps(inputs, Forward)
	if err != nil {
		t.Fatal(err)
	}
	base := steps[0]
	property := func(input [16]byte) bool {
		changed := crypto.SHA256Hex(input[:])
		cases := []RotationStep{base, base, base, base, base, base}
		cases[0].RotationID = "99999999-9999-4999-8999-999999999999"
		cases[1].PlanDigest = changed
		if cases[1].PlanDigest == base.PlanDigest {
			cases[1].PlanDigest = strings.Repeat("0", 64)
		}
		cases[2].Ref.AgentID = "99999999-9999-4999-8999-999999999999"
		cases[3].Direction = Inverse
		cases[4].Action = Update
		cases[5].Ref.Name = "substituted-" + changed[:16]
		service := *base.Service
		service.Name = cases[5].Ref.Name
		cases[5].Service = &service
		for _, v := range cases {
			if v.Validate() == nil {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

// Automatically discovered by .clusterfuzzlite/build.sh for OSS-Fuzz-family
// continuous execution. Accepted inputs still cannot acquire an unknown field,
// duplicate interpretation or a changed authority under the retained step ID.
func FuzzDependentRotationWireA267(f *testing.F) {
	intent, inputs := workflowFixture(f)
	steps, err := intent.Steps(inputs, Forward)
	if err != nil {
		f.Fatal(err)
	}
	step := steps[0]
	step.Challenge = "88888888-8888-4888-8888-888888888888"
	step.NotBefore = intent.Plan.CreatedAt
	step.Deadline = step.NotBefore.Add(time.Minute)
	seed, err := json.Marshal(step)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"status":"failed","status":"succeeded"}`))
	f.Add([]byte(`{"probe_id":"owned","challenge":"same","unknown":true}`))
	f.Add([]byte(strings.Repeat("[", 18) + strings.Repeat("]", 18)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		if parsed, err := DecodeRotationStep(raw); err == nil {
			parsed.Direction = map[string]string{Forward: Inverse, Inverse: Forward}[parsed.Direction]
			if parsed.Validate() == nil {
				t.Fatal("changed direction retained native authority")
			}
		}
		var proof FunctionalProof
		_ = DecodeFunctionalProof(raw, &proof)
		report, err := DecodeStepReport(raw)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		// Even a syntactically accepted report cannot smuggle in a second status
		// or an extension after the typed reader has interpreted its first value.
		for _, field := range []string{`,"status":"succeeded"}`, `,"unreviewed_authority":true}`} {
			altered := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(field)...)
			if _, err := DecodeStepReport(altered); err == nil {
				t.Fatal("ambiguous or unknown report field accepted")
			}
		}
	})
}
