// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAWSPolicyFixtureMatrixA264(t *testing.T) {
	raw, err := os.ReadFile("testdata/evaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policies map[string]json.RawMessage `json:"policies"`
		Cases    []struct {
			Name                                  string   `json:"name"`
			Expected                              Decision `json:"expected"`
			Identity, Boundary, Resource, Session []string
			SCP, RCP                              [][]string
			Unknown                               []string
			Principal                             string
			Context                               map[string][]string
			PartialContext                        bool   `json:"partial_context"`
			ResourceAccount                       string `json:"resource_account"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	documents := map[string]Document{}
	for id, body := range fixture.Policies {
		doc, e := Parse(id, body)
		if e != nil {
			t.Fatalf("fixture document %s: %v", id, e)
		}
		documents[id] = doc
	}
	set := func(ids []string, state Coverage) PolicySet {
		t.Helper()
		s := PolicySet{Coverage: state}
		for _, id := range ids {
			d, ok := documents[id]
			if !ok {
				t.Fatalf("unknown fixture document %s", id)
			}
			s.Documents = append(s.Documents, d)
		}
		return s
	}
	optional := func(ids []string) PolicySet {
		if ids == nil {
			return set(nil, Absent)
		}
		return set(ids, Complete)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			request := Request{Principal: Principal{Kind: IAMUser, ARN: "arn:aws:iam::111122223333:user/workload", AccountID: "111122223333"}, Action: "s3:GetObject", Resource: "arn:aws:s3:::owned/report", ResourceAccountID: "111122223333", Context: Context{Values: test.Context, Complete: !test.PartialContext}}
			if test.ResourceAccount != "" {
				request.ResourceAccountID = test.ResourceAccount
			}
			if test.Principal == "role_session" {
				request.Principal.Kind = RoleSession
				request.Principal.ARN = "arn:aws:sts::111122223333:assumed-role/workload/run"
				request.Principal.RoleARN = "arn:aws:iam::111122223333:role/workload"
			}
			evidence := Evidence{Identity: set(test.Identity, Complete), Resource: set(test.Resource, Complete), Boundary: optional(test.Boundary), Session: optional(test.Session), SCPCoverage: Absent, RCPCoverage: Absent}
			if test.SCP != nil {
				evidence.SCPCoverage = Complete
				for _, ids := range test.SCP {
					evidence.SCP = append(evidence.SCP, set(ids, Complete))
				}
			}
			if test.RCP != nil {
				evidence.RCPCoverage = Complete
				for _, ids := range test.RCP {
					evidence.RCP = append(evidence.RCP, set(ids, Complete))
				}
			}
			for _, unknown := range test.Unknown {
				switch unknown {
				case "boundary":
					evidence.Boundary = PolicySet{Coverage: Unavailable}
				case "scp":
					evidence.SCPCoverage = Unavailable
				default:
					t.Fatal("unknown fixture evidence state")
				}
			}
			result := Evaluate(request, evidence)
			if result.Decision != test.Expected {
				t.Fatalf("want %s, have %s; reasons=%+v", test.Expected, result.Decision, result.Reasons)
			}
		})
	}
}
