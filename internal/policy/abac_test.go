// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/policy"
)

func TestABACDenyOverlayUsesResourceAndEnvironment(t *testing.T) {
	const module = `package trstctl.abac

default deny := false
default reason := ""

deny if {
	input.permission == "certs:issue"
	input.resource.env == "prod"
	input.env.change_window != "true"
}

reason := "prod issuance requires change window" if {
	input.permission == "certs:issue"
	input.resource.env == "prod"
	input.env.change_window != "true"
}
`
	e, err := policy.NewABAC(policy.ABACConfig{Module: module})
	if err != nil {
		t.Fatalf("compile ABAC module: %v", err)
	}
	d, err := e.EvaluateDeny(context.Background(), policy.ABACInput{
		Permission: "certs:issue",
		TenantID:   "tenant-a",
		Resource:   map[string]string{"env": "prod"},
		Env:        map[string]string{"change_window": "false"},
	})
	if err != nil {
		t.Fatalf("evaluate ABAC deny: %v", err)
	}
	if !d.Deny || !strings.Contains(d.Reason, "change window") {
		t.Fatalf("prod outside window decision = %+v, want deny with reason", d)
	}

	d, err = e.EvaluateDeny(context.Background(), policy.ABACInput{
		Permission: "certs:issue",
		TenantID:   "tenant-a",
		Resource:   map[string]string{"env": "staging"},
		Env:        map[string]string{"change_window": "false"},
	})
	if err != nil {
		t.Fatalf("evaluate ABAC allow: %v", err)
	}
	if d.Deny {
		t.Fatalf("staging decision = %+v, want silent allow", d)
	}
}

func TestABACInvalidModuleFailsClosedAtCompile(t *testing.T) {
	if _, err := policy.NewABAC(policy.ABACConfig{Module: "not rego {{{"}); err == nil {
		t.Fatal("invalid ABAC module must fail to compile")
	}
}
