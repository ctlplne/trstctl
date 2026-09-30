// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// F259: protocols.ssh_user_principals holds literal login names only.
func TestValidateSSHUserPrincipals(t *testing.T) {
	if errs := validateSSHUserPrincipals([]string{"deploy", "oncall", "root", "svc-backup"}); len(errs) != 0 {
		t.Fatalf("valid list refused: %v", errs)
	}
	for name, list := range map[string][]string{
		"empty entry":   {""},
		"padded":        {" root"},
		"space":         {"on call"},
		"comma":         {"a,b"},
		"star wildcard": {"ro*t"},
		"question mark": {"ro?t"},
		"control":       {"x\x01"},
		"duplicate":     {"deploy", "deploy"},
		"too long":      {strings.Repeat("a", 257)},
	} {
		if errs := validateSSHUserPrincipals(list); len(errs) == 0 {
			t.Errorf("%s: %q accepted", name, list)
		}
	}
	many := make([]string, maxSSHUserPrincipals+1)
	for i := range many {
		many[i] = fmt.Sprintf("user%d", i)
	}
	if errs := validateSSHUserPrincipals(many); len(errs) == 0 {
		t.Errorf("%d names accepted; the cap is %d", len(many), maxSSHUserPrincipals)
	}
}

func TestSSHUserPrincipalsFromEnvironment(t *testing.T) {
	var p Protocols
	applyProtocolsEnv(func(key string) string {
		if key == "TRSTCTL_PROTOCOLS_SSH_USER_PRINCIPALS" {
			return "deploy, oncall"
		}
		return ""
	}, &p)
	if !slices.Equal(p.SSHUserPrincipals, []string{"deploy", "oncall"}) {
		t.Fatalf("TRSTCTL_PROTOCOLS_SSH_USER_PRINCIPALS = %q", p.SSHUserPrincipals)
	}
}

func TestEvalProfileDefaultsSSHUserPrincipals(t *testing.T) {
	eff, err := Protocols{Profile: ProtocolProfileEval, EvalTenantID: "11111111-1111-4111-8111-111111111111"}.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(eff.SSHUserPrincipals, []string{DefaultEvalSSHUserPrincipal}) {
		t.Fatalf("eval profile principals = %q, want [%s]", eff.SSHUserPrincipals, DefaultEvalSSHUserPrincipal)
	}
	eff, err = Protocols{Profile: ProtocolProfileEval, EvalTenantID: "11111111-1111-4111-8111-111111111111", SSHUserPrincipals: []string{"alice"}}.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(eff.SSHUserPrincipals, []string{"alice"}) {
		t.Fatalf("eval profile replaced an explicit list: %q", eff.SSHUserPrincipals)
	}
}
