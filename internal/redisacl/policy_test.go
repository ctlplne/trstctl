// SPDX-License-Identifier: BUSL-1.1

package redisacl

import (
	"reflect"
	"testing"
)

func TestCompileLimitsKeysAndCommands(t *testing.T) {
	rules, err := Compile(Role{
		KeyPrefixes: []string{"tenant-a:cache:", "tenant-a:jobs:"},
		Commands:    []string{"GET", "set", "del"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"~tenant-a:cache:*", "~tenant-a:jobs:*", "+get", "+set", "+del"}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("ACL rules = %#v, want %#v", rules, want)
	}
}

func TestCompileRefusesUnboundedOrAdministrativeAuthority(t *testing.T) {
	cases := []Role{
		{Commands: []string{"get"}},
		{KeyPrefixes: []string{""}, Commands: []string{"get"}},
		{KeyPrefixes: []string{"*"}, Commands: []string{"get"}},
		{KeyPrefixes: []string{"tenant:*"}, Commands: []string{"get"}},
		{KeyPrefixes: []string{"tenant:?"}, Commands: []string{"get"}},
		{KeyPrefixes: []string{"tenant:"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"config"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"acl"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"flushall"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"eval"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"scan"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"+@all"}},
		{KeyPrefixes: []string{"tenant:"}, Commands: []string{"get", "GET"}},
	}
	for _, policy := range cases {
		if rules, err := Compile(policy); err == nil {
			t.Errorf("Compile(%+v) = %#v, want rejection", policy, rules)
		}
	}
}
