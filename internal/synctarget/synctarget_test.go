// SPDX-License-Identifier: BUSL-1.1

package synctarget

import (
	"strings"
	"testing"
)

// Every registered type names itself, its platform and grammar, and either
// has a vendor endpoint or is self-hosted.
func TestEveryTargetDescribesItselfA241(t *testing.T) {
	if len(Types()) == 0 {
		t.Fatal("no hosted targets registered")
	}
	for _, typ := range Types() {
		target, ok := Lookup(typ)
		if !ok || target.Type != typ || target.Name == "" || target.Platform == "" || target.Grammar == "" || target.parse == nil {
			t.Fatalf("%s is not fully described: %+v", typ, target)
		}
		if target.Endpoint != "" && !strings.HasPrefix(target.Endpoint, "https://") {
			t.Fatalf("%s endpoint %q is not HTTPS", typ, target.Endpoint)
		}
	}
	if _, ok := Lookup("vault-kv-v2"); ok {
		t.Fatal("a built-in target is listed as hosted")
	}
}

func TestParseBindingA241(t *testing.T) {
	for _, c := range []struct {
		typ, binding string
		want         Binding
		err          string
	}{
		{"heroku", "payments-api", Binding{"app": "payments-api"}, ""},
		{"heroku", "payments api", nil, "one field"},
		{"railway", "environment 66666666-7777-4888-8999-aaaaaaaaaaaa project 11111111-2222-4333-8444-555555555555",
			Binding{"project": "11111111-2222-4333-8444-555555555555", "environment": "66666666-7777-4888-8999-aaaaaaaaaaaa"}, ""},
		{"railway", "project 11111111-2222-4333-8444-555555555555 project 11111111-2222-4333-8444-555555555555", nil, "given twice"},
		{"railway", "project 11111111-2222-4333-8444-555555555555 region x", nil, "unknown keyword"},
		{"qovery", "environment aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Binding{"scope": "ENVIRONMENT", "parent": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}, ""},
		{"laravel-forge", "org acme server 101 site 202", Binding{"org": "acme", "server": "101", "site": "202"}, ""},
		{"nope", "x", nil, "not a hosted secret-sync target"},
	} {
		got, err := ParseBinding(c.typ, c.binding)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("%s %q: err = %v, want %q", c.typ, c.binding, err, c.err)
			}
			continue
		}
		if err != nil || len(got) != len(c.want) {
			t.Fatalf("%s %q: %v %v", c.typ, c.binding, got, err)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s %q: %s = %q, want %q", c.typ, c.binding, k, got[k], v)
			}
		}
	}
}

func TestValidKeyA241(t *testing.T) {
	for _, c := range []struct {
		typ, key string
		ok       bool
	}{
		{"heroku", "DB_PASSWORD", true},
		{"heroku", "db/password", false},
		{"heroku", "1PASSWORD", false},
		{"heroku", "HEROKU_API_KEY", false},
		{"qovery", "QOVERY_TOKEN", false},
		{"qovery", "_LEADING", false},
		{"northflank", "db/password", true},
		{"render", strings.Repeat("A", 256), false},
	} {
		target, _ := Lookup(c.typ)
		if err := target.ValidKey(c.key); (err == nil) != c.ok {
			t.Fatalf("%s %q: err = %v, want ok=%v", c.typ, c.key, err, c.ok)
		}
	}
}
