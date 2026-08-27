// SPDX-License-Identifier: MPL-2.0

package driftplan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/drift"
)

func TestResolveNormalizesThePreviewAndExecutionContract(t *testing.T) {
	plan, err := Resolve(json.RawMessage(`{
		"watched":[
			{"path":" /etc/tls/edge.pem ","class":" certificate ","fingerprint":" sha256:abc ","mode":"0644"},
			{"path":"/etc/ssh/ssh_host_ed25519_key.pub","class":"ssh_key","fingerprint":"sha256:def","restricted":true}
		],
		"scope":[" /etc/tls ","/etc/tls","","/etc/ssh"],
		"policy":{" certificate ":"alert_and_block","ssh_key":"alert_only"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.NormalizedTargets, []string{"/etc/tls/edge.pem", "/etc/ssh/ssh_host_ed25519_key.pub"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized targets = %#v, want %#v", got, want)
	}
	if got, want := plan.Scope, []string{"/etc/tls", "/etc/ssh"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope = %#v, want %#v", got, want)
	}
	if len(plan.Watched) != 2 || plan.Watched[0].Mode.Perm() != 0o644 || !plan.Watched[1].Restricted {
		t.Fatalf("watched plan = %+v", plan.Watched)
	}
	if plan.Policy.Mode("certificate") != drift.AlertAndBlock || plan.Policy.Mode("ssh_key") != drift.AlertOnly {
		t.Fatalf("policy = %+v", plan.Policy)
	}
}

func TestResolveRejectsUnsafeOrIncompletePlans(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: `{"watched":[]}`, want: "at least one watched credential"},
		{name: "missing fingerprint", raw: `{"watched":[{"path":"/tmp/a","class":"certificate"}]}`, want: "requires path, class, and fingerprint"},
		{name: "bad mode", raw: `{"watched":[{"path":"/tmp/a","class":"certificate","fingerprint":"abc","mode":"banana"}]}`, want: "mode"},
		{name: "auto remediation", raw: `{"watched":[{"path":"/tmp/a","class":"certificate","fingerprint":"abc"}],"policy":{"certificate":"auto_remediate"}}`, want: "does not auto-remediate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(json.RawMessage(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func FuzzResolve(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"watched":[]}`,
		`{"watched":[{"path":"/tmp/a","class":"certificate","fingerprint":"sha256:abc","mode":"0600"}]}`,
		`{"watched":[{"path":"/tmp/a","class":"private_key","fingerprint":"sha256:def","restricted":true}],"policy":{"private_key":"alert_and_block"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		plan, err := Resolve(raw)
		if err != nil {
			return
		}
		if len(plan.Watched) == 0 || len(plan.Watched) != len(plan.NormalizedTargets) {
			t.Fatalf("successful plan has inconsistent watched/target counts: %+v", plan)
		}
		for i, watched := range plan.Watched {
			if watched.Path == "" || watched.Class == "" || watched.Fingerprint == "" || plan.NormalizedTargets[i] != watched.Path {
				t.Fatalf("successful plan contains an incomplete watched record: %+v", plan)
			}
		}
	})
}
