// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

func rotationFixture(t *testing.T) RotationIntent {
	t.Helper()
	value, e := rotationFixtureIntent()
	if e != nil {
		t.Fatal(e)
	}
	return value
}
func rotationFixtureIntent() (RotationIntent, error) {
	return NewRotationIntent(RotationIntent{RotationID: "58900000-0000-4000-8000-000000000001", AccountID: "58900000-0000-4000-8000-000000000002", TenantID: "58900000-0000-4000-8000-000000000003", AgentID: "58900000-0000-4000-8000-000000000004", InventoryRunID: "58900000-0000-4000-8000-000000000005", Native: winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "Owned Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}})
}

func rotationProof(i RotationIntent) RotationReport {
	at := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	return RotationReport{RotationID: i.RotationID, BindingDigest: i.BindingDigest, Status: "succeeded", ObservedAt: at, Proof: &winaccounts.RotationProof{Binding: i.Native, GenerationID: i.RotationID, NewAuthenticated: true, OldRefused: true, ObservedAt: at}}
}
func TestLocalRotationIntentAndProofBindExactHostSAMGenerationA268(t *testing.T) {
	i := rotationFixture(t)
	r := rotationProof(i)
	if e := r.Validate(i); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*RotationIntent){
		func(v *RotationIntent) { v.AgentID = v.AccountID }, func(v *RotationIntent) { v.TenantID = v.AccountID }, func(v *RotationIntent) { v.AccountID = v.AgentID },
		func(v *RotationIntent) { v.PredecessorGenerationID = v.AccountID }, func(v *RotationIntent) { v.InventoryRunID = v.AccountID },
		func(v *RotationIntent) { v.Native.Account.Name = "Another" }, func(v *RotationIntent) { v.Native.Account.SID = "S-1-5-21-1-2-3-1002" },
	} {
		v := i
		change(&v)
		if e := v.Validate(); e == nil {
			t.Fatal("changed authority kept its binding digest")
		}
		v, _ = NewRotationIntent(v)
		if r.Validate(v) == nil {
			t.Fatal("old native proof authorized changed source")
		}
	}
	r = rotationProof(i)
	r.Proof.OldRefused = false
	if r.Validate(i) == nil {
		t.Fatal("unrefused predecessor published success")
	}
	r = rotationProof(i)
	r.Proof.Binding.Account.SID = "S-1-5-21-9-8-7-1001"
	if r.Validate(i) == nil {
		t.Fatal("foreign token SID published success")
	}
	r = rotationProof(i)
	r.Status = "uncertain"
	r.Failure = "execution_uncertain"
	if r.Validate(i) == nil {
		t.Fatal("unknown native execution retained a success proof")
	}
	r.Proof = nil
	if e := r.Validate(i); e != nil {
		t.Fatal(e)
	}
	grant := RotationGrant{TenantID: i.TenantID, AgentID: i.AgentID, MachineSID: i.Native.Machine.SID, AccountSID: i.Native.Account.SID}
	if grant.Validate() != nil || !grant.Allows(i) {
		t.Fatal("exact local grant refused")
	}
	grant.AgentID = i.AccountID
	if grant.Allows(i) {
		t.Fatal("other host's grant authorized local reset")
	}
}
func TestLocalRotationWireRequiresClosedExplicitNativeFactsA268(t *testing.T) {
	i := rotationFixture(t)
	r := rotationProof(i)
	raw, _ := json.Marshal(i)
	report, _ := json.Marshal(r)
	if _, e := DecodeRotationIntent(raw); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeRotationReport(report); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"rotation_id":`, `"ROTATION_ID":"shadow","rotation_id":`, 1),
		strings.Replace(string(raw), `"rotation_id":`, `"rotatİon_id":"shadow","rotation_id":`, 1),
		strings.Replace(string(raw), `"predecessor_generation_id":"",`, "", 1),
		strings.Replace(string(raw), `"enabled":true,`, "", 1), strings.Replace(string(raw), `"locked":false,`, "", 1),
		strings.Replace(string(raw), `"name":"Owned Admin"`, `"name":"\ud800"`, 1),
		strings.Replace(string(raw), `"native":`, `"password":"must-refuse","native":`, 1),
	} {
		if _, e := DecodeRotationIntent([]byte(bad)); e == nil {
			t.Fatal("ambiguous, private or incomplete rotation intent accepted")
		}
	}
	for _, bad := range []string{
		strings.Replace(string(report), `"old_refused":true,`, "", 1),
		strings.Replace(string(report), `"new_authenticated":true,`, "", 1),
		strings.Replace(string(report), `"status":`, `"ſtatus":"uncertain","status":`, 1),
		strings.Replace(string(report), `"proof":`, `"password":"must-refuse","proof":`, 1),
		string(report) + " {}",
	} {
		if _, e := DecodeRotationReport([]byte(bad)); e == nil {
			t.Fatal("ambiguous, private or incomplete native proof accepted")
		}
	}
	raw[0] = 0xff
	if _, e := DecodeRotationIntent(raw); e == nil {
		t.Fatal("invalid UTF8 accepted")
	}
	if _, e := DecodeRotationReport(bytes.Repeat([]byte{'x'}, MaxRotationReportBytes+1)); e == nil {
		t.Fatal("oversized report accepted")
	}
}
func FuzzLocalAccountRotationWireA268(f *testing.F) {
	i, e := rotationFixtureIntent()
	if e != nil {
		f.Fatal(e)
		return
	}
	raw, _ := json.Marshal(i)
	proof, _ := json.Marshal(rotationProof(i))
	f.Add(raw)
	f.Add(proof)
	f.Add([]byte(`{"native":{"account":{"sid":"S-1-5-21-9-8-7-1001"}}}`))
	f.Add([]byte(`{"proof":{"old_refused":null}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if v, e := DecodeRotationIntent(raw); e == nil {
			if v.Validate() != nil {
				t.Fatal("decoded invalid intent")
			}
			encoded, e := json.Marshal(v)
			if e != nil || len(encoded) > MaxRotationIntentBytes {
				t.Fatal("accepted intent exceeded bound")
			}
			if _, e = DecodeRotationIntent(encoded); e != nil {
				t.Fatal("intent lost canonical facts", e)
			}
		}
		if v, e := DecodeRotationReport(raw); e == nil && v.Validate(i) == nil {
			encoded, e := json.Marshal(v)
			if e != nil || len(encoded) > MaxRotationReportBytes {
				t.Fatal("accepted proof exceeded bound")
			}
			again, e := DecodeRotationReport(encoded)
			if e != nil || again.Validate(i) != nil {
				t.Fatal("proof lost exact native facts", e)
			}
		}
	})
}
