// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"trstctl.com/trstctl/internal/crypto/windependents"
)

func inventoryFixtureIntent(t testing.TB) InventoryIntent {
	t.Helper()
	binding := HostBinding{Account: AccountBinding{AccountID: "11111111-1111-4111-8111-111111111111", ProviderID: "ad-services", Name: "service", DN: "CN=service,OU=services,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1001", GUID: strings.Repeat("a", 32)}, AgentID: "22222222-2222-4222-8222-222222222222", Revision: 1, Enabled: true}
	intent, err := NewInventoryIntent("33333333-3333-4333-8333-333333333333", binding)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}
func inventoryFixtureReport(t testing.TB) InventoryReport {
	intent := inventoryFixtureIntent(t)
	sid := intent.Binding.Account.SID
	return InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(), Coverage: []FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}, Services: []windependents.Service{{Name: "orders", AccountSID: sid, ConfigSHA256: strings.Repeat("b", 64)}}, Tasks: []windependents.Task{{Path: "\\owned\\work", AccountSID: sid, ConfigSHA256: strings.Repeat("c", 64), Enabled: true, LogonType: 1, ActionCount: 1}}, Pools: []windependents.Pool{{Name: "orders-pool", AccountSID: sid, ConfigSHA256: strings.Repeat("d", 64), EncryptionProvider: "owned-native-provider", PasswordProtected: true}}}
}
func TestInventoryBindingAndNativeFamilyCoverageA267(t *testing.T) {
	intent := inventoryFixtureIntent(t)
	report := inventoryFixtureReport(t)
	if err := report.Validate(intent); err != nil || !report.Complete() {
		t.Fatal("complete exact native inventory refused", err)
	}
	for _, change := range []func(*InventoryReport){
		func(r *InventoryReport) { r.BindingDigest = strings.Repeat("f", 64) },
		func(r *InventoryReport) { r.RunID = "44444444-4444-4444-8444-444444444444" },
		func(r *InventoryReport) { r.Coverage = r.Coverage[:2] },
		func(r *InventoryReport) { r.Coverage[2] = r.Coverage[0] },
		func(r *InventoryReport) { r.Services[0].AccountSID = "S-1-5-21-1-2-3-1002" },
		func(r *InventoryReport) { r.Tasks[0].ConfigSHA256 = "" },
		func(r *InventoryReport) { r.Pools[0].EncryptionProvider = "" },
		func(r *InventoryReport) { r.Services = append(r.Services, r.Services[0]) },
		func(r *InventoryReport) { r.Tasks = append(r.Tasks, r.Tasks[0]) },
		func(r *InventoryReport) { r.Pools = append(r.Pools, r.Pools[0]) },
	} {
		candidate := inventoryFixtureReport(t)
		change(&candidate)
		if candidate.Validate(intent) == nil {
			t.Fatal("foreign/incomplete native inventory admitted")
		}
	}
	report = inventoryFixtureReport(t)
	report.Pools = nil
	report.Coverage[2] = FamilyCoverage{Family: "iis", Status: "unavailable", Failure: "not_installed"}
	if err := report.Validate(intent); err != nil || report.Complete() {
		t.Fatal("unavailable family became empty complete coverage", err)
	}
	altered := intent
	altered.Binding.AgentID = "44444444-4444-4444-8444-444444444444"
	if altered.Validate() == nil {
		t.Fatal("host binding was changed without changing its authority digest")
	}
}
func FuzzInventoryReportBindingA267(f *testing.F) {
	f.Add([]byte("{}"))
	valid, err := json.Marshal(inventoryFixtureReport(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxInventoryReportBytes {
			return
		}
		var report InventoryReport
		if json.Unmarshal(raw, &report) != nil {
			return
		}
		intent := inventoryFixtureIntent(t)
		if err := report.Validate(intent); err == nil {
			if report.RunID != intent.RunID || report.BindingDigest != intent.BindingDigest || len(report.Coverage) != 3 {
				t.Fatal("unbound report admitted")
			}
		}
	})
}

func TestInventoryDecoderRejectsAmbiguousFieldsA267(t *testing.T) {
	for _, raw := range []string{`{"run_id":"a","Run_ID":"b"}`, `{"run_id":"a","\u0072un_id":"b"}`, `{"unrecognized":"value"}`, `{}{}`} {
		if _, err := DecodeInventoryReport([]byte(raw)); err == nil {
			t.Fatal("ambiguous report admitted")
		}
	}
}
func FuzzInventoryDecoderA267(f *testing.F) {
	f.Add([]byte("{}"))
	valid, err := json.Marshal(inventoryFixtureReport(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxInventoryReportBytes {
			return
		}
		report, err := DecodeInventoryReport(raw)
		if err == nil {
			_ = report.Validate(inventoryFixtureIntent(t))
		}
	})
}

func TestInventoryGeneratedNativeBindingsA267(t *testing.T) {
	property := func(rid uint32, revision uint16) bool {
		binding := inventoryFixtureIntent(t).Binding
		binding.Account.SID = "S-1-5-21-1-2-3-" + strconv.FormatUint(uint64(rid)%4294967295+1, 10)
		binding.Revision = int64(revision) + 1
		intent, err := NewInventoryIntent("33333333-3333-4333-8333-333333333333", binding)
		if err != nil {
			return false
		}
		report := inventoryFixtureReport(t)
		report.BindingDigest = intent.BindingDigest
		for i := range report.Services {
			report.Services[i].AccountSID = binding.Account.SID
		}
		for i := range report.Tasks {
			report.Tasks[i].AccountSID = binding.Account.SID
		}
		for i := range report.Pools {
			report.Pools[i].AccountSID = binding.Account.SID
		}
		if report.Validate(intent) != nil {
			return false
		}
		changed := binding
		changed.Revision++
		rebound, err := NewInventoryIntent(intent.RunID, changed)
		return err == nil && report.Validate(rebound) != nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
