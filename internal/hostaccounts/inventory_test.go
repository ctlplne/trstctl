// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

func inventoryFixture(t *testing.T) (InventoryIntent, InventoryReport) {
	t.Helper()
	intent, err := NewInventoryIntent(uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	report := InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "complete", Inventory: &winaccounts.Inventory{Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3}, Accounts: []winaccounts.Account{{Name: "Owned Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}}}
	return intent, report
}
func TestLocalAdministratorInventoryBindsExactHostAndCompleteSAMOnlyA268(t *testing.T) {
	intent, report := inventoryFixture(t)
	if err := report.Validate(intent); err != nil {
		t.Fatal(err)
	}
	foreign := intent
	foreign.AgentID = uuid.NewString()
	if report.Validate(foreign) == nil {
		t.Fatal("foreign host accepted")
	}
	foreign = intent
	foreign.TenantID = uuid.NewString()
	if report.Validate(foreign) == nil {
		t.Fatal("foreign tenant accepted")
	}
	report.Inventory.Accounts[0].SID = "S-1-5-21-9-8-7-1001"
	if report.Validate(intent) == nil {
		t.Fatal("domain or other machine account accepted as local")
	}
	_, report = inventoryFixture(t)
	report.RunID = intent.RunID
	report.BindingDigest = intent.BindingDigest
	report.Inventory.Machine.Role = 5
	if report.Validate(intent) == nil {
		t.Fatal("domain controller inventory accepted")
	}
	_, report = inventoryFixture(t)
	report.RunID = intent.RunID
	report.BindingDigest = intent.BindingDigest
	report.Status = "unavailable"
	report.Failure = "native_read_failed"
	if report.Validate(intent) == nil {
		t.Fatal("failed report preserved a partial account list")
	}
	report.Inventory = nil
	if err := report.Validate(intent); err != nil {
		t.Fatal(err)
	}
	report.Failure = "native error text"
	if report.Validate(intent) == nil {
		t.Fatal("unbounded native failure text accepted")
	}
}
func TestLocalAdministratorWireRejectsAmbiguousAndPrivateFieldsA268(t *testing.T) {
	intent, report := inventoryFixture(t)
	raw, _ := json.Marshal(intent)
	if _, err := DecodeInventoryIntent(raw); err != nil {
		t.Fatal(err)
	}
	reportRaw, _ := json.Marshal(report)
	if _, err := DecodeInventoryReport(reportRaw); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(reportRaw), `"run_id":`, `"RUN_ID":"shadow","run_id":`, 1)),
		[]byte(strings.Replace(string(reportRaw), `"name":"Owned Admin"`, `"name":"Owned Admin","password":"must-refuse"`, 1)),
		append(append([]byte{}, reportRaw...), []byte(` {}`)...),
		[]byte(strings.Replace(string(reportRaw), `"name":"Owned Admin"`, `"name":"`+strings.Repeat("x", MaxInventoryReportBytes)+`"`, 1)),
	} {
		if _, err := DecodeInventoryReport(raw); err == nil {
			t.Fatal("ambiguous or private report accepted")
		}
	}
}
func FuzzLocalAdministratorInventoryReportA268(f *testing.F) {
	intent, err := NewInventoryIntent("33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if err != nil {
		f.Fatal(err)
	}
	accepted := InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Status: "complete", Inventory: &winaccounts.Inventory{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Accounts: []winaccounts.Account{}}}
	encoded, err := json.Marshal(accepted)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"run_id":"one","RUN_ID":"two"}`))
	f.Add([]byte(`{"inventory":{"machine":{"role":5}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := DecodeInventoryReport(raw)
		if err != nil {
			return
		}
		intent, err := NewInventoryIntent(value.RunID, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
		if err != nil {
			return
		}
		if value.Validate(intent) == nil {
			encoded, err := json.Marshal(value)
			if err != nil || len(encoded) > MaxInventoryReportBytes {
				t.Fatal("accepted report exceeded bound")
			}
		}
	})
}

func TestLocalAdministratorWirePreservesExactJSONIdentityA268(t *testing.T) {
	_, report := inventoryFixture(t)
	raw, _ := json.Marshal(report)
	for _, bad := range []string{
		strings.Replace(string(raw), `"status":`, `"ſtatus":"unavailable","status":`, 1),
		strings.Replace(string(raw), `"name":"Owned Admin"`, `"name":"\ud800"`, 1),
		strings.Replace(string(raw), `"name":"Owned Admin"`, `"name":"\udc00"`, 1),
	} {
		if _, err := DecodeInventoryReport([]byte(bad)); err == nil {
			t.Fatal("ambiguous Unicode identity accepted")
		}
	}
}
