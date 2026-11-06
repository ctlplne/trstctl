// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"encoding/json"
	"os"
	"path/filepath"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

type inventoryServiceReader struct {
	sid   string
	calls *int
}

func (r inventoryServiceReader) Discover(context.Context, string) ([]windependents.Service, error) {
	*r.calls++
	return []windependents.Service{{Name: "owned-service", AccountSID: r.sid, ConfigSHA256: strings.Repeat("b", 64)}}, nil
}

type inventoryTaskReader struct {
	sid   string
	calls *int
}

func (r inventoryTaskReader) Discover(context.Context, string) ([]windependents.Task, error) {
	*r.calls++
	return []windependents.Task{{Path: "\\owned\\task", AccountSID: r.sid, ConfigSHA256: strings.Repeat("c", 64), Enabled: true, LogonType: 1, ActionCount: 1}}, nil
}

type inventoryPoolReader struct {
	sid    string
	calls  *int
	failed bool
}

func (r inventoryPoolReader) Discover(context.Context, string) ([]windependents.Pool, error) {
	*r.calls++
	if r.failed {
		return nil, errors.New("private native text must not reach the report")
	}
	return []windependents.Pool{{Name: "owned-pool", AccountSID: r.sid, ConfigSHA256: strings.Repeat("d", 64), EncryptionProvider: "native", PasswordProtected: true}}, nil
}
func hostInventoryIntent(t *testing.T) servicedependents.InventoryIntent {
	t.Helper()
	intent, err := servicedependents.NewInventoryIntent("33333333-3333-4333-8333-333333333333", servicedependents.HostBinding{Account: servicedependents.AccountBinding{AccountID: "11111111-1111-4111-8111-111111111111", ProviderID: "ad-services", Name: "service", DN: "CN=service,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1001", GUID: strings.Repeat("a", 32)}, AgentID: "22222222-2222-4222-8222-222222222222", Revision: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}
func TestWindowsInventoryNeedsExactLocalSIDAndExplicitCoverageA267(t *testing.T) {
	intent := hostInventoryIntent(t)
	calls := 0
	sid := intent.Binding.Account.SID
	readers := windowsInventoryReaders{services: inventoryServiceReader{sid, &calls}, tasks: inventoryTaskReader{sid, &calls}, pools: inventoryPoolReader{sid, &calls, false}}
	if _, err := collectWindowsInventory(t.Context(), intent, nil, readers); err == nil || calls != 0 {
		t.Fatal("unapproved host identity reached native readers")
	}
	report, err := collectWindowsInventory(t.Context(), intent, []string{sid}, readers)
	if err != nil || !report.Complete() || calls != 3 {
		t.Fatal("native family collection incomplete", err)
	}
	readers.pools = inventoryPoolReader{sid, &calls, true}
	report, err = collectWindowsInventory(t.Context(), intent, []string{sid}, readers)
	if err != nil || report.Complete() || report.Coverage[2].Status != "unavailable" || report.Coverage[2].Failure != "native_read_failed" {
		t.Fatal("native failure became empty success", err)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "private native text") {
		t.Fatal("native error text escaped")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	before := calls
	if _, err := collectWindowsInventory(canceled, intent, []string{sid}, readers); err == nil || calls != before {
		t.Fatal("canceled inventory reached native readers")
	}
}
func TestWindowsInventoryOnlyProfileGrantsNoFileOrShellAuthorityA267(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(path, []byte(`{"windows_dependent_sids":["S-1-5-21-1-2-3-1001"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := LoadHostProfile(path)
	if err != nil || len(profile.WindowsDependentSIDs) != 1 || len(profile.AllowedRoots) != 0 || len(profile.Actions) != 0 {
		t.Fatal("read-only native profile was not preserved", err)
	}
	if err := os.WriteFile(path, []byte(`{"windows_dependent_sids":["S-1-5-21-1-2-3-1001"],"actions":[{"logical_name":"arbitrary","command":"/bin/sh"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadHostProfile(path); err == nil {
		t.Fatal("native discovery profile authorized an unrooted action")
	}

}
