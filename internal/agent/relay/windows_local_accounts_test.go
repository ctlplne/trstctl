// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
)

type localAccountsReader struct {
	calls *int
	fail  bool
}

func (r localAccountsReader) Inventory(context.Context) (winaccounts.Inventory, error) {
	*r.calls++
	result := winaccounts.Inventory{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Accounts: []winaccounts.Account{{Name: "OwnedAdmin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}}
	if r.fail {
		return result, errors.New("private native error")
	}
	return result, nil
}
func TestHostLocalAdministratorInventoryNeedsLocalGrantAndDropsPartialA268(t *testing.T) {
	intent, err := hostaccounts.NewInventoryIntent(uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	reader := localAccountsReader{calls: &calls}
	if _, err := collectWindowsLocalAccounts(t.Context(), intent, false, reader); err == nil || calls != 0 {
		t.Fatal("missing local grant reached SAM")
	}
	report, err := collectWindowsLocalAccounts(t.Context(), intent, true, reader)
	if err != nil || report.Status != "complete" || calls != 1 || len(report.Inventory.Accounts) != 1 {
		t.Fatal("complete authorized inventory failed", err)
	}
	reader.fail = true
	report, err = collectWindowsLocalAccounts(t.Context(), intent, true, reader)
	if err != nil || report.Status != "unavailable" || report.Failure != "native_read_failed" || report.Inventory != nil {
		t.Fatal("partial inventory became success", err)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "private native error") {
		t.Fatal("native error escaped")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	before := calls
	if _, err := collectWindowsLocalAccounts(canceled, intent, true, reader); err == nil || calls != before {
		t.Fatal("canceled job reached SAM")
	}
	path := filepath.Join(t.TempDir(), "read-only-host.json")
	if err := os.WriteFile(path, []byte(`{"windows_local_accounts_inventory":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile, err := LoadHostProfile(path)
	if err != nil || !profile.WindowsLocalAccountsInventory || len(profile.Actions) != 0 || len(profile.WindowsDependentWrites) != 0 || len(profile.AllowedRoots) != 0 {
		t.Fatal("read-only grant gained another capability", err)
	}
}

func TestHostLocalAdministratorInventoryBulkheadAndUnsupportedA268(t *testing.T) {
	intent, err := hostaccounts.NewInventoryIntent(uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	windowsLocalAccountsSlots <- struct{}{}
	_, err = CollectWindowsLocalAccountsInventory(t.Context(), intent, true)
	<-windowsLocalAccountsSlots
	if err == nil {
		t.Fatal("busy native reader was not rejected")
	}
	if runtime.GOOS != "windows" {
		report, err := CollectWindowsLocalAccountsInventory(t.Context(), intent, true)
		if err != nil || report.Status != "unavailable" || report.Failure != "unsupported_os" || report.Inventory != nil {
			t.Fatal("non-Windows became an empty native pass", err)
		}
	}
}

type localInventoryChannel struct {
	Channel
	redeemed                int
	outcome, detail, digest string
}

func (c *localInventoryChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redeemed++
	return nil, errors.New("read must not redeem")
}
func (c *localInventoryChannel) ReportJobResult(_ context.Context, _ int64, _ int, outcome, detail, digest string) (bool, error) {
	c.outcome = outcome
	c.detail = detail
	c.digest = digest
	return true, nil
}
func TestHostLocalAdministratorJobNeverRedeemsAndSignsOnlyPublicReadA268(t *testing.T) {
	intent, err := hostaccounts.NewInventoryIntent(uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(intent)
	job := Job{JobID: 18, Attempt: 2, Kind: KindWindowsLocalAccountsInventory, Payload: raw}
	channel := &localInventoryChannel{}
	if runJob(t.Context(), channel, nil, connector.LocalOpsConfig{}, nil, nil, nil, job) || channel.redeemed != 0 || channel.outcome != OutcomeFailed {
		t.Fatal("ungranted job redeemed material or succeeded")
	}
	if runtime.GOOS != "windows" {
		channel = &localInventoryChannel{}
		if !runJob(t.Context(), channel, nil, connector.LocalOpsConfig{WindowsLocalAccountsInventory: true}, nil, nil, nil, job) || channel.redeemed != 0 || channel.outcome != OutcomeExecuted || channel.digest != crypto.SHA256Hex([]byte(channel.detail)) {
			t.Fatal("public report bypassed evidence digest or redeemed material")
		}
		report, err := hostaccounts.DecodeInventoryReport([]byte(channel.detail))
		if err != nil || report.Validate(intent) != nil || report.Status != "unavailable" || report.Failure != "unsupported_os" {
			t.Fatal("unsupported receipt lost explicit coverage", err)
		}
	}
}
