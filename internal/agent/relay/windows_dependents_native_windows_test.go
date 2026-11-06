//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"os"
	"os/user"
	"testing"

	"trstctl.com/trstctl/internal/servicedependents"
)

func TestNativeWindowsInventoryCollectorA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_INVENTORY") != "1" {
		t.Skip("owned native Windows CI lane only")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	intent := hostInventoryIntent(t)
	intent.Binding.Account.SID = current.Uid
	intent, err = servicedependents.NewInventoryIntent(intent.RunID, intent.Binding)
	if err != nil {
		t.Fatal("native runner account SID", err)
	}
	if _, err := CollectWindowsInventory(t.Context(), intent, nil); err == nil {
		t.Fatal("native collector bypassed the local SID grant")
	}
	report, err := CollectWindowsInventory(t.Context(), intent, []string{current.Uid})
	if err != nil || !report.Complete() {
		t.Fatalf("native collector coverage incomplete: %+v err=%v", report.Coverage, err)
	}
	if err := report.Validate(intent); err != nil {
		t.Fatal(err)
	}
	t.Log("A267_WINDOWS_INVENTORY_OK: actual host collector and all three native readers, exact local SID grant; selected-workload lifecycle is proven separately")
}
