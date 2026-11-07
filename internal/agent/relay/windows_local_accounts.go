// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
)

const KindWindowsLocalAccountsInventory = hostaccounts.InventoryDestination

var windowsLocalAccountsSlots = make(chan struct{}, 1)

type windowsLocalAccountsReader interface {
	Inventory(context.Context) (winaccounts.Inventory, error)
}

// CollectWindowsLocalAccountsInventory reads only after an explicit host-local
// grant. Its independent one-slot bulkhead rejects concurrent reads promptly.
func CollectWindowsLocalAccountsInventory(ctx context.Context, intent hostaccounts.InventoryIntent, allowed bool) (hostaccounts.InventoryReport, error) {
	if !allowed {
		return hostaccounts.InventoryReport{}, errors.New("relay: local administrator inventory is not granted by the host profile")
	}
	select {
	case windowsLocalAccountsSlots <- struct{}{}:
		defer func() { <-windowsLocalAccountsSlots }()
	default:
		return hostaccounts.InventoryReport{}, errors.New("relay: local administrator inventory worker is busy")
	}
	return collectWindowsLocalAccounts(ctx, intent, allowed, winaccounts.New())
}
func collectWindowsLocalAccounts(ctx context.Context, intent hostaccounts.InventoryIntent, allowed bool, reader windowsLocalAccountsReader) (hostaccounts.InventoryReport, error) {
	var report hostaccounts.InventoryReport
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if err := intent.Validate(); err != nil {
		return report, err
	}
	if !allowed || reader == nil {
		return report, errors.New("relay: local administrator inventory is not locally authorized")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	value, err := reader.Inventory(bounded)
	report = hostaccounts.InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "complete"}
	if err != nil {
		report.Status = "unavailable"
		report.Failure = "native_read_failed"
		switch {
		case errors.Is(err, winaccounts.ErrUnsupported):
			report.Failure = "unsupported_os"
		case errors.Is(err, winaccounts.ErrInventoryBound):
			report.Failure = "limit_exceeded"
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			report.Failure = "cancelled"
		}
	} else {
		report.Inventory = &value
	}
	return report, report.Validate(intent)
}
func runWindowsLocalAccountsInventory(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	intent, err := hostaccounts.DecodeInventoryIntent(job.Payload)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Local administrator inventory authority is invalid")
		return false
	}
	observed, err := CollectWindowsLocalAccountsInventory(ctx, intent, profile.WindowsLocalAccountsInventory)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Local administrator inventory is not locally authorized or could not be validated")
		return false
	}
	raw, err := json.Marshal(observed)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Local administrator inventory report could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	return true
}
