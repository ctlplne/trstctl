// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

const KindWindowsDependentInventory = servicedependents.InventoryDestination

type windowsInventoryReaders struct {
	services interface {
		Discover(context.Context, string) ([]windependents.Service, error)
	}
	tasks interface {
		Discover(context.Context, string) ([]windependents.Task, error)
	}
	pools interface {
		Discover(context.Context, string) ([]windependents.Pool, error)
	}
	unsupported bool
}

var windowsInventorySlots = make(chan struct{}, 1)

// CollectWindowsInventory reads one exact locally authorized account. The native
// interfaces expose discovery only: no password write or restart is reachable.
func CollectWindowsInventory(ctx context.Context, intent servicedependents.InventoryIntent, allowedSIDs []string) (servicedependents.InventoryReport, error) {
	select {
	case windowsInventorySlots <- struct{}{}:
		defer func() { <-windowsInventorySlots }()
	default:
		return servicedependents.InventoryReport{}, errors.New("relay: Windows inventory worker is busy")
	}
	readers := windowsInventoryReaders{unsupported: runtime.GOOS != "windows"}
	if !readers.unsupported {
		tasks, err := windependents.NewTasks(windependents.TaskExecutionPolicy{})
		if err != nil {
			return servicedependents.InventoryReport{}, err
		}
		readers.services = windependents.NewServices()
		readers.tasks = tasks
		readers.pools = windependents.NewPools()
	}
	return collectWindowsInventory(ctx, intent, allowedSIDs, readers)
}
func collectWindowsInventory(ctx context.Context, intent servicedependents.InventoryIntent, allowedSIDs []string, readers windowsInventoryReaders) (servicedependents.InventoryReport, error) {
	var report servicedependents.InventoryReport
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if err := intent.Validate(); err != nil {
		return report, err
	}
	if len(allowedSIDs) > 256 || !slices.Contains(allowedSIDs, intent.Binding.Account.SID) {
		return report, errors.New("relay: Windows account SID is not authorized by the local host profile")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report.RunID = intent.RunID
	report.BindingDigest = intent.BindingDigest
	report.ObservedAt = time.Now().UTC()
	if readers.unsupported {
		for _, family := range []string{"services", "tasks", "iis"} {
			report.Coverage = append(report.Coverage, servicedependents.FamilyCoverage{Family: family, Status: "unavailable", Failure: "unsupported_os"})
		}
		return report, report.Validate(intent)
	}
	if readers.services == nil || readers.tasks == nil || readers.pools == nil {
		return report, errors.New("relay: native Windows inventory readers are incomplete")
	}
	coverage := func(family string, err error) {
		entry := servicedependents.FamilyCoverage{Family: family, Status: "complete"}
		if err != nil {
			entry.Status = "unavailable"
			entry.Failure = "native_read_failed"
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				entry.Failure = "cancelled"
			}
		}
		report.Coverage = append(report.Coverage, entry)
	}
	sid := intent.Binding.Account.SID
	var err error
	report.Services, err = readers.services.Discover(bounded, sid)
	if err != nil {
		report.Services = nil
	}
	coverage("services", err)
	if err = bounded.Err(); err == nil {
		report.Tasks, err = readers.tasks.Discover(bounded, sid)
	}
	if err != nil {
		report.Tasks = nil
	}
	coverage("tasks", err)
	if err = bounded.Err(); err == nil {
		report.Pools, err = readers.pools.Discover(bounded, sid)
	}
	if err != nil {
		report.Pools = nil
	}
	coverage("iis", err)
	return report, report.Validate(intent)
}
func runWindowsDependentInventory(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	intent, err := servicedependents.DecodeInventoryIntent(job.Payload)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Windows dependent inventory intent is invalid")
		return false
	}
	observed, err := CollectWindowsInventory(ctx, intent, profile.WindowsDependentSIDs)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Windows dependent inventory is not locally authorized or could not be validated")
		return false
	}
	encoded, err := json.Marshal(observed)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "Windows dependent inventory report could not be encoded")
		return false
	}
	// A partial observation is a successfully executed read, with incomplete
	// native coverage retained explicitly. It cannot authorize rotation.
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), crypto.SHA256Hex(encoded))
	return true
}
