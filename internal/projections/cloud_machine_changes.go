// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventCloudMachineChangeProposed   = "cloud.machine.change.proposed"
	EventCloudMachineChangeProgressed = "cloud.machine.change.progressed"
)

type CloudMachineChangeProposed struct {
	Record change.Record `json:"record"`
}
type CloudMachineChangeProgressed struct {
	ID       string                      `json:"id"`
	State    string                      `json:"state"`
	Result   *change.Result              `json:"result,omitempty"`
	Approval *store.OperationApprovalUse `json:"approval,omitempty"`
	At       time.Time                   `json:"at"`
}
