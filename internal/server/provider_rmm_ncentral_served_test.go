// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/rmm/ncentral"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

// MSP-12 Done-when (served, N-central stand-in written from the public API
// reference): the shared RMM connector proof — each customer's devices under
// its own N-central customer only, mapped to its own agents with health in
// the device custom property, an install's token enrolling only that
// device's identity into the customer's own tenant once, no action on
// another customer's device or on a device moved to another customer, and
// neither the API user's JWT nor the token in the debug log or the outbox.
func TestServedNCentralDevicesHealthAndActionsMSP12(t *testing.T) {
	const jwt = "eyJ.ncentral-served-user-jwt.sig" // #nosec G101 -- a test-only value (CWE-798)
	nc := rmmtest.NewNCentral(jwt)
	t.Cleanup(nc.Close)
	for _, id := range []int64{701, 702, 703} {
		nc.AddScript(id)
	}
	nc.AddProperty(88)
	nc.AddDevice(rmmtest.NCentralDevice{ID: 3001, CustomerID: 101, Name: "ALPHA-DC01"})
	nc.AddDevice(rmmtest.NCentralDevice{ID: 3002, CustomerID: 101, Name: "ALPHA-NEW01"})
	nc.AddDevice(rmmtest.NCentralDevice{ID: 4001, CustomerID: 202, Name: "BETA-APP01"})
	scripts := map[int64]string{701: "install", 702: "upgrade", 703: "remove"}
	runRMMConnectorProof(t, rmmProofCase{
		target: config.ProviderBillingTarget{ID: "ncentral", Type: "ncentral", Endpoint: nc.URL(), AllowInsecureLoopback: true,
			NCentral: &config.NCentralTarget{UserJWTRef: writeServedCredentialFile(t, "ncentral-jwt", jwt),
				InstallScriptID: 701, UpgradeScriptID: 702, RemoveScriptID: 703, HealthPropertyID: 88}},
		secret: jwt, orgA: "101", orgB: "202", mapA: "101", a1: "3001", a2: "3002", b1: "4001", a1Host: "ALPHA-DC01", b1Host: "BETA-APP01",
		reportsHealth: true,
		health: func(device string) string {
			id, _ := strconv.ParseInt(device, 10, 64)
			return nc.Property(id, 88)
		},
		runs: func() []rmmProofRun {
			var out []rmmProofRun
			for _, task := range nc.Tasks() {
				out = append(out, rmmProofRun{Device: strconv.FormatInt(task.DeviceID, 10), Action: scripts[task.ItemID],
					Server: task.Params[ncentral.ParamServer], ServerName: task.Params[ncentral.ParamServerName],
					Identity: task.Params[ncentral.ParamIdentity], Token: task.Params[ncentral.ParamToken]})
			}
			return out
		},
		move: func(device, org string) {
			id, _ := strconv.ParseInt(device, 10, 64)
			customer, _ := strconv.ParseInt(org, 10, 64)
			nc.MoveDevice(id, customer)
		},
		refused: func() int { _, _, refused := nc.Counts(); return refused },
	})
}
