// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

var automateInstallLine = regexp.MustCompile(`^install\.ps1!!! -NonInteractive -Server "([^"]*)" -ServerName "([^"]*)" -Identity "([^"]*)" -Token "([^"]*)"$`)

// MSP-11 Done-when (served, ConnectWise Automate stand-in written from the
// calls the published AutomateAPI module makes): the shared RMM connector
// proof without health (Automate's extra-data-field write is not public) —
// each customer's computers under its own Automate client only, mapped to its
// own agents, an install's token (appended to the install line) enrolling
// only that computer's identity into the customer's own tenant once, no
// action on another customer's computer or on one moved to another client,
// and neither the integrator password nor the token in the debug log or the
// outbox.
func TestServedAutomateComputersAndActionsMSP11(t *testing.T) {
	const user = "trstctl-integrator"
	const password = "automate-served-password" // #nosec G101 -- a test-only value (CWE-798)
	const clientID = "11111111-2222-4333-8444-555555555555"
	cwa := rmmtest.NewAutomate(user, password, clientID, 2)
	t.Cleanup(cwa.Close)
	cwa.AddComputer(rmmtest.AutomateComputer{ID: 501, ClientID: 9, Name: "ALPHA-DC01", Online: true})
	cwa.AddComputer(rmmtest.AutomateComputer{ID: 502, ClientID: 9, Name: "ALPHA-NEW01"})
	cwa.AddComputer(rmmtest.AutomateComputer{ID: 601, ClientID: 12, Name: "BETA-APP01", Online: true})
	runRMMConnectorProof(t, rmmProofCase{
		target: config.ProviderBillingTarget{ID: "automate", Type: "automate", Endpoint: cwa.URL(), AllowInsecureLoopback: true,
			Automate: &config.AutomateTarget{Username: user, PasswordRef: writeServedCredentialFile(t, "automate-password", password), ClientID: clientID,
				ExecuteCommandID: 2, InstallLine: "install.ps1!!! -NonInteractive", UpgradeLine: "upgrade.ps1!!! -NonInteractive", RemoveLine: "remove.ps1!!! -NonInteractive"}},
		secret: password, orgA: "9", orgB: "12", mapA: "9", a1: "501", a2: "502", b1: "601", a1Host: "ALPHA-DC01", b1Host: "BETA-APP01",
		runs: func() []rmmProofRun {
			var out []rmmProofRun
			for _, cmd := range cwa.Commands() {
				r := rmmProofRun{Device: strconv.FormatInt(cmd.ComputerID, 10)}
				r.Action, _, _ = strings.Cut(cmd.Line, ".ps1!!!")
				if m := automateInstallLine.FindStringSubmatch(cmd.Line); m != nil {
					r.Server, r.ServerName, r.Identity, r.Token = m[1], m[2], m[3], m[4]
				}
				out = append(out, r)
			}
			return out
		},
		move: func(device, org string) {
			id, _ := strconv.ParseInt(device, 10, 64)
			client, _ := strconv.ParseInt(org, 10, 64)
			cwa.MoveComputer(id, client)
		},
		refused: func() int { _, _, refused := cwa.Counts(); return refused },
	})
}
