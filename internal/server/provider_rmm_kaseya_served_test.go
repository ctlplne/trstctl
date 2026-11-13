// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"regexp"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

var kaseyaEnrollmentLine = regexp.MustCompile(`^-Server "([^"]*)" -ServerName "([^"]*)" -Identity "([^"]*)" -Token "([^"]*)"$`)

// MSP-13 Done-when (served, Kaseya VSA stand-in written from the public help
// pages and module): the shared RMM connector proof — each customer's agents
// under its own VSA organization only, mapped to its own trstctl agents with
// health in the custom field, an install's token (handed to the install
// procedure through the enrollment field) enrolling only that agent's
// identity into the customer's own tenant once, no action on another
// customer's agent or on one moved to another organization, and neither the
// personal access token nor the install token in the debug log or the outbox.
func TestServedKaseyaAgentsHealthAndActionsMSP13(t *testing.T) {
	const user, pat = "trstctl-integration", "vsa-served-personal-access-token" // #nosec G101 -- test-only values (CWE-798)
	vsa := rmmtest.NewKaseya(user, pat)
	t.Cleanup(vsa.Close)
	for _, id := range []int64{41, 42, 43} {
		vsa.AddProcedure(id)
	}
	vsa.AddField("trstctlEnrollment")
	vsa.AddField("trstctlAgent")
	vsa.AddAgent(rmmtest.KaseyaAgent{ID: 600000001, OrgID: 71, Computer: "ALPHA-DC01", Online: true})
	vsa.AddAgent(rmmtest.KaseyaAgent{ID: 600000002, OrgID: 71, Computer: "ALPHA-NEW01"})
	vsa.AddAgent(rmmtest.KaseyaAgent{ID: 600000003, OrgID: 82, Computer: "BETA-APP01", Online: true})
	procedures := map[int64]string{41: "install", 42: "upgrade", 43: "remove"}
	runRMMConnectorProof(t, rmmProofCase{
		target: config.ProviderBillingTarget{ID: "vsa", Type: "kaseya", Endpoint: vsa.URL(), AllowInsecureLoopback: true,
			Kaseya: &config.KaseyaTarget{Username: user, AccessTokenRef: writeServedCredentialFile(t, "vsa-pat", pat),
				InstallProcedureID: 41, UpgradeProcedureID: 42, RemoveProcedureID: 43, EnrollmentField: "trstctlEnrollment", HealthField: "trstctlAgent"}},
		secret: pat, orgA: "71", orgB: "82", mapA: "71", a1: "600000001", a2: "600000002", b1: "600000003", a1Host: "ALPHA-DC01", b1Host: "BETA-APP01",
		reportsHealth: true,
		health: func(device string) string {
			id, _ := strconv.ParseInt(device, 10, 64)
			return vsa.Field(id, "trstctlAgent")
		},
		runs: func() []rmmProofRun {
			var out []rmmProofRun
			for _, run := range vsa.Runs() {
				r := rmmProofRun{Device: strconv.FormatInt(run.AgentID, 10), Action: procedures[run.ProcedureID]}
				if m := kaseyaEnrollmentLine.FindStringSubmatch(run.Enrollment); r.Action == "install" && m != nil {
					r.Server, r.ServerName, r.Identity, r.Token = m[1], m[2], m[3], m[4]
				}
				out = append(out, r)
			}
			return out
		},
		move: func(device, org string) {
			id, _ := strconv.ParseInt(device, 10, 64)
			o, _ := strconv.ParseInt(org, 10, 64)
			vsa.MoveAgent(id, o)
		},
		refused: func() int { _, _, refused := vsa.Counts(); return refused },
	})
}
