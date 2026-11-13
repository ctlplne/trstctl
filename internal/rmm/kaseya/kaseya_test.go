// SPDX-License-Identifier: BUSL-1.1

package kaseya_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/kaseya"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

const (
	vsaUser = "trstctl-integration"
	vsaPAT  = `vsa-pat-"with"\escapes` // #nosec G101 -- a test-only value with characters JSON must escape (CWE-798)
)

func newInstance(t *testing.T) *rmmtest.Kaseya {
	t.Helper()
	s := rmmtest.NewKaseya(vsaUser, vsaPAT)
	t.Cleanup(s.Close)
	for _, id := range []int64{41, 42, 43} {
		s.AddProcedure(id)
	}
	s.AddField("trstctlEnrollment")
	s.AddField("trstctlAgent")
	s.AddAgent(rmmtest.KaseyaAgent{ID: 600000001, OrgID: 71, Computer: "ALPHA-DC01", Online: true})
	s.AddAgent(rmmtest.KaseyaAgent{ID: 600000002, OrgID: 71, Computer: "ALPHA-WEB01"})
	s.AddAgent(rmmtest.KaseyaAgent{ID: 600000003, OrgID: 82, Computer: "BETA-APP01", Online: true})
	return s
}

func newClient(t *testing.T, s *rmmtest.Kaseya, pat string) *kaseya.Client {
	t.Helper()
	c, err := kaseya.New(kaseya.Config{BaseURL: s.URL(), Username: vsaUser, EnrollmentField: "trstctlEnrollment", HealthField: "trstctlAgent",
		Procedures: map[rmm.Action]int64{rmm.ActionInstall: 41, rmm.ActionUpgrade: 42, rmm.ActionRemove: 43}},
		http.DefaultClient, kaseya.Credentials{AccessToken: []byte(pat)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-13 (connector): after a Basic sign-in with the user's personal access
// token, an organization lists only its own agents; an agent reads with its
// organization; an install writes the enrollment line (server, identity and
// one-time token) to the agent's enrollment field and then runs the install
// procedure; upgrade and remove run their procedures; health lands in the
// configured custom field; a wrong token is refused before anything runs and
// no error names it.
func TestKaseyaAgentsActionsAndHealthMSP13(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, vsaPAT)
	agents, err := c.ListDevices(ctx, "71")
	if err != nil || len(agents) != 2 || agents[0].ID != "600000001" || agents[0].Name != "ALPHA-DC01" || !agents[0].Online || agents[1].Online ||
		agents[0].OrgID != "71" {
		t.Fatalf("organization 71 agents = %+v %v", agents, err)
	}
	if d, found, err := c.Device(ctx, "600000003"); err != nil || !found || d.OrgID != "82" {
		t.Fatalf("agent 600000003 = %+v %v %v", d, found, err)
	}
	if _, found, err := c.Device(ctx, "600000099"); err != nil || found {
		t.Fatalf("an unknown agent = %v %v", found, err)
	}
	token := []byte(`one-time "token"`)
	if _, err := c.RunAction(ctx, "600000002", rmm.ActionInstall, &rmm.InstallParams{Server: "agents.example.test:8443", ServerName: "agents.example.test",
		Identity: "rmm-vsa-600000002", Token: token}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunAction(ctx, "600000001", rmm.ActionUpgrade, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunAction(ctx, "600000001", rmm.ActionRemove, nil); err != nil {
		t.Fatal(err)
	}
	runs := s.Runs()
	if len(runs) != 3 || runs[0].ProcedureID != 41 || runs[0].AgentID != 600000002 ||
		runs[0].Enrollment != `-Server "agents.example.test:8443" -ServerName "agents.example.test" -Identity "rmm-vsa-600000002" -Token "`+string(token)+`"` ||
		runs[1].ProcedureID != 42 || runs[1].Enrollment != "" || runs[2].ProcedureID != 43 {
		t.Fatalf("runs = %+v", runs)
	}
	if _, err := c.RunAction(ctx, "600000001", rmm.ActionInstall, nil); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an install without a token = %v", err)
	}
	if err := c.ReportHealth(ctx, "600000001", "trstctl agent healthy (version 1.4.2)"); err != nil {
		t.Fatal(err)
	}
	if got := s.Field(600000001, "trstctlAgent"); got != "trstctl agent healthy (version 1.4.2)" {
		t.Fatalf("health field = %q", got)
	}
	if _, err := c.ListDevices(ctx, "org-a"); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an organization that is not a number = %v", err)
	}
	if _, err := c.RunAction(ctx, "600000001", rmm.Action("reboot"), nil); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an unconfigured action = %v", err)
	}

	wrong := newClient(t, s, "not-the-token")
	if _, err := wrong.RunAction(ctx, "600000001", rmm.ActionUpgrade, nil); !errors.Is(err, rmm.ErrBeforeWrite) || strings.Contains(err.Error(), vsaPAT) {
		t.Fatalf("a wrong token = %v", err)
	}
	if len(s.Runs()) != 3 {
		t.Fatalf("a wrong token ran something: %d runs", len(s.Runs()))
	}
}
