// SPDX-License-Identifier: BUSL-1.1

package automate_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/automate"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

const (
	automateUser     = "trstctl-integrator"
	automatePassword = `automate-password "with"\escapes` // #nosec G101 -- a test-only value with characters JSON must escape (CWE-798)
	automateClientID = "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f"
	executeCommand   = 2
)

func newInstance(t *testing.T) *rmmtest.Automate {
	t.Helper()
	s := rmmtest.NewAutomate(automateUser, automatePassword, automateClientID, executeCommand)
	t.Cleanup(s.Close)
	s.AddComputer(rmmtest.AutomateComputer{ID: 501, ClientID: 9, Name: "ALPHA-DC01", Online: true})
	s.AddComputer(rmmtest.AutomateComputer{ID: 502, ClientID: 9, Name: "ALPHA-WEB01"})
	s.AddComputer(rmmtest.AutomateComputer{ID: 601, ClientID: 12, Name: "BETA-APP01", Online: true})
	return s
}

func newClient(t *testing.T, s *rmmtest.Automate, password string) *automate.Client {
	t.Helper()
	c, err := automate.New(automate.Config{BaseURL: s.URL(), Username: automateUser, ClientID: automateClientID, CommandID: executeCommand,
		Commands: map[rmm.Action]string{rmm.ActionInstall: `powershell.exe!!! -NonInteractive -File C:\trstctl\install.ps1`,
			rmm.ActionUpgrade: `powershell.exe!!! -NonInteractive -File C:\trstctl\upgrade.ps1`, rmm.ActionRemove: `cmd.exe!!! /c C:\trstctl\remove.cmd`}},
		http.DefaultClient, automate.Credentials{Password: []byte(password)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-11 (connector): after signing in with the integrator user and the
// integration's client ID, a client lists only its own computers; a computer
// reads with its client; an install executes the install line with the
// server, identity and one-time token appended; upgrade and remove execute
// theirs; health is not written (no public call); an integrator user that
// needs two-factor sign-in and a wrong password are refused before anything
// runs, and no error names the password.
func TestAutomateComputersAndActionsMSP11(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, automatePassword)
	computers, err := c.ListDevices(ctx, "9")
	if err != nil || len(computers) != 2 || computers[0].ID != "501" || computers[0].Name != "ALPHA-DC01" || !computers[0].Online ||
		computers[1].Online || computers[0].OrgID != "9" {
		t.Fatalf("client 9 computers = %+v %v", computers, err)
	}
	if d, found, err := c.Device(ctx, "601"); err != nil || !found || d.OrgID != "12" {
		t.Fatalf("computer 601 = %+v %v %v", d, found, err)
	}
	if _, found, err := c.Device(ctx, "999"); err != nil || found {
		t.Fatalf("an unknown computer = %v %v", found, err)
	}
	token := []byte(`one-time "token"`)
	if id, err := c.RunAction(ctx, "502", rmm.ActionInstall, &rmm.InstallParams{Server: "agents.example.test:8443", ServerName: "agents.example.test",
		Identity: "rmm-automate-502", Token: token}); err != nil || id == "" {
		t.Fatalf("install = %q %v", id, err)
	}
	if _, err := c.RunAction(ctx, "501", rmm.ActionUpgrade, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunAction(ctx, "501", rmm.ActionRemove, nil); err != nil {
		t.Fatal(err)
	}
	commands := s.Commands()
	if len(commands) != 3 || commands[0].ComputerID != 502 || commands[0].CommandID != executeCommand ||
		commands[0].Line != `powershell.exe!!! -NonInteractive -File C:\trstctl\install.ps1 -Server "agents.example.test:8443" -ServerName "agents.example.test" -Identity "rmm-automate-502" -Token "`+string(token)+`"` ||
		commands[1].Line != `powershell.exe!!! -NonInteractive -File C:\trstctl\upgrade.ps1` || commands[2].Line != `cmd.exe!!! /c C:\trstctl\remove.cmd` {
		t.Fatalf("commands = %+v", commands)
	}
	if _, err := c.RunAction(ctx, "501", rmm.ActionInstall, nil); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an install without a token = %v", err)
	}
	if err := c.ReportHealth(ctx, "501", "trstctl agent healthy (version 1.4.2)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListDevices(ctx, "client-a"); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("a client that is not a number = %v", err)
	}

	wrong := newClient(t, s, "not-the-password")
	if _, err := wrong.RunAction(ctx, "501", rmm.ActionUpgrade, nil); !errors.Is(err, rmm.ErrBeforeWrite) || strings.Contains(err.Error(), automatePassword) {
		t.Fatalf("a wrong password = %v", err)
	}
	s.RequireTwoFactor()
	if _, err := newClient(t, s, automatePassword).RunAction(ctx, "501", rmm.ActionUpgrade, nil); !errors.Is(err, rmm.ErrBeforeWrite) ||
		!strings.Contains(err.Error(), "two-factor") {
		t.Fatalf("an integrator user that needs two-factor = %v", err)
	}
	if len(s.Commands()) != 3 {
		t.Fatalf("a refused sign-in ran something: %d commands", len(s.Commands()))
	}
}
