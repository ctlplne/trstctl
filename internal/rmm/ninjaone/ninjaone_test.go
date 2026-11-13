// SPDX-License-Identifier: BUSL-1.1

package ninjaone_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/ninjaone"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

const (
	ninjaClient = "trstctl-ninja-client"
	ninjaSecret = `ninja-secret "with"\escapes` // #nosec G101 -- a test-only value with characters JSON and forms must escape (CWE-798)
)

func newClient(t *testing.T, s *rmmtest.NinjaOne, secret string) *ninjaone.Client {
	t.Helper()
	c, err := ninjaone.New(ninjaone.Config{BaseURL: s.URL(), ClientID: ninjaClient, HealthField: "trstctlAgent",
		Scripts: map[rmm.Action]int64{rmm.ActionInstall: 31, rmm.ActionUpgrade: 32, rmm.ActionRemove: 33}},
		http.DefaultClient, ninjaone.Credentials{ClientSecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newInstance(t *testing.T) *rmmtest.NinjaOne {
	t.Helper()
	s := rmmtest.NewNinjaOne(ninjaClient, ninjaSecret)
	t.Cleanup(s.Close)
	for _, id := range []int64{31, 32, 33} {
		s.AddScript(id)
	}
	s.AddDevice(rmmtest.NinjaDevice{ID: 1001, OrgID: 11, SystemName: "ALPHA-DC01"})
	s.AddDevice(rmmtest.NinjaDevice{ID: 1002, OrgID: 11, SystemName: "ALPHA-WEB01", Offline: true})
	s.AddDevice(rmmtest.NinjaDevice{ID: 2001, OrgID: 22, SystemName: "BETA-APP01"})
	return s
}

// MSP-9 (connector): after a client-credentials sign-in, an organization
// lists only its own devices; a device reads with its organization; an
// install runs the install script with the server, identity and one-time
// token as parameters; upgrade and remove run their scripts; health lands in
// the configured custom field; a wrong secret is refused before anything
// runs and no error names it.
func TestNinjaOneDevicesActionsAndHealthMSP9(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, ninjaSecret)
	devices, err := c.ListDevices(ctx, "11")
	if err != nil || len(devices) != 2 || devices[0].ID != "1001" || devices[0].Name != "ALPHA-DC01" || !devices[0].Online || devices[1].Online {
		t.Fatalf("organization 11 devices = %+v %v", devices, err)
	}
	if d, found, err := c.Device(ctx, "2001"); err != nil || !found || d.OrgID != "22" {
		t.Fatalf("device 2001 = %+v %v %v", d, found, err)
	}
	if _, found, err := c.Device(ctx, "9999"); err != nil || found {
		t.Fatalf("an unknown device = %v %v", found, err)
	}
	token := []byte("one-time-token-value")
	if _, err := c.RunAction(ctx, "1001", rmm.ActionInstall, &rmm.InstallParams{Server: "agents.example:8443", ServerName: "agents.example",
		Identity: "rmm-ninja-1001", Token: token}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []rmm.Action{rmm.ActionUpgrade, rmm.ActionRemove} {
		if _, err := c.RunAction(ctx, "1001", action, nil); err != nil {
			t.Fatal(err)
		}
	}
	runs := s.Runs()
	if len(runs) != 3 || runs[0].ScriptID != 31 || runs[1].ScriptID != 32 || runs[2].ScriptID != 33 || runs[0].RunAs != "system" ||
		!strings.Contains(runs[0].Parameters, `-Token "one-time-token-value"`) || !strings.Contains(runs[0].Parameters, `-Identity "rmm-ninja-1001"`) ||
		runs[1].Parameters != "" {
		t.Fatalf("runs = %+v", runs)
	}
	if err := c.ReportHealth(ctx, "1001", "trstctl agent healthy"); err != nil {
		t.Fatal(err)
	}
	if f := s.Fields(1001); f["trstctlAgent"] != "trstctl agent healthy" {
		t.Fatalf("custom fields = %+v", f)
	}
	if _, err := c.RunAction(ctx, "1001", rmm.ActionInstall, &rmm.InstallParams{Server: "s"}); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an install without a token = %v", err)
	}
	_, err = newClient(t, s, "not-the-secret").ListDevices(ctx, "11")
	if !errors.Is(err, rmm.ErrBeforeWrite) || strings.Contains(err.Error(), "not-the-secret") {
		t.Fatalf("a wrong secret = %v", err)
	}
	if len(s.Runs()) != 3 {
		t.Fatal("a refused call ran a script")
	}
}
