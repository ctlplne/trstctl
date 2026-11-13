// SPDX-License-Identifier: BUSL-1.1

package ncentral_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/ncentral"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

const ncentralJWT = `eyJ.ncentral-user-jwt."with"\escapes` // #nosec G101 -- a test-only value with characters JSON must escape (CWE-798)

func newInstance(t *testing.T) *rmmtest.NCentral {
	t.Helper()
	s := rmmtest.NewNCentral(ncentralJWT)
	t.Cleanup(s.Close)
	for _, id := range []int64{701, 702, 703} {
		s.AddScript(id)
	}
	s.AddProperty(88)
	s.AddDevice(rmmtest.NCentralDevice{ID: 3001, CustomerID: 101, Name: "ALPHA-DC01"})
	s.AddDevice(rmmtest.NCentralDevice{ID: 3002, CustomerID: 101, Name: "ALPHA-WEB01"})
	s.AddDevice(rmmtest.NCentralDevice{ID: 4001, CustomerID: 202, Name: "BETA-APP01"})
	return s
}

func newClient(t *testing.T, s *rmmtest.NCentral, jwt string) *ncentral.Client {
	t.Helper()
	c, err := ncentral.New(ncentral.Config{BaseURL: s.URL(), HealthPropertyID: 88,
		Scripts: map[rmm.Action]int64{rmm.ActionInstall: 701, rmm.ActionUpgrade: 702, rmm.ActionRemove: 703}},
		http.DefaultClient, ncentral.Credentials{UserJWT: []byte(jwt)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-12 (connector): after authenticating with the API user's JWT, a
// customer lists only its own devices; a device reads with its customer; an
// install runs the install script as a direct task under the device's own
// customer with the server, identity and one-time token as parameters, each
// task uniquely named; upgrade and remove run their scripts; health lands in
// the configured custom property; a wrong JWT is refused before anything runs
// and no error names it.
func TestNCentralDevicesActionsAndHealthMSP12(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, ncentralJWT)
	devices, err := c.ListDevices(ctx, "101")
	if err != nil || len(devices) != 2 || devices[0].ID != "3001" || devices[0].Name != "ALPHA-DC01" || devices[0].OrgID != "101" {
		t.Fatalf("customer 101 devices = %+v %v", devices, err)
	}
	if d, found, err := c.Device(ctx, "4001"); err != nil || !found || d.OrgID != "202" {
		t.Fatalf("device 4001 = %+v %v %v", d, found, err)
	}
	if _, found, err := c.Device(ctx, "9999"); err != nil || found {
		t.Fatalf("an unknown device = %v %v", found, err)
	}
	token := []byte(`one-time "token"`)
	if _, err := c.RunAction(ctx, "3002", rmm.ActionInstall, &rmm.InstallParams{Server: "agents.example.test:8443", ServerName: "agents.example.test",
		Identity: "rmm-ncentral-3002", Token: token}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []rmm.Action{rmm.ActionUpgrade, rmm.ActionUpgrade, rmm.ActionRemove} {
		if _, err := c.RunAction(ctx, "3001", action, nil); err != nil {
			t.Fatalf("%s = %v", action, err)
		}
	}
	tasks := s.Tasks()
	if len(tasks) != 4 || tasks[0].ItemID != 701 || tasks[0].DeviceID != 3002 || tasks[0].CustomerID != 101 || tasks[0].Credential != "LocalSystem" ||
		tasks[0].Params[ncentral.ParamToken] != string(token) || tasks[0].Params[ncentral.ParamIdentity] != "rmm-ncentral-3002" ||
		tasks[0].Params[ncentral.ParamServer] != "agents.example.test:8443" || tasks[1].ItemID != 702 || len(tasks[1].Params) != 0 || tasks[3].ItemID != 703 {
		t.Fatalf("tasks = %+v", tasks)
	}
	if _, err := c.RunAction(ctx, "3001", rmm.ActionInstall, nil); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an install without a token = %v", err)
	}
	if err := c.ReportHealth(ctx, "3001", "trstctl agent healthy (version 1.4.2)"); err != nil {
		t.Fatal(err)
	}
	if got := s.Property(3001, 88); got != "trstctl agent healthy (version 1.4.2)" {
		t.Fatalf("property = %q", got)
	}
	if _, err := c.ListDevices(ctx, "customer-a"); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("a customer that is not a number = %v", err)
	}

	wrong := newClient(t, s, "not-the-jwt")
	if _, err := wrong.RunAction(ctx, "3001", rmm.ActionUpgrade, nil); !errors.Is(err, rmm.ErrBeforeWrite) || strings.Contains(err.Error(), ncentralJWT) {
		t.Fatalf("a wrong JWT = %v", err)
	}
	if len(s.Tasks()) != 4 {
		t.Fatalf("a wrong JWT ran something: %d tasks", len(s.Tasks()))
	}
}
