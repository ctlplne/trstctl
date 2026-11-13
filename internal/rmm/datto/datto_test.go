// SPDX-License-Identifier: BUSL-1.1

package datto_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/datto"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
)

const (
	dattoKey    = "DATTO-API-KEY-TRSTCTL"
	dattoSecret = `datto-secret "with"\escapes&more` // #nosec G101 -- a test-only value with characters JSON and forms must escape (CWE-798)

	siteA     = "6f0b6f1e-5a4c-4a43-9a8f-0b1c2d3e4f50"
	siteB     = "7a1c7e2f-6b5d-4b54-8b9e-1c2d3e4f5061"
	deviceA1  = "a1a1a1a1-0000-4000-8000-000000000001"
	deviceA2  = "a2a2a2a2-0000-4000-8000-000000000002"
	deviceB1  = "b1b1b1b1-0000-4000-8000-000000000001"
	install   = "c0c0c0c0-0000-4000-8000-0000000000c1"
	upgrade   = "c0c0c0c0-0000-4000-8000-0000000000c2"
	uninstall = "c0c0c0c0-0000-4000-8000-0000000000c3"
)

func newInstance(t *testing.T) *rmmtest.Datto {
	t.Helper()
	s := rmmtest.NewDatto(dattoKey, dattoSecret)
	t.Cleanup(s.Close)
	for _, c := range []string{install, upgrade, uninstall} {
		s.AddComponent(c)
	}
	s.AddDevice(rmmtest.DattoDevice{UID: deviceA1, SiteUID: siteA, Hostname: "ALPHA-DC01", Online: true})
	s.AddDevice(rmmtest.DattoDevice{UID: deviceA2, SiteUID: siteA, Hostname: "ALPHA-WEB01"})
	s.AddDevice(rmmtest.DattoDevice{UID: deviceB1, SiteUID: siteB, Hostname: "BETA-APP01", Online: true})
	return s
}

func newClient(t *testing.T, s *rmmtest.Datto, secret string) *datto.Client {
	t.Helper()
	c, err := datto.New(datto.Config{BaseURL: s.URL(), HealthUDF: 12,
		Components: map[rmm.Action]string{rmm.ActionInstall: install, rmm.ActionUpgrade: upgrade, rmm.ActionRemove: uninstall}},
		http.DefaultClient, datto.Credentials{APIKey: []byte(dattoKey), APISecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-10 (connector): after a password-grant sign-in through the public
// client, a site lists only its own devices; a device reads with its site; an
// install runs the install component as a quick job with the server,
// identity and one-time token as variables; upgrade and remove run their
// components; health lands in the configured user-defined field; a wrong
// secret is refused before anything runs and no error names it.
func TestDattoDevicesActionsAndHealthMSP10(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, dattoSecret)
	devices, err := c.ListDevices(ctx, siteA)
	if err != nil || len(devices) != 2 || devices[0].ID != deviceA1 || devices[0].Name != "ALPHA-DC01" || !devices[0].Online || devices[1].Online {
		t.Fatalf("site A devices = %+v %v", devices, err)
	}
	for _, d := range devices {
		if d.OrgID != siteA {
			t.Fatalf("site A listed %+v", d)
		}
	}
	if d, found, err := c.Device(ctx, deviceB1); err != nil || !found || d.OrgID != siteB {
		t.Fatalf("device B1 = %+v %v %v", d, found, err)
	}
	if _, found, err := c.Device(ctx, "00000000-0000-4000-8000-00000000dead"); err != nil || found {
		t.Fatalf("an unknown device = %v %v", found, err)
	}
	token := []byte(`one-time "token"`)
	job, err := c.RunAction(ctx, deviceA1, rmm.ActionInstall, &rmm.InstallParams{Server: "agents.example.test:8443", ServerName: "agents.example.test",
		Identity: "rmm-datto-" + deviceA1, Token: token})
	if err != nil || job == "" {
		t.Fatalf("install = %q %v", job, err)
	}
	if _, err := c.RunAction(ctx, deviceA1, rmm.ActionUpgrade, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunAction(ctx, deviceA2, rmm.ActionRemove, nil); err != nil {
		t.Fatal(err)
	}
	jobs := s.Jobs()
	if len(jobs) != 3 || jobs[0].ComponentUID != install || jobs[0].DeviceUID != deviceA1 || jobs[0].Variables[datto.VarToken] != string(token) ||
		jobs[0].Variables[datto.VarServer] != "agents.example.test:8443" || jobs[0].Variables[datto.VarIdentity] != "rmm-datto-"+deviceA1 ||
		jobs[1].ComponentUID != upgrade || len(jobs[1].Variables) != 0 || jobs[2].ComponentUID != uninstall || jobs[2].DeviceUID != deviceA2 {
		t.Fatalf("jobs = %+v", jobs)
	}
	if _, err := c.RunAction(ctx, deviceA1, rmm.ActionInstall, nil); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("an install without a token = %v", err)
	}
	if err := c.ReportHealth(ctx, deviceA1, "trstctl agent healthy (version 1.4.2)"); err != nil {
		t.Fatal(err)
	}
	if f := s.UDFs(deviceA1); f["udf12"] != "trstctl agent healthy (version 1.4.2)" {
		t.Fatalf("UDFs = %+v", f)
	}
	if _, err := c.ListDevices(ctx, "site-a"); !errors.Is(err, rmm.ErrBeforeWrite) {
		t.Fatalf("a site that is not a UID = %v", err)
	}

	wrong := newClient(t, s, "not-the-secret")
	_, _, refusedBefore := s.Counts()
	if _, err := wrong.RunAction(ctx, deviceA1, rmm.ActionUpgrade, nil); !errors.Is(err, rmm.ErrBeforeWrite) || strings.Contains(err.Error(), dattoSecret) {
		t.Fatalf("a wrong secret = %v", err)
	}
	if _, _, refused := s.Counts(); refused != refusedBefore+1 || len(s.Jobs()) != 3 {
		t.Fatalf("a wrong secret ran something: refused %d, jobs %d", refused-refusedBefore, len(s.Jobs()))
	}
}
