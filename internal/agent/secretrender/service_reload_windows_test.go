// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"trstctl.com/trstctl/internal/crypto"
)

var (
	reloadFixtureName   = flag.String("a238l3-service", "", "owned SCM reload fixture name")
	reloadFixtureMarker = flag.String("a238l3-marker", "", "file the reload fixture appends each control to")
)

// reloadFixtureService takes PARAMCHANGE and user-defined controls and appends
// each to the marker file.
type reloadFixtureService struct{}

func (reloadFixtureService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange}
	note := func(line string) {
		f, err := os.OpenFile(*reloadFixtureMarker, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the owning test's marker file, passed by that test (CWE-22)
		if err == nil {
			_, _ = f.WriteString(line + "\n")
			_ = f.Close()
		}
	}
	for request := range requests {
		switch {
		case request.Cmd == svc.Interrogate:
			status <- request.CurrentStatus
		case request.Cmd == svc.Stop || request.Cmd == svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case request.Cmd == svc.ParamChange:
			note("paramchange")
			status <- request.CurrentStatus
		case request.Cmd >= 128 && request.Cmd <= 255:
			note(fmt.Sprintf("control %d", request.Cmd))
			status <- request.CurrentStatus
		}
	}
	return false, 0
}

// TestWindowsReloadServiceFixtureA238L3 is the service process: the SCM starts
// this test binary with the fixture's flags.
func TestWindowsReloadServiceFixtureA238L3(t *testing.T) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		t.Skip("SCM fixture process only")
	}
	if *reloadFixtureName == "" || !filepath.IsAbs(*reloadFixtureMarker) {
		t.Fatal("invalid owned reload fixture")
	}
	if err := svc.Run(*reloadFixtureName, reloadFixtureService{}); err != nil {
		t.Fatal("owned reload fixture dispatcher failed")
	}
}

// A238-L3 Done-when (Windows): a template that reloads by a service has the
// SCM send the running service PARAMCHANGE after each write, or the code from
// 128 to 255 it names; a stopped service refuses the control and the write's
// reload reports it. It creates and deletes its own service, so it runs only
// where TRSTCTL_A238L3_WINDOWS_SERVICE=1 (the CI windows-latest job).
func TestWindowsReloadControlsAServiceA238L3(t *testing.T) {
	if os.Getenv("TRSTCTL_A238L3_WINDOWS_SERVICE") != "1" {
		t.Skip("creates an owned Windows service: set TRSTCTL_A238L3_WINDOWS_SERVICE=1 on a disposable host")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := crypto.RandomBytes(4)
	if err != nil {
		t.Fatal(err)
	}
	name := "trstctl-a238l3-" + hex.EncodeToString(suffix)
	dir := t.TempDir()
	marker := filepath.Join(dir, "controls.log")
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, DisplayName: name},
		"-test.run=^TestWindowsReloadServiceFixtureA238L3$", "-a238l3-service="+name, "-a238l3-marker="+marker)
	if err != nil {
		t.Fatal(err)
	}
	stop := func() {
		_, _ = s.Control(svc.Stop)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				return
			}
		}
	}
	t.Cleanup(func() {
		stop()
		if err := s.Delete(); err != nil {
			t.Errorf("delete the owned service %s: %v", name, err)
		}
		_ = s.Close()
	})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the owned reload fixture did not start")
		}
	}
	waitFor := func(line string) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if raw, _ := os.ReadFile(marker); strings.Contains(string(raw), line+"\n") { // #nosec G304 -- the test's own temp file (CWE-22)
				return
			}
		}
		raw, _ := os.ReadFile(marker) // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("the service never saw %q; it saw %q", line, raw)
	}
	src := &fakeSource{values: map[string]string{"web/name": "one"}, versions: map[string]int{"web/name": 1}}
	r, err := New(Config{Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"),
		Templates: []Template{{Name: "web", Destination: filepath.Join(dir, "web.conf"), Text: "name={{ secret \"web/name\" }}\n",
			Reload: Hook{Service: name}}}}, src, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.reconcile(t.Context(), r.cfg.Templates[0]); err != nil {
		t.Fatal(err)
	}
	waitFor("paramchange")
	r.cfg.Templates[0].Reload.ServiceControl = 200
	src.set("web/name", "two")
	if err := r.reconcile(t.Context(), r.cfg.Templates[0]); err != nil {
		t.Fatal(err)
	}
	waitFor("control 200")
	stop()
	src.set("web/name", "three")
	if err := r.reconcile(t.Context(), r.cfg.Templates[0]); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("a stopped service's reload: %v", err)
	}
	t.Log("A238L3_WINDOWS_SERVICE_RELOAD_OK")
}
