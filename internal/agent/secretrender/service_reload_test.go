// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A238-L3 Done-when (portable part, the control stubbed): a template can reload
// by a Windows service control. After each write the renderer sends the named
// service PARAMCHANGE (6), or the code from 128 to 255 the template names; a
// refused control is the write's reload error. A template naming a service is
// refused off Windows, and anywhere when it names two ways to reload, a code
// outside 128 to 255, or a name with a slash.
func TestRendererReloadsByAWindowsServiceControlA238L3(t *testing.T) {
	var sent []string
	var refuse error
	wasSupported, wasControl := serviceReloads, controlService
	serviceReloads = true
	controlService = func(name string, code uint32) error {
		sent = append(sent, fmt.Sprintf("%s %d", name, code))
		return refuse
	}
	t.Cleanup(func() { serviceReloads, controlService = wasSupported, wasControl })
	dir := t.TempDir()
	src := &fakeSource{values: map[string]string{"web/name": "one"}, versions: map[string]int{"web/name": 1}}
	template := func(name, reload string) Template {
		t.Helper()
		var tmpl Template
		raw := `{"name":` + strconv.Quote(name) + `,"destination":` + strconv.Quote(filepath.Join(dir, name+".conf")) +
			`,"template":"name={{ secret \"web/name\" }}\n","reload":` + reload + `}`
		if err := json.Unmarshal([]byte(raw), &tmpl); err != nil {
			t.Fatal(err)
		}
		return tmpl
	}
	renderer := func(tmpl Template) (*Renderer, error) {
		return New(Config{Server: "unused", TokenFile: "unused", Consumer: "web-1/app",
			StateDir: filepath.Join(dir, "state-"+tmpl.Name), Templates: []Template{tmpl}}, src, nil, nil)
	}

	r, err := renderer(template("web", `{"service":"app-svc"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.reconcile(t.Context(), r.cfg.Templates[0]); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sent, ","); got != "app-svc 6" {
		t.Fatalf("after the write the service was sent %q, want PARAMCHANGE (app-svc 6)", got)
	}
	// A refused control is the reload's error.
	refuse = errors.New("the service did not accept the control")
	src.set("web/name", "two")
	if err := r.reconcile(t.Context(), r.cfg.Templates[0]); err == nil || !strings.Contains(err.Error(), "did not accept") {
		t.Fatalf("a refused control: %v", err)
	}
	refuse, sent = nil, nil

	own, err := renderer(template("own", `{"service":"app-svc","service_control":200}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := own.reconcile(t.Context(), own.cfg.Templates[0]); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sent, ","); got != "app-svc 200" {
		t.Fatalf("the service was sent %q, want its own code (app-svc 200)", got)
	}

	for reload, want := range map[string]string{
		`{"service":"app-svc","command":["nginx","-s","reload"]}`: "one of a command, a signal or a service",
		`{"service":"app-svc","service_control":100}`:             "service_control",
		`{"service_control":200}`:                                 "service_control",
		`{"service":"apps/web"}`:                                  "no slashes",
	} {
		if _, err := renderer(template("bad", reload)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("reload %s: %v, want an error naming %q", reload, err, want)
		}
	}
	serviceReloads = false
	if _, err := renderer(template("elsewhere", `{"service":"app-svc"}`)); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("a service reload off Windows: %v", err)
	}
}
