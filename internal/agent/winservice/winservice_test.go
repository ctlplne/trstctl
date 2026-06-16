package winservice_test

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/winservice"
)

const exe = `C:\Program Files\trstctl\trstctl-agent.exe`

func mustSpec(t *testing.T) winservice.Spec {
	t.Helper()
	s, err := winservice.BuildSpec(winservice.Config{
		ExePath:   exe,
		Arguments: []string{"--service=run", "--enroll-url", "https://cp.example/enroll", "--name", "win-1"},
	})
	if err != nil {
		t.Fatalf("BuildSpec: %v", err)
	}
	return s
}

// TestBuildSpecDefaultsToAutomaticService is part of the "registers as a
// service" acceptance: the service is named trstctl-agent, starts
// automatically, has a display name and description, and runs the configured
// executable with its arguments.
func TestBuildSpecDefaultsToAutomaticService(t *testing.T) {
	s := mustSpec(t)
	if s.Name != "trstctl-agent" {
		t.Errorf("service name = %q, want trstctl-agent", s.Name)
	}
	if !s.AutomaticStart {
		t.Error("service does not start automatically, want auto-start")
	}
	if s.DisplayName == "" || s.Description == "" {
		t.Errorf("display name / description empty: %q / %q", s.DisplayName, s.Description)
	}
	if s.ExePath != exe {
		t.Errorf("exe path = %q, want %q", s.ExePath, exe)
	}
	if len(s.Arguments) == 0 || s.Arguments[0] != "--service=run" {
		t.Errorf("arguments = %v, want to start with --service=run", s.Arguments)
	}
}

// TestBuildSpecRejectsMissingExe: a spec without an executable path is invalid.
func TestBuildSpecRejectsMissingExe(t *testing.T) {
	if _, err := winservice.BuildSpec(winservice.Config{}); err == nil {
		t.Error("BuildSpec with no ExePath succeeded, want error")
	}
}

// wellFormed reports whether s is well-formed XML (parses to EOF).
func wellFormed(s string) error {
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// TestWiXSourceRegistersServiceAndBinary is the "installs via MSI" +
// "registers as a service" acceptance at the packaging layer: the generated WiX
// source is well-formed and declares the service (auto-start), a service
// control to start/stop it, the agent binary as a component, a product version,
// and a stable upgrade code so upgrades replace rather than duplicate.
func TestWiXSourceRegistersServiceAndBinary(t *testing.T) {
	src, err := winservice.WiXSource(mustSpec(t), winservice.WiXOptions{Version: "1.2.3"})
	if err != nil {
		t.Fatalf("WiXSource: %v", err)
	}
	if err := wellFormed(src); err != nil {
		t.Fatalf("WiX source is not well-formed XML: %v", err)
	}
	for _, want := range []string{
		`<ServiceInstall`,
		`Name="trstctl-agent"`,
		`Start="auto"`,
		`<ServiceControl`,
		`trstctl-agent.exe`,
		`Version="1.2.3"`,
		`UpgradeCode="`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("WiX source missing %q", want)
		}
	}
}

// TestWiXSourceUpgradeCodeIsStable: the upgrade code does not change between
// builds (so the MSI upgrades in place); two renders agree.
func TestWiXSourceUpgradeCodeIsStable(t *testing.T) {
	a, err := winservice.WiXSource(mustSpec(t), winservice.WiXOptions{Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := winservice.WiXSource(mustSpec(t), winservice.WiXOptions{Version: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	extract := func(s string) string {
		i := strings.Index(s, `UpgradeCode="`)
		if i < 0 {
			return ""
		}
		s = s[i+len(`UpgradeCode="`):]
		return s[:strings.IndexByte(s, '"')]
	}
	if ua, ub := extract(a), extract(b); ua == "" || ua != ub {
		t.Errorf("upgrade code not stable across versions: %q vs %q", ua, ub)
	}
}
