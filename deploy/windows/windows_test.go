// SPDX-License-Identifier: BUSL-1.1

package windows_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentBootstrapMSIRequiresConfiguredFirstBootProperties(t *testing.T) {
	body, err := os.ReadFile("trstctl-agent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	wxs := string(body)
	for _, want := range []string{
		`Property Id="ENROLLURL"`,
		`Property Id="SERVER"`,
		`Property Id="SERVERNAME"`,
		`Property Id="BOOTSTRAPTOKENFILE"`,
		`ENROLLURL is required`,
		`SERVER is required`,
		`SERVERNAME is required`,
		`--enroll-url [ENROLLURL]`,
		`--bootstrap-token-file [BOOTSTRAPTOKENFILE]`,
		`--server [SERVER]`,
		`--server-name [SERVERNAME]`,
		`FailureActionsWhen="failedToStopOrReturnedError"`,
		`<ServiceConfigFailureActions`,
		`<Failure Action="restartService" Delay="30000"`,
		`<Failure Action="restartService" Delay="60000"`,
		`<Failure Action="restartService" Delay="300000"`,
	} {
		if !strings.Contains(wxs, want) {
			t.Errorf("trstctl-agent.wxs missing %q", want)
		}
	}
	for _, bad := range []string{
		"https://control-plane.example:8443/enroll",
		"--bootstrap-token ",
	} {
		if strings.Contains(wxs, bad) {
			t.Errorf("trstctl-agent.wxs still contains unsafe/non-runnable marker %q", bad)
		}
	}
}

func TestAgentBootstrapWindowsDocsUseTokenFile(t *testing.T) {
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	for _, want := range []string{
		"trstctl-cli agents enroll-token",
		"BOOTSTRAPTOKENFILE=C:\\ProgramData\\trstctl\\bootstrap-token.txt",
		"--bootstrap-token-file C:\\ProgramData\\trstctl\\bootstrap-token.txt",
		"--server-name cp",
		"single-use",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("deploy/windows/README.md missing %q", want)
		}
	}
	if strings.Contains(doc, "--enroll-url https://cp:8443/enroll") {
		t.Error("deploy/windows/README.md passes /enroll even though trstctl-agent appends /enroll/bootstrap itself")
	}
}
