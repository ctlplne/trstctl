// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli/evaluate"
	"trstctl.com/trstctl/internal/config"
)

// A249: `trstctl evaluate --journeys secrets,ssh` passes against a served
// control plane — its secret store, its SSH CA and its KRL — with the shipped
// trstctl run injecting the rotated secret into a real child process; and a
// forced failure in each journey is reported as a failure while the other
// journey still passes.
func TestServedEvaluateSecretsAndSSHJourneysA249(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the run step's child is a POSIX shell")
	}
	// The SSH CA as the eval profile serves it: one direct user principal.
	h := newServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SSHUserPrincipals: []string{config.DefaultEvalSSHUserPrincipal}}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A249 evaluation tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "certs:issue", "certs:write", "certs:read")
	run := func(force string) evaluate.Pack {
		t.Helper()
		pack, err := evaluate.Evaluate(t.Context(), evaluate.Options{
			Server: h.ts.URL, Token: token, HTTPClient: h.ts.Client(),
			Journeys: []string{evaluate.JourneySecrets, evaluate.JourneySSH}, ForceFailure: force,
			// No RunCLI: the run step is the shipped one — this binary's trstctl run,
			// in-process, starting a real /bin/sh child.
			Timeout: time.Minute, PollInterval: 100 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pack
	}
	statuses := func(steps []evaluate.Step) string {
		out := make([]string, 0, len(steps))
		for _, s := range steps {
			out = append(out, s.Name+"="+string(s.Status))
		}
		return strings.Join(out, " ")
	}
	details := func(steps []evaluate.Step) string {
		out := make([]string, 0, len(steps))
		for _, s := range steps {
			out = append(out, s.Name+": "+s.Detail)
		}
		return strings.Join(out, "\n")
	}

	pack := run("")
	for _, journey := range pack.Journeys {
		if journey.Verdict != evaluate.StatusPass {
			t.Fatalf("%s journey against the served control plane: %s\n%s", journey.Name, statuses(journey.Steps), details(journey.Steps))
		}
	}
	if pack.Format != evaluate.PackFormatV2 || pack.Verdict != evaluate.StatusPass || len(pack.Journeys) != 2 {
		t.Fatalf("pack %s verdict %s with %d journeys", pack.Format, pack.Verdict, len(pack.Journeys))
	}

	for _, tc := range []struct{ journey, steps string }{
		{evaluate.JourneySecrets, "secret_create=pass secret_read=fail secret_rotate=skipped secret_run=skipped secret_delete=skipped"},
		{evaluate.JourneySSH, "ssh_issue=pass ssh_verify=pass ssh_revoke=pass ssh_krl=fail"},
	} {
		pack := run(tc.journey)
		if pack.Verdict != evaluate.StatusFail {
			t.Fatalf("a forced %s failure passed the pack", tc.journey)
		}
		for _, journey := range pack.Journeys {
			got := statuses(journey.Steps)
			switch {
			case journey.Name == tc.journey && (got != tc.steps || !journey.ForcedFailure):
				t.Fatalf("forced %s: %s\n%s", tc.journey, got, details(journey.Steps))
			case journey.Name != tc.journey && journey.Verdict != evaluate.StatusPass:
				t.Fatalf("forcing %s failed the %s journey: %s\n%s", tc.journey, journey.Name, got, details(journey.Steps))
			}
		}
	}
}
