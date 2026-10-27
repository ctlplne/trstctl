// SPDX-License-Identifier: BUSL-1.1

package tlsvalidity_test

import (
	"bytes"
	"encoding/csv"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/tlsvalidity"
)

const day = 24 * time.Hour

var reportNow = at("2026-10-26T12:00:00Z")

func enabled() tlsvalidity.Scheduler {
	return tlsvalidity.Scheduler{Enabled: true, RenewBefore: 30 * day}
}

// A178 done-when: a public TLS profile requesting 397 days is flagged for the
// 2026 and 2027 steps (and, at 47 days, the 2029 one).
func TestPublicTLSProfileRequesting397DaysIsFlagged(t *testing.T) {
	report := tlsvalidity.NewReport(reportNow, enabled(), nil, []tlsvalidity.ProfileFacts{
		{Name: "web-public", Version: 3, PublicTLS: true, ServerAuth: true, MaxValidity: 397 * day},
		{Name: "web-internal", Version: 1, ServerAuth: true, MaxValidity: 397 * day},
		{Name: "public-uncapped", Version: 1, PublicTLS: true, ServerAuth: true},
		{Name: "public-47", Version: 1, PublicTLS: true, ServerAuth: true, MaxValidity: tlsvalidity.Steps[3].MaxLifetime()},
		{Name: "public-exact-47", Version: 1, PublicTLS: true, ServerAuth: true, MaxValidity: 47 * day},
	}, false, 5000)
	byName := map[string]tlsvalidity.ProfileReadiness{}
	for _, p := range report.Profiles {
		byName[p.Name] = p
	}
	flagged := func(name string) []bool {
		var out []bool
		for _, step := range byName[name].Steps {
			out = append(out, step.Flagged)
		}
		return out
	}
	public := byName["web-public"]
	if public.RequestedDays != 398 || len(public.Steps) != 3 {
		t.Fatalf("web-public = %+v, want 398 requested days and three steps", public)
	}
	if public.Steps[0].Effective != "2026-03-15" || public.Steps[1].Effective != "2027-03-15" || public.Steps[2].Effective != "2029-03-15" {
		t.Fatalf("steps = %+v", public.Steps)
	}
	for _, step := range public.Steps {
		if !step.Flagged || step.Reason != tlsvalidity.ReasonRequestedValidityExceeds {
			t.Fatalf("397-day public TLS profile not flagged at %s: %+v", step.Effective, step)
		}
	}
	if got := flagged("web-internal"); !slices.Equal(got, []bool{false, false, false}) {
		t.Fatalf("a profile that does not say it is public TLS was flagged: %v", got)
	}
	for _, step := range byName["public-uncapped"].Steps {
		if !step.Flagged || step.Reason != tlsvalidity.ReasonNoValidityCeiling {
			t.Fatalf("an uncapped public TLS profile must be flagged: %+v", step)
		}
	}
	if got := flagged("public-47"); !slices.Equal(got, []bool{false, false, false}) {
		t.Fatalf("47 days less the inclusive second fits every step: %v", got)
	}
	if got := flagged("public-exact-47"); !slices.Equal(got, []bool{false, false, true}) {
		t.Fatalf("exactly 47 days is one second too long for the 2029 step: %v", got)
	}
	if report.Steps[0].FlaggedProfiles != 2 || report.Steps[2].FlaggedProfiles != 3 {
		t.Fatalf("flagged counts = %d/%d/%d", report.Steps[0].FlaggedProfiles, report.Steps[1].FlaggedProfiles, report.Steps[2].FlaggedProfiles)
	}
}

func cert(id string, scope tlsvalidity.Scope, automation tlsvalidity.Automation) tlsvalidity.CertificateFacts {
	return tlsvalidity.CertificateFacts{
		ID: id, Subject: "CN=" + id, Issuer: "CN=issuer",
		NotBefore: at("2026-10-01T00:00:00Z"), NotAfter: at("2026-10-01T00:00:00Z").Add(30*day - time.Second),
		Scope: scope, Automation: automation, RenewalLifetime: 30 * day,
	}
}

// A178 done-when: every certificate has a verdict under every step, and the
// verdict follows its automation, holds and deployment path.
func TestEveryCertificateHasAVerdictPerStep(t *testing.T) {
	verified := cert("scheduled-verified", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationScheduled)
	verified.Deployment = tlsvalidity.DeploymentVerified
	delivered := cert("scheduled-delivered", tlsvalidity.ScopePrivateTLS, tlsvalidity.AutomationScheduled)
	delivered.Deployment = tlsvalidity.DeploymentDelivered
	undeployed := cert("scheduled-undeployed", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationScheduled)
	undeployed.Deployment = tlsvalidity.DeploymentNone
	held := cert("scheduled-held", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationScheduled)
	held.Deployment = tlsvalidity.DeploymentVerified
	held.Holds = []string{tlsvalidity.ReasonRenewalPaused}
	held.ApprovalRequired = true
	long := cert("scheduled-150", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationScheduled)
	long.Deployment = tlsvalidity.DeploymentVerified
	long.RenewalLifetime = 150 * day
	certs := []tlsvalidity.CertificateFacts{
		verified, delivered, undeployed, held, long,
		cert("client", tlsvalidity.ScopePrivateTLS, tlsvalidity.AutomationClient),
		cert("not-tls", tlsvalidity.ScopeNotTLSServer, tlsvalidity.AutomationClient),
		cert("manual-public", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationNone),
		cert("manual-private", tlsvalidity.ScopePrivateTLS, tlsvalidity.AutomationNone),
	}
	report := tlsvalidity.NewReport(reportNow, enabled(), certs, nil, false, 5000)
	if len(report.Certificates) != len(certs) {
		t.Fatalf("report covers %d of %d certificates", len(report.Certificates), len(certs))
	}
	want := map[string][3]tlsvalidity.Verdict{
		"scheduled-verified":   {"renews", "renews", "renews"},
		"scheduled-delivered":  {"at_risk", "at_risk", "at_risk"},
		"scheduled-undeployed": {"at_risk", "at_risk", "at_risk"},
		"scheduled-held":       {"at_risk", "at_risk", "at_risk"},
		"scheduled-150":        {"renews", "at_risk", "at_risk"},
		"client":               {"at_risk", "at_risk", "at_risk"},
		"not-tls":              {"at_risk", "at_risk", "at_risk"},
		"manual-public":        {"manual", "manual", "manual"},
		"manual-private":       {"manual", "manual", "manual"},
	}
	for _, row := range report.Certificates {
		if len(row.Steps) != 3 {
			t.Fatalf("%s has %d step verdicts, want 3", row.CertificateID, len(row.Steps))
		}
		var got [3]tlsvalidity.Verdict
		for i, step := range row.Steps {
			got[i] = step.Verdict
			if step.Verdict != tlsvalidity.VerdictRenews && len(step.Reasons) == 0 {
				t.Fatalf("%s %s is %s without a reason", row.CertificateID, step.Effective, step.Verdict)
			}
		}
		if got != want[row.CertificateID] {
			t.Errorf("%s verdicts = %v, want %v", row.CertificateID, got, want[row.CertificateID])
		}
	}
	reasons := func(id string, step int) []string {
		for _, row := range report.Certificates {
			if row.CertificateID == id {
				return row.Steps[step].Reasons
			}
		}
		return nil
	}
	for id, reason := range map[string]string{
		"scheduled-delivered":  tlsvalidity.ReasonDeploymentUnverified,
		"scheduled-undeployed": tlsvalidity.ReasonNoAutomatedDeployment,
		"client":               tlsvalidity.ReasonClientRenewalUnobserved,
		"manual-public":        tlsvalidity.ReasonNoAutomatedRenewal,
	} {
		if !slices.Contains(reasons(id, 0), reason) {
			t.Errorf("%s reasons = %v, want %s", id, reasons(id, 0), reason)
		}
	}
	if got := reasons("scheduled-held", 0); !slices.Equal(got, []string{tlsvalidity.ReasonRenewalPaused, tlsvalidity.ReasonApprovalRequired}) {
		t.Errorf("held reasons = %v", got)
	}
	if got := reasons("scheduled-150", 1); !slices.Equal(got, []string{tlsvalidity.ReasonRenewalLifetimeExceedsMaximum}) {
		t.Errorf("a 150-day public renewal under the 100-day step: %v", got)
	}
	// Only the public TLS certificate nothing renews counts toward the hand
	// renewal load: 2, 4 and 8 renewals a year at 200, 100 and 47 days.
	for i, perYear := range []int{2, 4, 8} {
		summary := report.Steps[i]
		if summary.ManualRenewalsPerYear != perYear || summary.PublicTLSManual != 1 || summary.Manual != 2 {
			t.Errorf("step %s summary = %+v, want %d manual renewals a year", summary.Effective, summary, perYear)
		}
		if summary.Renews+summary.AtRisk+summary.Manual != len(certs) {
			t.Errorf("step %s counts %+v do not add up to %d", summary.Effective, summary, len(certs))
		}
	}
	if !report.Steps[0].InEffect || report.Steps[1].InEffect || report.Steps[2].InEffect {
		t.Fatalf("on 2026-10-26 only the 2026 step is in effect: %+v", report.Steps)
	}
	scheduled := report.Certificates[0]
	if scheduled.RenewalLifetimeDays != 30 || scheduled.RenewalLeadDays != 10 || scheduled.Deployment != tlsvalidity.DeploymentVerified || scheduled.IdentityID != "" {
		t.Fatalf("scheduled row = %+v", scheduled)
	}
}

func TestDisabledSchedulerMakesScheduledCertificatesManual(t *testing.T) {
	c := cert("scheduled", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationScheduled)
	c.Deployment = tlsvalidity.DeploymentVerified
	report := tlsvalidity.NewReport(reportNow, tlsvalidity.Scheduler{}, []tlsvalidity.CertificateFacts{c}, nil, false, 5000)
	for _, step := range report.Certificates[0].Steps {
		if step.Verdict != tlsvalidity.VerdictManual || !slices.Equal(step.Reasons, []string{tlsvalidity.ReasonSchedulerDisabled}) {
			t.Fatalf("step %+v", step)
		}
	}
}

func TestPublicCertificateLongerThanItsIssuanceMaximum(t *testing.T) {
	c := cert("long", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationNone)
	c.NotBefore = at("2026-04-01T00:00:00Z")
	c.NotAfter = c.NotBefore.Add(397 * day)
	private := c
	private.ID, private.Scope = "long-private", tlsvalidity.ScopePrivateTLS
	report := tlsvalidity.NewReport(reportNow, enabled(), []tlsvalidity.CertificateFacts{c, private}, nil, false, 5000)
	got := report.Certificates[0]
	if got.ValidityDays != 398 || got.MaxDaysAtIssuance != 200 || !got.ExceedsMaximumAtIssuance {
		t.Fatalf("public row = %+v", got)
	}
	if report.Certificates[1].ExceedsMaximumAtIssuance {
		t.Fatal("the maximum does not bind a private certificate")
	}
}

func TestRenewalLeadMatchesTheScheduler(t *testing.T) {
	for _, tc := range []struct {
		renewBefore, lifetime, lead time.Duration
	}{
		{30 * day, 30 * day, 10 * day}, // the lead covers the lifetime: ARI alone
		{7 * day, 30 * day, 10 * day},  // the ARI window opens first
		{20 * day, 30 * day, 20 * day}, // the configured lead opens first
		{30 * day, 200 * day, 66*day + 16*time.Hour},
		{0, 47 * day, 47 * day / 3},
	} {
		if got := tlsvalidity.RenewalLead(tc.renewBefore, tc.lifetime); got != tc.lead {
			t.Errorf("RenewalLead(%s, %s) = %s, want %s", tc.renewBefore, tc.lifetime, got, tc.lead)
		}
	}
}

func TestClassifyCertificate(t *testing.T) {
	for _, tc := range []struct {
		isCA     bool
		ekus     []string
		policies []string
		want     tlsvalidity.Scope
	}{
		{true, []string{"serverAuth"}, []string{"2.23.140.1.2.1"}, tlsvalidity.ScopeCACertificate},
		{false, []string{"clientAuth"}, []string{"2.23.140.1.2.1"}, tlsvalidity.ScopeNotTLSServer},
		{false, []string{"serverAuth", "clientAuth"}, []string{"2.23.140.1.2.2"}, tlsvalidity.ScopePublicTLS},
		{false, nil, []string{"1.3.6.1.4.1.99999.1", "2.23.140.1.1"}, tlsvalidity.ScopePublicTLS},
		{false, []string{"serverAuth"}, nil, tlsvalidity.ScopePrivateTLS},
		{false, []string{"any"}, []string{"1.3.6.1.4.1.99999.1"}, tlsvalidity.ScopePrivateTLS},
	} {
		if got := tlsvalidity.ClassifyCertificate(tc.isCA, tc.ekus, tc.policies); got != tc.want {
			t.Errorf("ClassifyCertificate(%v, %v, %v) = %s, want %s", tc.isCA, tc.ekus, tc.policies, got, tc.want)
		}
	}
}

// A178 done-when: the report exports, and the export names its BR version.
func TestCSVExportNamesItsRequirements(t *testing.T) {
	injected := cert("=HYPERLINK(\"x\")", tlsvalidity.ScopePublicTLS, tlsvalidity.AutomationNone)
	report := tlsvalidity.NewReport(reportNow, enabled(), []tlsvalidity.CertificateFacts{
		injected, cert("ok", tlsvalidity.ScopePrivateTLS, tlsvalidity.AutomationClient),
	}, []tlsvalidity.ProfileFacts{{Name: "web-public", Version: 2, PublicTLS: true, ServerAuth: true, MaxValidity: 397 * day}}, false, 5000)
	if got := tlsvalidity.Filename(report); got != "validity-readiness-br-2.3.1-2026-10-26.csv" {
		t.Fatalf("filename = %q", got)
	}
	raw, err := tlsvalidity.CSV(report)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(records[0], tlsvalidity.CSVHeader) {
		t.Fatalf("header = %v", records[0])
	}
	if len(records) != 1+2*3+1*3 {
		t.Fatalf("rows = %d, want one per certificate or profile and step", len(records))
	}
	for _, record := range records[1:] {
		if !strings.Contains(record[12], "Baseline Requirements 2.3.1 (2026-10-04) section 6.3.2") {
			t.Fatalf("row does not name its requirements: %v", record)
		}
	}
	if records[1][1] != `'=HYPERLINK("x")` || records[1][2] != `CN==HYPERLINK("x")` {
		t.Fatalf("formula cells were not neutralized: %v", records[1])
	}
	profileRow := records[len(records)-3]
	if profileRow[0] != "profile" || profileRow[10] != "flagged" || profileRow[11] != tlsvalidity.ReasonRequestedValidityExceeds || profileRow[7] != "2026-03-15" || profileRow[9] != "true" {
		t.Fatalf("profile row = %v", profileRow)
	}
}
