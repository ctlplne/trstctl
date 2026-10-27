// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/compliance"
)

// compliance report-runs verify re-checks a saved scheduled report run on this
// machine against the report signing key the operator pinned separately.
// Nothing is sent anywhere.

const customerAssuranceReportType = "customer_assurance"

func complianceReportRunVerifyUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl compliance report-runs verify --report <file> --public-key <file> [--html <file>]")
	_, _ = fmt.Fprintln(w, "\nVerifies a file saved from 'compliance report-runs download' offline: the signature over the run's manifest")
	_, _ = fmt.Fprintln(w, "with the key in --public-key (the PEM or DER key from 'compliance report-signing-key', pinned separately; the")
	_, _ = fmt.Fprintln(w, "file's own public_key_der is never trusted), and that the manifest binds a complete run. For a customer")
	_, _ = fmt.Fprintln(w, "assurance report it also checks the HTML rendering against its digest; --html then writes that rendering")
	_, _ = fmt.Fprintln(w, "to a file. Nothing is sent anywhere.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl compliance report-runs verify --report signed-report.json --public-key report-signing-key.pem --html report.html")
}

func runComplianceReportRunVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compliance report-runs verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reportFile := fs.String("report", "", "a file saved from 'compliance report-runs download'")
	keyFile := fs.String("public-key", "", "the report signing key you pinned separately (PEM or DER)")
	htmlFile := fs.String("html", "", "write a verified customer assurance report's HTML rendering to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *reportFile == "" || *keyFile == "" {
		_, _ = fmt.Fprintln(stderr, "error: --report and --public-key are required")
		return 2
	}
	artifact, err := os.ReadFile(*reportFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: read report: %v\n", err)
		return 1
	}
	rawKey, err := os.ReadFile(*keyFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: read public key: %v\n", err)
		return 1
	}
	key, err := compliance.ParsePublicKey(rawKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	verified, err := compliance.VerifyScheduledReport(artifact, key)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if verified.ReportType != customerAssuranceReportType && *htmlFile != "" {
		_, _ = fmt.Fprintf(stderr, "error: --html applies only to a customer assurance report; this run is %s\n", verified.ReportType)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "verified: %s report run %s for tenant %s\n", verified.ReportType, verified.RunID, verified.TenantID)
	_, _ = fmt.Fprintf(stdout, "  schedule %s, due %s, generated %s\n", verified.ScheduleID,
		verified.DueAt.UTC().Format("2006-01-02T15:04:05Z"), verified.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(stdout, "  signed by the pinned key sha256:%s\n", verified.KeySHA256)
	if verified.ReportType != customerAssuranceReportType {
		return 0
	}
	report, err := assurance.CheckCustomerReport(verified.Payload)
	if err != nil || report.TenantID != verified.TenantID {
		if err == nil {
			err = fmt.Errorf("the report names tenant %s, the signed run %s", report.TenantID, verified.TenantID)
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "  customer assurance report for %s, %s to %s, in the %s brand\n", report.TenantName,
		report.PeriodFrom.Format("2006-01-02"), report.PeriodThrough.Format("2006-01-02"), report.Brand.ProductName)
	for _, line := range report.Summary {
		_, _ = fmt.Fprintf(stdout, "  - %s\n", line)
	}
	if *htmlFile != "" {
		if err := os.WriteFile(*htmlFile, []byte(report.HTML), 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write HTML: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "  HTML rendering written to %s (sha256:%s)\n", *htmlFile, report.HTMLSHA256)
	}
	return 0
}
