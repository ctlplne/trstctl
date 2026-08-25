// SPDX-License-Identifier: MPL-2.0

// featureparityreport renders the canonical capability catalog as one
// standalone, sanitized HTML control panel. It does not maintain a second
// feature list; every row and stage comes from internal/featureparity.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/featureparity"
)

func main() {
	var output string
	var title string
	var consoleBase string
	var generatedAt string
	var candidateSHA string
	flag.StringVar(&output, "out", "", "output HTML file (required)")
	flag.StringVar(&title, "title", "trstctl frontend parity control panel", "report title")
	flag.StringVar(&consoleBase, "console-base", "", "optional served console base URL for route links")
	flag.StringVar(&generatedAt, "generated-at", "", "exact RFC3339 evidence timestamp (defaults to now)")
	flag.StringVar(&candidateSHA, "candidate", "", "exact 40-character lowercase candidate SHA (required)")
	flag.Parse()

	if output == "" {
		fatalf("--out is required")
	}
	if candidateSHA == "" {
		fatalf("--candidate is required")
	}
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, generatedAt); err != nil {
		fatalf("--generated-at must be RFC3339: %v", err)
	}
	catalog, err := featureparity.Load()
	if err != nil {
		fatalf("load canonical catalog: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
		fatalf("create report directory: %v", err)
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- explicit operator-selected local report output
	if err != nil {
		fatalf("open report output: %v", err)
	}
	renderErr := featureparity.RenderControlPanel(file, catalog, featureparity.ReportOptions{
		Title: title, ConsoleBase: consoleBase, GeneratedAt: generatedAt, CandidateSHA: candidateSHA,
	})
	closeErr := file.Close()
	if renderErr != nil {
		fatalf("render report: %v", renderErr)
	}
	if closeErr != nil {
		fatalf("close report: %v", closeErr)
	}
	fmt.Printf("wrote %s\n", output)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "featureparityreport: "+format+"\n", args...)
	os.Exit(1)
}
