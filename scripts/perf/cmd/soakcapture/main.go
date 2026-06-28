// Command soakcapture drives the local eval perf stack long enough to emit a
// captured soak series that scripts/perf/soak.sh can analyze with --in.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

func main() {
	var (
		profile     = flag.String("profile", "captured-soak", "series profile name")
		out         = flag.String("out", "", "optional JSON series path; stdout when empty")
		samples     = flag.Int("samples", 12, "number of captured resource samples")
		stepSec     = flag.Int("step-seconds", 5, "seconds between captured samples")
		loadSamples = flag.Int("load-samples", 8, "hot-path load samples per captured resource sample")
		noSleep     = flag.Bool("no-sleep", false, "advance timestamps without sleeping; intended for tests only")
		printPretty = flag.Bool("pretty", true, "pretty-print JSON")
	)
	flag.Parse()

	series, err := perf.CaptureSoakSeries(perf.SoakCaptureOptions{
		Profile:     *profile,
		Samples:     *samples,
		Step:        time.Duration(*stepSec) * time.Second,
		LoadSamples: *loadSamples,
		Sleep:       !*noSleep,
	})
	if err != nil {
		fail("capture soak series: %v", err)
	}

	var data []byte
	if *printPretty {
		data, err = json.MarshalIndent(series, "", "  ")
	} else {
		data, err = json.Marshal(series)
	}
	if err != nil {
		fail("marshal series: %v", err)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail("create output dir: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fail("write %s: %v", *out, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
