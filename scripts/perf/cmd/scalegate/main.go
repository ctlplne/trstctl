// SPDX-License-Identifier: BUSL-1.1

// Command scalegate runs the enterprise-scale harness (A266) once and writes
// its receipt: scripts/perf/run-scale.sh is the rerun script.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

func main() {
	var (
		inventory = flag.Int("inventory", 10000, "certificates imported into inventory through the switching kit")
		renewals  = flag.Int("renewals", 200, "managed identities issued, deployed and renewed in one storm")
		clients   = flag.Int("clients", 8, "concurrent API clients")
		chunk     = flag.Int("chunk", 25000, "rows per switching import (at most 50000)")
		seed      = flag.Uint64("seed", 266, "seeds the generated inventory, so a rerun imports the same rows")
		lifetime  = flag.Duration("fleet-lifetime", 0, "the fleet's full signed certificate lifetime; the run waits about two thirds of it, less the CA's 5m backdate, before the storm, and the storm gets as long again (default: a storm budget of 200 ms a renewal, at least 3m)")
		timeout   = flag.Duration("timeout", 6*time.Hour, "how long the run may take")
		out       = flag.String("out", "", "JSON receipt path; stdout when empty")
	)
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	report, err := perf.RunScale(ctx, perf.ScaleConfig{Inventory: *inventory, Renewals: *renewals, Clients: *clients, Chunk: *chunk, Seed: *seed,
		FleetLifetimeSeconds: int(*lifetime / time.Second)})
	if err != nil {
		fail("scale run: %v", err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail("marshal receipt: %v", err)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil { // #nosec G301 -- developer tool writing a run receipt; the mode is intentional (CWE-276)
			fail("create output dir: %v", err)
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil { // #nosec G306 -- developer tool writing a run receipt; the mode is intentional (CWE-276)
			fail("write %s: %v", *out, err)
		}
	}
	fmt.Fprintln(os.Stderr, summary(report))
	if !report.OK {
		fail("scale run found %d correctness gaps: %s", len(report.Failures), strings.Join(report.Failures, "; "))
	}
}

// summary is the receipt in a few lines.
func summary(r perf.ScaleReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scale run %s on %s/%s (%d CPUs): inventory %d, renewals %d, clients %d, fleet lifetime %s\n", r.Schema, r.Host.OS, r.Host.Arch,
		r.Host.CPUs, r.Config.Inventory, r.Config.Renewals, r.Config.Clients, time.Duration(r.Config.FleetLifetimeSeconds)*time.Second)
	for _, p := range r.Phases {
		fmt.Fprintf(&b, "  %-18s %8d items in %8.1f s (%8.1f/s)", p.Name, p.Items, p.Seconds, p.PerSecond)
		if p.Latency != nil {
			fmt.Fprintf(&b, "  p50 %.1f ms  p95 %.1f ms  p99 %.1f ms", p.Latency.P50, p.Latency.P95, p.Latency.P99)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "  inventory: %d certificates, database %.1f MiB\n", r.Inventory.Certificates, float64(r.Inventory.DatabaseBytes)/(1<<20))
	fmt.Fprintf(&b, "  storm: %d due, %d renewed and %d delivered in %.1f s (%.1f/s), peak outbox %d, reads p95 %.1f ms over %d\n", r.Storm.Due,
		r.Storm.Renewed, r.Storm.Delivered, r.Storm.DrainSeconds, r.Storm.RenewalsPerSecond, r.Storm.MaxOutboxPending, r.Storm.Reads.P95, r.Storm.Reads.Count)
	fmt.Fprintf(&b, "  ok: %t", r.OK)
	return b.String()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "scalegate: "+format+"\n", args...)
	os.Exit(1)
}
