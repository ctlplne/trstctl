// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func cycleVerdicts(cycles []CycleResult) string {
	out := make([]string, 0, len(cycles))
	for _, c := range cycles {
		out = append(out, string(c.Verdict))
	}
	return strings.Join(out, " ")
}

// A249: --cycles repeats the journeys unattended. A cycle an outage cuts
// short is interrupted, and the run passes only when the next cycle passes
// after /readyz answers again; any other failure, an outage on the last
// cycle, or one that does not recover fails the run.
func TestUnattendedCyclesRecoverA249(t *testing.T) {
	run := func(t *testing.T, cycles int, bend func(lab *labServer, opts *Options)) Pack {
		t.Helper()
		lab, srv := newLabServer(t)
		opts := labOptions(srv, lab, JourneySecrets, JourneySSH)
		opts.Cycles, opts.RecoveryTimeout = cycles, 5*time.Second
		if bend != nil {
			bend(lab, &opts)
		}
		pack, err := Evaluate(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		return pack
	}
	// The control plane goes away as cycle n starts and is back shortly.
	outageAt := func(n int, back time.Duration) func(*labServer, *Options) {
		return func(lab *labServer, opts *Options) {
			opts.CycleStarted = func(cycle int) {
				if cycle == n {
					lab.mu.Lock()
					lab.down = true
					lab.mu.Unlock()
					time.AfterFunc(back, func() {
						lab.mu.Lock()
						lab.down = false
						lab.mu.Unlock()
					})
				}
			}
		}
	}

	t.Run("every cycle passes", func(t *testing.T) {
		pack := run(t, 3, nil)
		if pack.Format != PackFormatV3 || pack.Verdict != StatusPass || cycleVerdicts(pack.Cycles) != "pass pass pass" ||
			pack.Summary.Passed != 27 || len(pack.Journeys) != 2 {
			t.Fatalf("pack %s %s cycles %q summary %+v", pack.Format, pack.Verdict, cycleVerdicts(pack.Cycles), pack.Summary)
		}
		// A v3 pack signs and verifies offline like the others, cycles and all.
		key, err := jose.GenerateRSASigningKey("audit-export")
		if err != nil {
			t.Fatal(err)
		}
		if err := Sign(&pack, key, "audit-export"); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(pack)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := key.PublicJWKS()
		if err != nil {
			t.Fatal(err)
		}
		set, err := jose.ParseJWKSet(keys)
		if err != nil {
			t.Fatal(err)
		}
		verified, _, err := Verify(raw, set)
		if err != nil || len(verified.Cycles) != 3 {
			t.Fatalf("verify v3 = %d cycles, %v", len(verified.Cycles), err)
		}
		edited := verified
		edited.Cycles = append([]CycleResult(nil), verified.Cycles...)
		edited.Cycles[1].Verdict = StatusInterrupted
		forged, err := json.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(forged, set); err == nil {
			t.Fatal("a pack with an edited cycle verified")
		}
		var out strings.Builder
		report(&out, verified)
		if !strings.Contains(out.String(), "cycle 3: PASS") {
			t.Fatalf("report = %s", out.String())
		}
	})
	t.Run("an outage mid-run recovers", func(t *testing.T) {
		pack := run(t, 3, outageAt(2, 300*time.Millisecond))
		if pack.Verdict != StatusPass || cycleVerdicts(pack.Cycles) != "pass interrupted pass" {
			t.Fatalf("verdict %s cycles %q", pack.Verdict, cycleVerdicts(pack.Cycles))
		}
		outage := pack.Cycles[1].Outage
		if outage == nil || outage.RecoveredAt.IsZero() || !outage.RecoveredAt.After(outage.FirstSeen) || !strings.Contains(outage.Detail, "503") {
			t.Fatalf("outage = %+v", outage)
		}
		if pack.Cycles[0].Outage != nil || pack.Cycles[2].Outage != nil {
			t.Fatalf("outages outside cycle 2: %+v / %+v", pack.Cycles[0].Outage, pack.Cycles[2].Outage)
		}
		if !strings.Contains(strings.Join(pack.Limits, " "), "1 cycle was cut short") {
			t.Fatalf("limits = %q", pack.Limits)
		}
	})
	t.Run("an outage on the last cycle has no recovery to show", func(t *testing.T) {
		pack := run(t, 2, outageAt(2, 300*time.Millisecond))
		if pack.Verdict != StatusFail || cycleVerdicts(pack.Cycles) != "pass interrupted" {
			t.Fatalf("verdict %s cycles %q", pack.Verdict, cycleVerdicts(pack.Cycles))
		}
	})
	t.Run("a failure with the control plane up fails the run", func(t *testing.T) {
		pack := run(t, 2, func(_ *labServer, opts *Options) { opts.ForceFailure = JourneySecrets })
		if pack.Verdict != StatusFail || cycleVerdicts(pack.Cycles) != "fail fail" || pack.Cycles[0].Outage != nil {
			t.Fatalf("verdict %s cycles %q", pack.Verdict, cycleVerdicts(pack.Cycles))
		}
	})
	t.Run("an outage that outlasts the recovery timeout fails the run", func(t *testing.T) {
		pack := run(t, 3, func(lab *labServer, opts *Options) {
			outageAt(2, time.Hour)(lab, opts)
			opts.RecoveryTimeout = 200 * time.Millisecond
		})
		if pack.Verdict != StatusFail || !strings.HasPrefix(cycleVerdicts(pack.Cycles), "pass fail fail") ||
			!strings.Contains(pack.Cycles[1].Outage.Detail, "did not answer /readyz") {
			t.Fatalf("verdict %s cycles %q outage %+v", pack.Verdict, cycleVerdicts(pack.Cycles), pack.Cycles[1].Outage)
		}
	})
	t.Run("the incident journey runs once", func(t *testing.T) {
		if _, err := Evaluate(t.Context(), Options{Server: "https://cp.lab.test", Token: "t", DeploymentTarget: "x",
			Journeys: []string{JourneyCertificate, JourneyIncident}, Cycles: 2}); err == nil || !strings.Contains(err.Error(), "runs once") {
			t.Fatalf("incident with cycles = %v", err)
		}
	})
}
