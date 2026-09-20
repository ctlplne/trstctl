// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every scheduler the Server declares must actually be started (C1a discipline).
//
// This backlog has now produced FIVE instances of the same defect, and they are
// all the same shape: a capability is complete, its unit tests drive it
// directly, and nothing in the composition root calls it.
//
//	D2  VerifyAddress with no producer
//	B2  endpoint.renew job kind with no enqueue
//	B5  a custody projection that was never written
//	J2  RunRestoreDrill with no production caller
//	D2/D3  RunEndpointVerificationScheduler never registered as a worker — and
//	       endpoint_verification_scheduler.go is the ONLY producer of
//	       endpoint.verify work, so no deployment ever re-probed an endpoint
//	       while the epic's acceptance criterion said a renewal that never lands
//	       is detected within one interval
//
// Unit tests cannot catch this by construction: they are standing in for the
// caller that does not exist, so they pass precisely because the gap is there.
// The only thing that can catch it is a census that reads the composition root
// and asks whether each declared worker appears in it.
//
// Reading source as text is crude. It is also the one method that cannot be
// satisfied by a test double, which is the whole point.

var runWorkerRe = regexp.MustCompile(`(?m)^func \(s \*Server\) (Run[A-Za-z0-9_]*)\(ctx context\.Context\) \{`)

// notRuntimeWorkers are Run* methods that are deliberately NOT background
// workers started at boot. Each needs a reason, because "it is not a worker" is
// exactly what somebody would say about one that was accidentally never wired.
//
// EMPTY, and that is the point: every Run*(ctx) method this package declares is
// currently registered, so nothing needs excusing. A first draft carried an
// entry for RunLicensedBackgroundWorkers on the theory that it is a fan-out
// point rather than a worker — but it IS registered (run.go), so the exemption
// excused nothing and would have gone on excusing it if that ever changed. A
// dead exemption in a guard is how the guard stops being trusted, so it is
// gone. Add an entry only when a method genuinely must not be started, and say
// why.
var notRuntimeWorkers = map[string]string{}

func TestEveryDeclaredRuntimeWorkerIsActuallyStarted(t *testing.T) {
	t.Parallel()
	sources, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	for _, entry := range sources {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name) // #nosec G304 -- test reads its own package directory (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range runWorkerRe.FindAllStringSubmatch(string(body), -1) {
			declared[m[1]] = name
		}
	}
	if len(declared) < 5 {
		t.Fatalf("found only %d Run*(ctx) methods; the census regex has stopped matching and this "+
			"guard is no longer guarding anything", len(declared))
	}

	root, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	composition := string(root)

	var unwired []string
	for worker, file := range declared {
		if _, ok := notRuntimeWorkers[worker]; ok {
			continue
		}
		// Both registration forms count. The composition root starts some
		// workers under the shutdown-scoped workCtx and others under the
		// server's own ctx, and a census that only knew one form would report
		// six healthy workers as dead — which is what the first draft of this
		// test did, and is exactly the kind of false alarm that gets a guard
		// disabled rather than heeded.
		if !strings.Contains(composition, "startRuntimeWorker(workCtx, srv."+worker+")") &&
			!strings.Contains(composition, "startRuntimeWorker(ctx, srv."+worker+")") {
			unwired = append(unwired, worker+" ("+file+")")
		}
	}
	sort.Strings(unwired)
	if len(unwired) > 0 {
		t.Fatalf("these schedulers are declared and never started, so they do not run in any "+
			"deployment: %s\n\nRegister each in run.go's worker list, or add it to "+
			"notRuntimeWorkers with the reason it is not one. Every previous instance of this "+
			"shipped a capability that was complete, tested, documented and unreachable.",
			strings.Join(unwired, ", "))
	}
}
