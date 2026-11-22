// SPDX-License-Identifier: BUSL-1.1

package demo

import (
	"os"
	"strings"
	"testing"
)

// The seeded drift watch must pass the same operator-root admission as an
// ordinary source. Grant only a disposable demo directory to the control plane;
// a tenant must never gain a watch over the container's other files.
func TestDemoDriftWatchHasADedicatedOperatorRoot(t *testing.T) {
	control := parseCompose(t).Services["trstctl"]
	const root = "/etc/trstctl/demo"
	if got := stringValue(control.Environment["TRSTCTL_SECRETS_DRIFT_ROOTS"]); got != root {
		t.Fatalf("demo drift roots = %q, want only %q", got, root)
	}
	if !contains(control.Volumes, "./drift-demo:"+root+":ro") {
		t.Fatalf("demo drift root %q is not mounted read-only from its dedicated directory", root)
	}
	if info, err := os.Stat("drift-demo"); err != nil || !info.IsDir() {
		t.Fatalf("demo drift directory is missing or not a directory: %v", err)
	}
	if !strings.Contains(read(t, "seed.mjs"), `path: "/etc/trstctl/demo/edge-gateway.crt"`) {
		t.Fatal("seeded drift watch does not stay inside the dedicated operator root")
	}
}
