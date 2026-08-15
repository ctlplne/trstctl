// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os/exec"
	"strings"
	"testing"
)

// The agent binary is not the control plane (epic A3, doctrine D1).
//
// trstctl-agent runs inside a customer's estate, on hosts and in network
// segments the control plane can never reach. Everything about its security
// story — one-way outbound, no standing credentials, no database access, the
// brain never trusts the edge — depends on the binary being structurally unable
// to do control-plane things. A binary that links the PostgreSQL driver is one
// misconfiguration away from being pointed at the database; a binary that links
// the orchestrator is one import away from executing effects locally that must
// only ever run behind the outbox.
//
// So the boundary is enforced here, on the linked dependency graph, not by
// convention. Before this guard existed the boundary was already broken twice —
// internal/agent/discovery and internal/sshinv each carried a store-backed sink
// whose only callers were control-plane tests, and through those two edges the
// agent binary linked internal/store, internal/events, internal/config,
// internal/audit, internal/privacy, internal/auditchain and eleven pgx
// packages. Both sinks now live in the tests that used them.
//
// forbiddenAgentDeps is the closed set. Adding a package here needs the same
// scrutiny as removing one: the question is always "what could a compromised or
// misconfigured agent DO with this linked in".
var forbiddenAgentDeps = []string{
	// The database. An agent talks to the control plane over one mTLS channel;
	// it never holds a connection string, so it should never hold the driver.
	"trstctl.com/trstctl/internal/store",
	"github.com/jackc/pgx",
	// The served control plane and its effect machinery. Work reaches an agent
	// as a claimed job over the channel (A1), never as linked-in handlers.
	"trstctl.com/trstctl/internal/server",
	"trstctl.com/trstctl/internal/orchestrator",
	"trstctl.com/trstctl/internal/api",
	// The event spine and its consumers. Agents REPORT evidence over the
	// channel; the control plane appends it. An agent that could append events
	// directly would bypass tenant attribution (AN-1/AN-2).
	"trstctl.com/trstctl/internal/events",
	"trstctl.com/trstctl/internal/audit",
	"trstctl.com/trstctl/internal/privacy",
	// Control-plane configuration. The agent has flags and its own small config
	// surface; linking config.Load would let a deployment hand an agent the
	// control plane's config file and have it mean something.
	"trstctl.com/trstctl/internal/config",
}

// TestAgentBinaryLinksNoControlPlane fails if the agent binary's transitive
// dependency graph contains any forbidden package. It shells out to `go list`
// because the module graph is the artifact under test: a src-tree grep would
// miss an edge added two hops away, which is exactly how the store edge got in.
func TestAgentBinaryLinksNoControlPlane(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../cmd/trstctl-agent").Output()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/trstctl-agent: %v", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		for _, forbidden := range forbiddenAgentDeps {
			if dep == forbidden || strings.HasPrefix(dep, forbidden+"/") {
				t.Errorf("trstctl-agent links %s — the agent binary must not link the control plane (see the comment on forbiddenAgentDeps)", dep)
			}
		}
	}
}

// TestConnectorCoreStaysHostNeutral pins the property that lets the SAME
// connector implementations run on either side (A3): internal/connector and
// every connector implementation package import only the crypto boundary, the
// plugin host surface, and the standard library. The moment one of them grows a
// store or server import, the relay runtime drags the control plane into the
// agent binary and the guard above fires — this guard exists so the failure
// names the actual defect (a connector package stopped being host-neutral)
// rather than its symptom.
func TestConnectorCoreStaysHostNeutral(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "trstctl.com/trstctl/internal/connector/...").Output()
	if err != nil {
		t.Fatalf("go list -deps ./internal/connector/...: %v", err)
	}
	allowedPrefixes := []string{
		"trstctl.com/trstctl/internal/crypto",
		"trstctl.com/trstctl/internal/pluginhost",
		"trstctl.com/trstctl/internal/connector",
		// Host-neutral utilities both sides may link. Each is here because its
		// own dependency graph is clean, and each is re-checked by this guard
		// transitively — if one of them grows a store or events import, this
		// test names it.
		//
		// bulkhead: bounded worker pools. AN-7 applies wherever work executes,
		// which after A3 includes the relay. Imports nothing of ours.
		"trstctl.com/trstctl/internal/bulkhead",
		// secretjson/secrettext: the AN-8 wrappers that keep secret bytes out of
		// string-typed JSON. Import only the crypto boundary.
		"trstctl.com/trstctl/internal/secretjson",
		"trstctl.com/trstctl/internal/secrettext",
		// netsec: the stdlib-only SSRF/reserved-address policy. The plugin
		// sandbox's dial control shares netsec.HardBlockedIP (J3/V25) instead
		// of hand-copying the predicate; the agent binary already links netsec
		// for its own plugin runtime, so this widens nothing.
		"trstctl.com/trstctl/internal/netsec",
		// observ: the metrics/trace primitives (Registry, CounterVec, SpanData).
		// The control-plane-only exporters — including the audit streamer that
		// replays the event log — were split into internal/observ/otlp exactly so
		// this core could stay on the agent side of the line. observ/otlp is NOT
		// allowed here, and the prefix match below is written to exclude it.
		"trstctl.com/trstctl/internal/observ",
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep = strings.TrimSpace(dep)
		if !strings.HasPrefix(dep, "trstctl.com/") {
			continue // stdlib and vetted third-party are governed elsewhere
		}
		ok := false
		for _, allowed := range allowedPrefixes {
			if dep == allowed || (allowed != "trstctl.com/trstctl/internal/observ" && strings.HasPrefix(dep, allowed+"/")) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("internal/connector graph reaches %s; the connector core must stay host-neutral (crypto boundary + pluginhost + stdlib only)", dep)
		}
	}
}
