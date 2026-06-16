package docs

import (
	"strings"
	"testing"
)

// TestEnrollRenewalDisclosedAsNotServed is the reality-bound disclosure for DOCS-001:
// enrollment-protocols.md previously claimed POST /enroll/renewal "is mounted and
// served," but the running binary's API mounts ONLY POST /enroll/bootstrap, so a
// renewal request 404s. This test binds the doc to the served code, in both
// directions:
//
//   - while the served API does NOT mount renewal, the doc must say so (no "renewal
//     ... mounted and served" over-claim, and an explicit not-yet-mounted/404
//     statement) and link the wire-in epic;
//   - if a future change mounts renewal (the route appears in internal/api), the
//     stale not-served disclosure must be retired.
//
// The behavioral companion is internal/api/TestEnrollRoutesServed, which drives the
// real mux and asserts bootstrap serves while renewal 404s.
func TestEnrollRenewalDisclosedAsNotServed(t *testing.T) {
	const apiSrc = "../internal/api/api.go"
	api := read(t, apiSrc)

	bootstrapServed := strings.Contains(api, `"POST /enroll/bootstrap"`)
	renewalServed := strings.Contains(api, `"POST /enroll/renewal"`)

	// Code anchor: the served API must still mount bootstrap (the disclosure that
	// "bootstrap is served, renewal is not" rests on this being true).
	if !bootstrapServed {
		t.Fatal("internal/api no longer mounts POST /enroll/bootstrap; the DOCS-001 served-vs-library disclosure has no code anchor — revisit this reality test")
	}

	doc := read(t, "features/enrollment-protocols.md")
	low := strings.Join(strings.Fields(strings.ToLower(doc)), " ")

	if renewalServed {
		// Renewal is now genuinely served: the not-served disclosure would be a stale
		// under-claim and must have been retired.
		if strings.Contains(low, "not yet mounted") && strings.Contains(low, "/enroll/renewal") {
			t.Error("POST /enroll/renewal appears to be SERVED now (mounted in internal/api), but enrollment-protocols.md still discloses it as not-yet-mounted — update the doc (EXC-WIRE-02 closed) (DOCS-001)")
		}
		return
	}

	// Not served: the doc must NOT over-claim renewal as served, and must disclose the
	// 404 reality + link the epic.
	for _, overClaim := range []string{
		"renewal endpoints (`post /enroll/bootstrap`, `post /enroll/renewal`) **are mounted and served**",
		"post /enroll/renewal` (served)",
		"bootstrap and renewal endpoints (`post /enroll/bootstrap`, `post /enroll/renewal`) are mounted and served",
	} {
		if strings.Contains(low, overClaim) {
			t.Errorf("enrollment-protocols.md over-claims POST /enroll/renewal as served (%q) while internal/api does not mount it (DOCS-001)", overClaim)
		}
	}
	if !strings.Contains(low, "not yet mounted") {
		t.Error("enrollment-protocols.md must disclose POST /enroll/renewal as library-complete-but-not-yet-mounted (DOCS-001)")
	}
	if !strings.Contains(low, "404") {
		t.Error("enrollment-protocols.md should state that /enroll/renewal returns 404 on the running binary (DOCS-001)")
	}
	if !strings.Contains(doc, "EXC-WIRE-02") {
		t.Error("enrollment-protocols.md must link the wire-in epic EXC-WIRE-02 for the unmounted renewal route (DOCS-001)")
	}
}

// TestAgentMTLSChannelDisclosedAsNotServed is the reality-bound disclosure for
// WIRE-004: the agent↔control-plane mTLS gRPC channel is library-only — the
// transport package registers only the health service and exposes no agent RPCs, and
// nothing in internal/server mounts an agent gRPC listener, so served
// /enroll/bootstrap mints an agent certificate for a channel the running binary does
// not serve. The agent CA is additionally in-process and regenerated per boot (an
// AN-4 deviation that rotates the pinned CA on restart). limitations.md must disclose
// this honestly and link the wire-in epic; if a future change serves the channel (a
// gRPC server appears in internal/server), the stale disclosure must be retired.
func TestAgentMTLSChannelDisclosedAsNotServed(t *testing.T) {
	// Code anchor 1: the agent transport still registers only the health service (no
	// agent RPCs), proving the channel is a stub today.
	tr := read(t, "../internal/agent/transport/transport.go")
	if !strings.Contains(tr, "RegisterHealthServer") {
		t.Fatal("internal/agent/transport no longer registers the health service; revisit the WIRE-004 reality test")
	}

	served := serverServesAgentGRPC(t)

	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if served {
		// Now genuinely served: the not-served disclosure would be stale.
		if strings.Contains(low, "agent mtls") && strings.Contains(low, "not yet served by the binary") {
			t.Error("an agent gRPC listener appears to be served now, but limitations.md still discloses the agent mTLS channel as not-yet-served — update the disclosure (WIRE-004)")
		}
		return
	}

	// Not served: limitations.md must name the agent mTLS channel as built/tested but
	// not served, disclose the per-boot in-process agent CA, and link the epic.
	for _, m := range []string{"agent", "mtls", "not yet served by the binary"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the agent↔control-plane mTLS gRPC channel as built/tested-but-not-served (missing marker %q) (WIRE-004)", m)
		}
	}
	if !strings.Contains(low, "wire-004") {
		t.Error("limitations.md should cite WIRE-004 in the agent mTLS channel disclosure so the finding is traceable")
	}
	if !strings.Contains(lim, "EXC-WIRE-02") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-02 for the agent mTLS channel (WIRE-004)")
	}
	// Over-claim guard: do not claim agents complete RPCs / the channel is served.
	for _, oc := range []string{"agents connect over mtls in the running binary", "the agent grpc channel is served"} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims the agent mTLS channel as served (%q) while no listener is mounted (WIRE-004)", oc)
		}
	}
}

// serverServesAgentGRPC reports whether the served composition (internal/server)
// stands up an agent-facing gRPC listener — by importing the agent transport package
// or constructing a grpc.Server for agents. Today it does not (the only grpc.Server
// is the signer UDS); when EXC-WIRE-02 mounts the agent listener, this flips true.
func serverServesAgentGRPC(t *testing.T) bool {
	t.Helper()
	for _, f := range nonTestGoFiles(t, "../internal/server") {
		src := read(t, f)
		if strings.Contains(src, `trstctl.com/trstctl/internal/agent/transport"`) ||
			strings.Contains(src, "transport.NewServer(") {
			return true
		}
	}
	return false
}
