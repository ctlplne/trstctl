// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

func TestACMEDeviceAttestationDocumentationMatchesServedProfileSeam(t *testing.T) {
	acmeServer := read(t, "../internal/server/protocol_mounts.go")
	acmeProof := read(t, "../internal/protocols/acme/device_attest.go")
	profileModel := read(t, "../internal/profile/profile.go")
	for source, want := range map[string]string{
		acmeServer:   "WithDeviceAttestationPolicy",
		acmeProof:    "ParseAndVerifyTPMDeviceAttestation",
		profileModel: "ACMEDeviceAttestationPolicy",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("served TPM device-attest-01 seam no longer contains %q; revisit its docs", want)
		}
	}
	for _, page := range []string{"features/acme-and-dns.md", "guides/profile-authoring.md"} {
		low := strings.ToLower(read(t, page))
		for _, want := range []string{
			"device-attest-01",
			"default-off",
			"operator",
			"tpm",
			"csr",
			"internal/crypto",
			"no manufacturer metadata",
			"http-01",
			"dns-01",
			"tls-alpn-01",
		} {
			if !strings.Contains(low, want) {
				t.Errorf("%s must document TPM device attestation reality (missing %q)", page, want)
			}
		}
	}
}

// TestEnrollRenewalDocumentedAsServed binds enrollment-protocols.md to the served
// /enroll route set. Bootstrap stays on the primary control-plane mux; renewal is
// served through the dedicated agent-CA mTLS listener, so the old
// library-complete-but-404 disclosure must stay retired without reintroducing renewal
// on the general API listener.
func TestEnrollRenewalDocumentedAsServed(t *testing.T) {
	const apiSrc = "../internal/api/api.go"
	api := read(t, apiSrc)
	agents := read(t, "../internal/api/agents.go")
	enroll := read(t, "../internal/api/enroll.go")
	server := read(t, "../internal/server/server.go")
	agentHTTPRenewal := read(t, "../internal/server/agenthttprenewal.go")

	bootstrapServed := strings.Contains(api, `"POST /enroll/bootstrap"`)
	renewalHandler := strings.Contains(enroll, "func (a *API) AgentRenewalHandler() http.Handler") &&
		strings.Contains(enroll, `"POST /enroll/renewal"`)
	renewalWired := strings.Contains(server, "a.AgentRenewalHandler()") &&
		strings.Contains(agentHTTPRenewal, "RunAgentHTTPRenewal") &&
		strings.Contains(agentHTTPRenewal, "AgentHTTPRenewalServed")

	if !bootstrapServed {
		t.Fatal("internal/api no longer mounts POST /enroll/bootstrap; revisit the F54 enrollment docs")
	}
	if strings.Contains(api, `"POST /enroll/renewal"`) {
		t.Fatal("internal/api primary mux mounts POST /enroll/renewal; renewal must stay on the dedicated agent-CA mTLS listener")
	}
	if !renewalHandler || !renewalWired {
		t.Fatal("server no longer wires POST /enroll/renewal through the dedicated agent HTTP renewal listener; docs must not claim F54 renewal is served")
	}

	doc := read(t, "features/enrollment-protocols.md")
	low := strings.Join(strings.Fields(strings.ToLower(doc)), " ")

	for _, stale := range []string{
		"not yet mounted",
		"404 on the running binary",
		"tracked as future work",
		"library-complete but **not yet mounted**",
	} {
		if strings.Contains(low, stale) && strings.Contains(low, "/enroll/renewal") {
			t.Errorf("enrollment-protocols.md still carries stale F54 renewal under-claim %q", stale)
		}
	}
	for _, want := range []string{
		"`post /enroll/bootstrap`",
		"`post /enroll/renewal`",
		"dedicated agent-ca mtls https listener",
		"agent_channel.http_renewal_addr",
		"verified client certificate",
		"review exact enrollment plan",
		"effect-free",
		"refuses this mutation too",
		"lost, expired, or already-used token cannot be recovered",
		"agents enroll-token-preview",
		"served",
	} {
		if !strings.Contains(low, want) {
			t.Errorf("enrollment-protocols.md must document served embedded enrollment renewal (missing %q)", want)
		}
	}
	for _, want := range []string{
		"agentEnrollmentBlockers",
		"agentRenewalReady",
		"renewal_ready",
		"renewal_path",
		"renewal_authentication",
	} {
		if !strings.Contains(agents, want) {
			t.Errorf("the F54 shared preview/mutation renewal oracle no longer contains %q", want)
		}
	}
}

// TestAgentMTLSChannelDisclosedAsNotServed is the reality-bound disclosure for
// WIRE-004: while the agent steady-state channel was library-only, limitations.md
// had to disclose that under-claim honestly. Once internal/server mounts the
// agent-facing gRPC listener, the stale not-served disclosure must be retired and
// replaced with a positive served statement.
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
		if !containsAll(low, []string{"agent", "mtls grpc channel", "served by the running binary"}) {
			t.Error("an agent gRPC listener is served now, but limitations.md does not positively disclose the served agent mTLS channel — update the disclosure (WIRE-004)")
		}
		for _, stale := range []string{
			"agent mtls channel is not yet served by the binary",
			"agent mtls grpc channel is not yet served by the binary",
			"agent-facing grpc listener is not yet served by the binary",
		} {
			if strings.Contains(low, stale) {
				t.Errorf("an agent gRPC listener appears to be served now, but limitations.md still discloses the agent mTLS channel as not-yet-served (%q) — update the disclosure (WIRE-004)", stale)
			}
		}
		if strings.Contains(low, "agent ca") && strings.Contains(low, "regenerated per boot") {
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
