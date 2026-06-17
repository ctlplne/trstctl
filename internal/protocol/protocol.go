// Package protocol defines the versioned wire contract between the in-network agent
// and the control plane (SCHEMA-003). Both binaries import it, so the negotiated
// version and the support window are a single source of truth rather than an
// unenforced convention.
//
// During a rolling fleet upgrade an old agent and a new control plane (and the
// reverse) coexist. The REST surface stays additive by policy, but that alone is a
// convention; this package makes the agent announce its protocol version and lets
// the server make an explicit, documented compatibility decision: an agent within
// the supported window is accepted, one outside it is rejected with a clear,
// actionable error instead of failing in some opaque way later.
package protocol

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	// HeaderAgentVersion carries the agent's human-readable build version (the same
	// string buildinfo.Version() reports), for display and diagnostics. It is not used
	// for a compatibility decision — that is HeaderAgentProtocol's job — because build
	// versions are not ordered in a way the server can reason about.
	HeaderAgentVersion = "X-Trstctl-Agent-Version"
	// HeaderAgentProtocol carries the integer agent↔control-plane protocol version the
	// agent speaks. The server uses it to accept or reject the request, so it is the
	// stable compatibility contract, decoupled from the cosmetic build version.
	HeaderAgentProtocol = "X-Trstctl-Agent-Protocol"
	// HeaderServerProtocol is echoed by the server on a protocol-bearing response so an
	// agent can detect server-side skew and adapt or warn.
	HeaderServerProtocol = "X-Trstctl-Server-Protocol"
	// MetadataAgentVersion is the gRPC metadata key equivalent of
	// HeaderAgentVersion. gRPC metadata keys are lowercase by contract.
	MetadataAgentVersion = "x-trstctl-agent-version"
	// MetadataAgentProtocol is the gRPC metadata key equivalent of
	// HeaderAgentProtocol for the steady-state agent channel.
	MetadataAgentProtocol = "x-trstctl-agent-protocol"
	// MetadataServerProtocol is the gRPC metadata key equivalent of
	// HeaderServerProtocol.
	MetadataServerProtocol = "x-trstctl-server-protocol"
	// MetadataAgentCapabilities carries the steady-state RPC capabilities the
	// agent intends to use on this connection.
	MetadataAgentCapabilities = "x-trstctl-agent-capabilities"
	// MetadataServerCapabilities echoes the steady-state RPC capabilities this
	// server advertises for the negotiated protocol.
	MetadataServerCapabilities = "x-trstctl-server-capabilities"
)

// Version is the current agent↔control-plane protocol version. Bump it only on a
// breaking change to that contract; an additive change keeps the same version.
const Version = 1

// MinSupportedVersion and MaxSupportedVersion bound the protocol versions the
// control plane accepts from an agent — the documented N-1 / N+1 support window
// across a rolling upgrade. MinSupportedVersion is the oldest agent still served;
// MaxSupportedVersion tolerates an agent one step ahead (a partially-upgraded fleet
// where agents roll before the control plane). Widen the window deliberately when
// the support policy changes; do not silently drop an old version.
const (
	MinSupportedVersion = 1
	MaxSupportedVersion = Version + 1
)

// Supported reports whether the control plane serves a given agent protocol
// version. A zero/absent version (a pre-handshake agent that sends no header) is
// treated as the baseline Version, so existing agents that predate the handshake
// keep working — the handshake is additive.
func Supported(agentVersion int) bool {
	if agentVersion == 0 {
		agentVersion = Version
	}
	return agentVersion >= MinSupportedVersion && agentVersion <= MaxSupportedVersion
}

// ParseAgentProtocol reads the agent protocol version from request headers. A
// missing or unpar-seable header yields 0 ("unspecified"), which Supported treats as
// the baseline — so a pre-handshake agent is accepted, while a malformed value does
// not spuriously reject a request.
func ParseAgentProtocol(h http.Header) int {
	return ParseAgentProtocolValue(h.Get(HeaderAgentProtocol))
}

// ParseAgentProtocolValue parses a single protocol-version value from HTTP
// headers or gRPC metadata. A missing or malformed value yields 0 ("unspecified"),
// which Supported treats as the baseline for additive compatibility.
func ParseAgentProtocolValue(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// VersionString returns Version in the wire form used by HTTP headers and gRPC
// metadata.
func VersionString() string { return strconv.Itoa(Version) }

// SetAgentHeaders stamps the agent's version + protocol onto an outgoing request, so
// the control plane can record the version and make a compatibility decision
// (SCHEMA-003). version is the agent's build version string (buildinfo.Version()).
func SetAgentHeaders(h http.Header, version string) {
	if version != "" {
		h.Set(HeaderAgentVersion, version)
	}
	h.Set(HeaderAgentProtocol, VersionString())
}
