package protocol_test

import (
	"net/http"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/protocol"
)

// TestSupportedWindow pins the documented N-1/N+1 support window (SCHEMA-003): the
// current version and one step ahead are supported, below the minimum is not, and a
// zero/absent version (a pre-handshake agent) is treated as the baseline and accepted.
func TestSupportedWindow(t *testing.T) {
	cases := []struct {
		ver  int
		want bool
	}{
		{0, true}, // pre-handshake agent -> baseline (Version), accepted (additive)
		{protocol.MinSupportedVersion, true},
		{protocol.Version, true},
		{protocol.MaxSupportedVersion, true},
		{protocol.MaxSupportedVersion + 1, false}, // too new -> rejected
	}
	// A version strictly below the supported floor is rejected — but only assert it
	// when the floor is above 1, since 0 is the reserved "unspecified/baseline" value
	// (asserted true above), not a real "too old" version.
	if protocol.MinSupportedVersion > 1 {
		cases = append(cases, struct {
			ver  int
			want bool
		}{protocol.MinSupportedVersion - 1, false})
	}
	for _, c := range cases {
		if got := protocol.Supported(c.ver); got != c.want {
			t.Errorf("Supported(%d) = %v, want %v", c.ver, got, c.want)
		}
	}
}

// TestParseAndSetAgentProtocol round-trips the headers and pins the lenient parse: a
// missing or malformed protocol header reads as 0 (baseline), never a spurious
// rejection.
func TestParseAndSetAgentProtocol(t *testing.T) {
	h := http.Header{}
	protocol.SetAgentHeaders(h, "v1.2.3")
	if got := h.Get(protocol.HeaderAgentVersion); got != "v1.2.3" {
		t.Errorf("agent version header = %q, want v1.2.3", got)
	}
	if got := protocol.ParseAgentProtocol(h); got != protocol.Version {
		t.Errorf("parsed protocol = %d, want %d", got, protocol.Version)
	}

	// Missing header -> 0.
	if got := protocol.ParseAgentProtocol(http.Header{}); got != 0 {
		t.Errorf("missing protocol header parsed as %d, want 0", got)
	}
	// Malformed header -> 0 (not a panic, not a spurious value).
	bad := http.Header{}
	bad.Set(protocol.HeaderAgentProtocol, "not-a-number")
	if got := protocol.ParseAgentProtocol(bad); got != 0 {
		t.Errorf("malformed protocol header parsed as %d, want 0", got)
	}
	// A well-formed explicit value parses.
	ok := http.Header{}
	ok.Set(protocol.HeaderAgentProtocol, strconv.Itoa(protocol.MaxSupportedVersion))
	if got := protocol.ParseAgentProtocol(ok); got != protocol.MaxSupportedVersion {
		t.Errorf("parsed protocol = %d, want %d", got, protocol.MaxSupportedVersion)
	}
}
