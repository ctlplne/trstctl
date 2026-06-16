package acme

import (
	"net"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

// The ACME HTTP-01 challenge identifier is attacker-influenced, so a CA that
// fetched it unguarded could be coerced into reaching internal endpoints — classic
// CA SSRF (SEC-006). The guard is the shared internal/netsec implementation, which
// the notification/connector channels also use (SEC-008) so the denylist cannot
// drift between call sites. These thin aliases preserve the package-local names the
// validator and its tests already use.

// ErrSSRFBlocked is returned when an outbound challenge fetch targets a blocked
// (non-public) address. It is netsec.ErrSSRFBlocked, re-exported for the ACME
// package's callers and tests.
var ErrSSRFBlocked = netsec.ErrSSRFBlocked

// blockedIP reports whether ip is in the SSRF denylist (delegates to netsec).
func blockedIP(ip net.IP) bool { return netsec.BlockedIP(ip) }

// ssrfSafeClient returns the SSRF-safe HTTP client for HTTP-01 validation.
func ssrfSafeClient(timeout time.Duration) *http.Client { return netsec.SafeClient(timeout) }
