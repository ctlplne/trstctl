// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"sync/atomic"
	"syscall"

	"trstctl.com/trstctl/internal/netsec"
)

// egressPolicy is the agent's policy for the connections it opens to run jobs
// (A190). The binary sets it once at startup from its flags; until then, and
// when it is nil, only the always-on part applies: link-local, cloud metadata,
// unspecified and multicast destinations are refused.
var egressPolicy atomic.Pointer[netsec.RelayEgress]

// SetEgressPolicy installs the agent's egress policy; nil leaves the always-on
// part alone.
func SetEgressPolicy(p *netsec.RelayEgress) { egressPolicy.Store(p) }

// egress is the current policy. Its methods are nil-safe.
func egress() *netsec.RelayEgress { return egressPolicy.Load() }

// egressControl chains base, which may be nil, before the policy.
func egressControl(base func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
	return egress().Guard(base)
}
