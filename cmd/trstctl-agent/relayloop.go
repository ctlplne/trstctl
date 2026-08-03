// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const (
	// relayClaimBatch caps one relay claim. Small on purpose: each job in a batch
	// redeems its own credential, so a large batch means more live material on
	// this host at once for no throughput a relay actually needs.
	relayClaimBatch = 4
	// relayMinLease floors the lease a relay asks for, so a very short poll
	// interval cannot request a lease too brief to finish a deploy in.
	relayMinLease = 60 * time.Second
)

// relayLoopFor arms the relay loop, or returns nils when it must not run.
//
// Two conditions, both required. The operator asked (--relay-claim), and this
// agent's CERTIFICATE carries the network role. The second is not a courtesy
// check: the control plane will refuse relay work to a host-role certificate
// regardless, so an agent polling without the role would generate load, log
// nothing useful, and present as a stalled queue rather than as the
// misconfiguration it is. Refusing here says so once, at startup, in words.
func relayLoopFor(o agentOptions, a *agent.Agent, conn *grpc.ClientConn) (*time.Timer, relay.Channel) {
	if !o.relayClaim {
		return nil, nil
	}
	roles := a.Roles()
	hasNetwork := false
	for _, role := range roles {
		if role == mtls.AgentRoleNetwork {
			hasNetwork = true
			break
		}
	}
	if !hasNetwork {
		fmt.Fprintf(os.Stderr,
			"trstctl-agent: --relay-claim was set but this agent's certificate carries roles %v, not %q; "+
				"relay work will not be claimed. Re-enroll with a network-role bootstrap token to make this agent a relay.\n",
			roles, mtls.AgentRoleNetwork)
		return nil, nil
	}
	fmt.Printf("trstctl-agent: relay claiming enabled for %v every %s\n",
		relay.ClaimableKinds(), o.relayPollEvery)
	return time.NewTimer(o.relayPollEvery),
		relayChannel{transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version()))}
}

// relayTimerChan is nil-safe: a nil timer yields a nil channel, which blocks
// forever in a select, so the disarmed case simply never fires.
func relayTimerChan(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

// relayLeaseFor turns a poll interval into the lease a relay asks for. It asks
// for meaningfully longer than it polls: a lease that expires between polls
// would hand the job to somebody else mid-deploy.
func relayLeaseFor(poll time.Duration) time.Duration {
	lease := poll * 4
	if lease < relayMinLease {
		return relayMinLease
	}
	return lease
}

// relayHTTPClient is the relay's client for appliance APIs.
//
// It deliberately carries neither the control plane's egress guard nor its
// SSRF-blocking transport. A relay exists to reach devices on private,
// non-routable addresses inside its own segment — the exact destinations those
// controls are built to refuse. Keeping admission-time endpoint validation on
// the control plane and NOT re-running it here is the correct split, and it is
// a real reduction in what the control plane can promise about where a relay
// connects; docs/limitations.md says so plainly rather than leaving it to be
// discovered.
func relayHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// An appliance that redirects a credential upload elsewhere is not a
			// case worth following automatically.
			return http.ErrUseLastResponse
		},
	}
}
