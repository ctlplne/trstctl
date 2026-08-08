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
	"trstctl.com/trstctl/internal/connector"
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
func relayLoopFor(o agentOptions, a *agent.Agent, conn *grpc.ClientConn) (*time.Timer, relay.Channel, connector.LocalOpsConfig) {
	var hostProfile connector.LocalOpsConfig
	if !o.relayClaim && !o.selfUpgrade {
		return nil, nil, hostProfile
	}
	if !o.relayClaim {
		// Self-upgrade only (A5): the claim loop runs so this agent can pick
		// up its own agent.upgrade jobs, and asks for nothing else — an agent
		// with no exec profile claiming connector work would spend the queue's
		// attempts discovering it cannot do any of it.
		fmt.Printf("trstctl-agent: self-upgrade claiming enabled every %s\n", o.relayPollEvery)
		return time.NewTimer(o.relayPollEvery),
			relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity},
			hostProfile
	}
	// The host exec profile is loaded and VALIDATED at startup, not at first
	// job. An operator who mistyped a path finds out when they start the agent,
	// not an hour later when a renewal fails on a machine they are not watching.
	if o.hostExecProfile != "" {
		loaded, err := relay.LoadHostProfile(o.hostExecProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: host exec profile could not be loaded:", err)
			fmt.Fprintln(os.Stderr, "trstctl-agent: file and reload deploys will not be claimed on this host")
		} else {
			hostProfile = loaded
			fmt.Printf("trstctl-agent: host exec profile loaded (%d allowed roots, %d permitted commands)\n",
				len(hostProfile.AllowedRoots), len(hostProfile.Actions))
		}
	}
	roles := a.Roles()
	hasNetwork, hasHost := false, false
	for _, role := range roles {
		switch role {
		case mtls.AgentRoleNetwork:
			hasNetwork = true
		case mtls.AgentRoleHost:
			hasHost = true
		}
	}
	// A host agent with a profile claims file/reload work; a relay claims
	// appliance work; an agent granted both claims both. Only an agent that can
	// do neither is refused, and told which grant it is missing.
	if hasHost && len(hostProfile.AllowedRoots) > 0 {
		fmt.Printf("trstctl-agent: host connector execution enabled for %v\n", relay.HostConnectorKinds())
		return time.NewTimer(o.relayPollEvery),
			relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity},
			hostProfile
	}
	if !hasNetwork {
		fmt.Fprintf(os.Stderr,
			"trstctl-agent: --relay-claim was set but this agent's certificate carries roles %v, not %q; "+
				"relay work will not be claimed. Re-enroll with a network-role bootstrap token to make this agent a relay.\n",
			roles, mtls.AgentRoleNetwork)
		if o.selfUpgrade {
			// The relay grant is missing but the self-upgrade opt-in stands on
			// its own: upgrades are per-agent work either role may do.
			return time.NewTimer(o.relayPollEvery),
				relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity},
				hostProfile
		}
		return nil, nil, hostProfile
	}
	fmt.Printf("trstctl-agent: relay claiming enabled for %v every %s\n",
		relay.ClaimableKinds(), o.relayPollEvery)
	return time.NewTimer(o.relayPollEvery),
		relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity},
		hostProfile
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
