// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const (
	// One worker executes one job at a time. Do not pre-claim jobs whose leases
	// would expire while an earlier job waits for its external CA.
	relayClaimBatch = 1
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
			relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, leaseSeconds: int(relayLeaseFor(o.relayPollEvery).Seconds())},
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
			fmt.Printf("trstctl-agent: host exec profile loaded (%d allowed roots, %d permitted commands, %d Kubernetes namespaces)\n",
				len(hostProfile.AllowedRoots), len(hostProfile.Actions), len(hostProfile.KubernetesSecretNamespaces))
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
	if hasHost && relay.ProfileGrantsHostWork(hostProfile) {
		fmt.Printf("trstctl-agent: host connector execution enabled for %v\n", relay.HostConnectorKinds())
		return time.NewTimer(o.relayPollEvery),
			relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, leaseSeconds: int(relayLeaseFor(o.relayPollEvery).Seconds())},
			hostProfile
	}
	if hasHost {
		// Envoy's co-resident management API and encrypted posture predecessor
		// need no file/exec grant. The claim runner narrows this mode to the two
		// PQC posture kinds; it cannot accidentally take a file deploy job.
		fmt.Printf("trstctl-agent: host PQC posture claiming enabled every %s\n", o.relayPollEvery)
		return time.NewTimer(o.relayPollEvery),
			relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, leaseSeconds: int(relayLeaseFor(o.relayPollEvery).Seconds())},
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
				relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, leaseSeconds: int(relayLeaseFor(o.relayPollEvery).Seconds())},
				hostProfile
		}
		return nil, nil, hostProfile
	}
	fmt.Printf("trstctl-agent: relay claiming enabled for %v every %s\n",
		relay.ClaimableKinds(), o.relayPollEvery)
	return time.NewTimer(o.relayPollEvery),
		relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, leaseSeconds: int(relayLeaseFor(o.relayPollEvery).Seconds())},
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
func relayHTTPClient(caBundlePath string) (*http.Client, error) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// An appliance that redirects a credential upload elsewhere is not a
			// case worth following automatically.
			return http.ErrUseLastResponse
		},
	}
	if caBundlePath != "" {
		transport, err := newRelayCATransport(caBundlePath)
		if err != nil {
			return nil, err
		}
		client.Transport = transport
	}
	return client, nil
}

// relayCATransport (A86) serves --relay-ca-bundle without a restart. Every
// request first looks at the file (at most every relayCACheckEvery): a changed
// file is re-read and, when it parses as CA material, becomes the trust for
// the next connection; an unusable replacement keeps the bundle that worked
// and is remembered as the last error. Startup is still fail-closed: the
// first load must succeed, exactly as before. Status() is what the executor
// census reports, so the console shows the bundle in use, not the file.
type relayCATransport struct {
	path       string
	checkEvery time.Duration

	mu        sync.Mutex
	current   *http.Transport
	modTime   time.Time
	size      int64
	sha256    string
	loadedAt  time.Time
	lastErr   string
	lastCheck time.Time
}

const relayCACheckEvery = 5 * time.Second

func newRelayCATransport(path string) (*relayCATransport, error) {
	t := &relayCATransport{path: path, checkEvery: relayCACheckEvery}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read relay CA bundle: %w", err)
	}
	if err := t.load(info); err != nil {
		return nil, err
	}
	return t, nil
}

// load reads and installs the bundle described by info. Errors leave the
// current transport in place; the caller decides whether that is fatal.
func (t *relayCATransport) load(info os.FileInfo) error {
	caPEM, err := os.ReadFile(t.path) // #nosec G304 -- explicit operator-supplied CA path, parsed as public PEM trust only (CWE-22).
	if err != nil {
		return fmt.Errorf("read relay CA bundle: %w", err)
	}
	digest := crypto.SHA256Hex(caPEM)
	if digest == t.sha256 && t.current != nil {
		t.modTime, t.size = info.ModTime(), info.Size()
		return nil
	}
	next, err := mtls.HTTPTransportWithSystemRootsAndCA(caPEM)
	if err != nil {
		return fmt.Errorf("build relay HTTPS trust: %w", err)
	}
	previous := t.current
	t.current, t.sha256, t.loadedAt, t.lastErr = next, digest, time.Now().UTC(), ""
	t.modTime, t.size = info.ModTime(), info.Size()
	if previous != nil {
		previous.CloseIdleConnections()
	}
	return nil
}

// refresh re-reads a changed bundle. It never clears a working transport.
func (t *relayCATransport) refresh() {
	now := time.Now()
	if t.checkEvery > 0 && !t.lastCheck.IsZero() && now.Sub(t.lastCheck) < t.checkEvery {
		return
	}
	t.lastCheck = now
	info, err := os.Stat(t.path)
	if err != nil {
		t.noteReloadError(fmt.Sprintf("relay CA bundle unreadable; keeping the bundle loaded at %s: %v", t.loadedAt.Format(time.RFC3339), err))
		return
	}
	if info.ModTime().Equal(t.modTime) && info.Size() == t.size {
		return
	}
	before := t.sha256
	if err := t.load(info); err != nil {
		// Remember the attempt so the same broken file is not re-parsed on
		// every request, and keep the bundle that worked.
		t.modTime, t.size = info.ModTime(), info.Size()
		t.noteReloadError(fmt.Sprintf("relay CA bundle replacement rejected; keeping the bundle loaded at %s: %v", t.loadedAt.Format(time.RFC3339), err))
		return
	}
	if t.sha256 != before {
		fmt.Printf("trstctl-agent: relay CA bundle reloaded from %s (sha256 %s)\n", t.path, t.sha256[:16])
	}
}

func (t *relayCATransport) noteReloadError(msg string) {
	if t.lastErr != msg {
		fmt.Fprintln(os.Stderr, "trstctl-agent:", msg)
	}
	t.lastErr = msg
}

// RoundTrip implements http.RoundTripper over the bundle currently in force.
func (t *relayCATransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.refresh()
	current := t.current
	t.mu.Unlock()
	return current.RoundTrip(r)
}

// Status is the census view of the bundle in force.
func (t *relayCATransport) Status() *transport.RelayCABundleReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	return &transport.RelayCABundleReport{SHA256: t.sha256, LoadedAt: t.loadedAt, Error: t.lastErr}
}
