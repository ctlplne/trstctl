// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/buildinfo"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/workloadapi"
)

// workloadChannel adapts the transport client to the host Workload API's
// Upstream (epic B3).
//
// The same shape as relayChannel: internal/agent/workloadapi holds an interface
// so it can be exercised without a control plane, and this binary owns the
// translation. It is also the only place the two meet, which keeps the question
// "what does this host send upward on a workload's behalf" answerable by
// reading one file.
type workloadChannel struct {
	c *transport.AgentClient
}

func (w workloadChannel) FetchWorkloadSVID(
	ctx context.Context, publicKeyDER []byte, selectors, audience []string,
) (*workloadapi.SVIDSet, error) {
	resp, err := w.c.FetchWorkloadSVID(ctx, &transport.FetchWorkloadSVIDRequest{
		PublicKeyDER: publicKeyDER, Selectors: selectors, Audience: audience,
	})
	if err != nil {
		return nil, err
	}
	out := &workloadapi.SVIDSet{Bundle: resp.Bundle}
	for _, svid := range resp.X509SVIDs {
		out.X509 = append(out.X509, workloadapi.X509SVID{
			SPIFFEID: svid.SPIFFEID, CertChainDER: svid.CertChainDER, Hint: svid.Hint,
			ExpiresAt: unixOrZero(svid.ExpiresAtUnix),
		})
	}
	for _, svid := range resp.JWTSVIDs {
		out.JWT = append(out.JWT, workloadapi.JWTSVID{
			SPIFFEID: svid.SPIFFEID, Token: svid.Token,
			ExpiresAt: unixOrZero(svid.ExpiresAtUnix),
		})
	}
	return out, nil
}

// unixOrZero converts a unix timestamp, leaving zero as the zero time.
//
// Zero means the control plane did not report an expiry, which is different from
// "expires at the epoch" — and a client that read the epoch would treat a
// perfectly good SVID as long expired.
func unixOrZero(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// startWorkloadAPI serves the host-local SPIFFE Workload API, if configured.
//
// Returns a stop function that is always safe to call, so the caller can defer
// it unconditionally rather than branching on whether the socket was enabled.
//
// A failure to start is reported and does NOT bring the agent down. The Workload
// API is one of several things this process does, and a socket path that cannot
// be bound — a directory that does not exist, a permission the operator has not
// granted — must not also stop this host's certificate renewals and inventory.
// It is loud rather than fatal.
func startWorkloadAPI(ctx context.Context, o agentOptions, conn *grpc.ClientConn) func() {
	socket := strings.TrimSpace(o.workloadAPISocket)
	if socket == "" {
		return func() {}
	}
	workloadAPIEnabled.Store(true)
	srv := workloadapi.New(
		workloadChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version()))},
		func(spiffeID string, selectors []string) {
			// Reported to stdout for now, and counted for the heartbeat below.
			// The console's per-host view reads the counter, not this line.
			workloadIssueCount.Add(1)
		},
	)
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fmt.Printf("trstctl-agent: SPIFFE Workload API serving on %s\n", socket)
		if err := srv.Serve(serveCtx, socket); err != nil && serveCtx.Err() == nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: workload API stopped:", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// workloadIssueCount is how many SVIDs this host has issued since start.
//
// It is what the heartbeat reports, and it is the difference between a console
// that says "the Workload API is configured here" and one that says "workloads
// on this host are actually getting identities". The first is a claim about
// configuration; the second is evidence.
var workloadIssueCount atomic.Int64

// Workload API heartbeat counter keys (epic B3).
//
// Two keys, and the pair is the point. "Served" alone would tell an operator the
// socket is configured, which is a claim about a flag; "issued" alone would read
// as zero on a healthy host that simply has no workloads yet. Together they
// separate the three states an operator actually needs apart: not serving,
// serving and idle, serving and working.
const (
	workloadAPIServedKey = "workload_api_served"
	workloadAPIIssuedKey = "workload_api_svids_issued"
	// pluginConnectorsKey counts verified third-party connectors on this relay
	// (epic E4).
	pluginConnectorsKey = "plugin_connectors_loaded"
	// A4: how many control-plane endpoints this relay's enrollment proxy can
	// currently reach, and how many are in cooldown.
	//
	// Both, not a ratio: "two of two healthy" and "two of four healthy" are
	// different operational situations and a percentage renders them the same.
	enrollProxyHealthyKey   = "enroll_proxy_endpoints_healthy"
	enrollProxyUnhealthyKey = "enroll_proxy_endpoints_unhealthy"
)

// pluginConnectorCount is how many verified third-party connectors this relay
// loaded at start.
//
// Set once, after verification. A count taken before verification would report
// modules that were refused, which is the opposite of what an operator checking
// this number wants to know.
var pluginConnectorCount atomic.Int64

// workloadAPICounters adds this host's Workload API state to the heartbeat.
//
// Reported on EVERY beat, including when the socket is off — a key that
// disappeared when the feature was disabled would leave the console unable to
// distinguish "this agent turned it off" from "this agent is too old to report
// it", and those call for different actions.
func workloadAPICounters(inv map[string]int64) map[string]int64 {
	out := inv
	if out == nil {
		out = map[string]int64{}
	}
	served := int64(0)
	if workloadAPIEnabled.Load() {
		served = 1
	}
	out[workloadAPIServedKey] = served
	out[workloadAPIIssuedKey] = workloadIssueCount.Load()
	// E4: how many verified third-party connectors this relay carries.
	//
	// Reported by the relay because only the relay knows. The control plane
	// does not distribute these modules, does not hold the operator's publisher
	// keys, and cannot enumerate what a given machine loaded — so any count it
	// rendered from its own state would be a guess. This is the measurement.
	out[pluginConnectorsKey] = pluginConnectorCount.Load()
	// A4: enrollment proxy health, so the Protocols console can show which
	// segments have a working proxy and how many endpoints each relay can
	// currently reach. Reported by the relay because only the relay knows which
	// of its upstreams are answering from where it sits.
	if pool := enrollProxyPool.Load(); pool != nil {
		h := pool.Health()
		out[enrollProxyHealthyKey] = int64(h.Healthy)
		out[enrollProxyUnhealthyKey] = int64(h.Unhealthy)
	}
	return out
}

// workloadAPIEnabled records whether this agent is serving the socket.
var workloadAPIEnabled atomic.Bool
