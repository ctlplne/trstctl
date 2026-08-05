// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/agent/enrollproxy"
	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Assembling the relay's third-party connector runtime from operator input
// (epic E4).
//
// Every input here comes from the operator's own command line: which modules,
// which publisher keys vouch for them, which exact builds, and what those
// modules are allowed to do. None of it is read from the module, and none of it
// arrives from the control plane.
//
// That is the point. A grant derived from a module's own metadata would let a
// publisher widen their privileges by editing a file they ship; a grant pushed
// from the control plane would mean the vendor decides what partner code may do
// inside a customer's network. Both make the capability system decorative. The
// person who owns the machine decides what runs on it.

// buildPluginRuntime constructs the relay's plugin runtime, or nil when third-
// party connectors are not configured.
//
// A configuration error is FATAL rather than a warning. An agent that came up
// having silently skipped its plugin directory would serve a subset of the
// connectors an operator configured, and the missing one is exactly the one
// whose signature did not check out.
func buildPluginRuntime(ctx context.Context, o agentOptions) (*relay.PluginRuntime, error) {
	dir := strings.TrimSpace(o.pluginDir)
	if dir == "" {
		return nil, nil
	}
	keys, err := readPluginKeys(o.pluginKeys)
	if err != nil {
		return nil, err
	}
	grant, err := buildPluginGrant(o.pluginCaps, o.pluginCapPrefix)
	if err != nil {
		return nil, err
	}
	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir:              dir,
		TrustedKeyPEMs:   keys,
		PinnedDigestsHex: splitList(o.pluginPins),
		Grant:            grant,
	})
	if err != nil {
		return nil, err
	}
	if rt != nil {
		names := rt.Names()
		pluginConnectorCount.Store(int64(len(names)))
		fmt.Printf("trstctl-agent: third-party connectors loaded and verified: %v\n", names)
	}
	return rt, nil
}

// readPluginKeys loads the publisher public keys from disk.
func readPluginKeys(list string) ([][]byte, error) {
	paths := splitList(list)
	if len(paths) == 0 {
		return nil, fmt.Errorf("trstctl-agent: --connector-plugin-dir is set but --connector-plugin-key " +
			"is not; this agent will not load third-party code it cannot verify")
	}
	out := make([][]byte, 0, len(paths))
	for _, path := range paths {
		pem, err := os.ReadFile(path) // #nosec G304 -- operator-supplied trust key path (CWE-22)
		if err != nil {
			return nil, fmt.Errorf("trstctl-agent: read connector plugin key %q: %w", path, err)
		}
		out = append(out, pem)
	}
	return out, nil
}

// buildPluginGrant turns the operator's capability flags into a grant.
//
// A capability named with no prefix is unrestricted FOR THAT CAPABILITY, which
// is a deliberate and visible choice on a command line rather than a default.
// A prefix naming a capability that was not granted is an error: it reads as a
// restriction and would silently be none, which is the shape of mistake this
// whole subsystem exists to make impossible.
func buildPluginGrant(caps, prefixes string) (pluginhost.Grant, error) {
	names := splitList(caps)
	if len(names) == 0 {
		return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: --connector-plugin-dir is set but " +
			"--connector-plugin-capability is not; third-party connectors run under a grant the " +
			"operator states explicitly, never a default")
	}
	granted := make([]pluginhost.Capability, 0, len(names))
	known := map[string]bool{}
	for _, name := range names {
		cap, ok := pluginCapability(name)
		if !ok {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: unknown connector plugin capability %q", name)
		}
		granted = append(granted, cap)
		known[name] = true
	}
	grant := pluginhost.NewGrant(granted...)
	for _, raw := range splitList(prefixes) {
		name, prefix, ok := strings.Cut(raw, "=")
		if !ok {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: connector plugin capability "+
				"prefix %q is not capability=prefix", raw)
		}
		name = strings.TrimSpace(name)
		if !known[name] {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: capability prefix names %q, which "+
				"is not in --connector-plugin-capability; it would read as a restriction and be none", name)
		}
		cap, _ := pluginCapability(name)
		grant = grant.WithPathPrefix(cap, strings.TrimSpace(prefix))
	}
	return grant, nil
}

// pluginCapability maps an operator-facing name to a capability.
func pluginCapability(name string) (pluginhost.Capability, bool) {
	switch strings.TrimSpace(name) {
	case "fs.read":
		return pluginhost.CapFSRead, true
	case "fs.write":
		return pluginhost.CapFSWrite, true
	case "net.dial":
		return pluginhost.CapNetDial, true
	default:
		return "", false
	}
}

// startEnrollProxy serves the LAN-local enrolment proxy, if configured.
//
// Returns a stop function that is always safe to call. A failure to bind is
// reported and does NOT bring the agent down: the proxy is one of several things
// this process does, and an address already in use must not also stop this
// segment's connector deploys and inventory.
func startEnrollProxy(ctx context.Context, o agentOptions) func() {
	listen := strings.TrimSpace(o.enrollProxyListen)
	if listen == "" {
		return func() {}
	}
	upstreams := splitList(o.enrollProxyUpstream)
	if len(upstreams) == 0 {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --enroll-proxy-listen is set but "+
			"--enroll-proxy-upstream is not; the proxy has nowhere to forward to and will not start")
		return func() {}
	}
	pool, err := enrollproxy.NewPool(upstreams, nil, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: enrolment proxy:", err)
		return func() {}
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           pool,
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fmt.Printf("trstctl-agent: enrolment proxy serving on %s -> %v\n", listen, upstreams)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "trstctl-agent: enrolment proxy stopped:", err)
		}
	}()
	enrollProxyPool.Store(pool)
	return func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
	}
}

// enrollProxyPool holds the running pool so the heartbeat can report its health.
var enrollProxyPool atomic.Pointer[enrollproxy.Pool]

// startRevocationCache serves the control plane's CRL to this segment (epic R3).
//
// Returns a stop function that is always safe to call. A configuration problem
// is reported and does not bring the agent down: revocation caching is additive,
// and an operator who mistyped a URL should not also lose this segment's
// enrolment proxy and connector deploys.
func startRevocationCache(ctx context.Context, o agentOptions) func() {
	listen := strings.TrimSpace(o.revCacheListen)
	if listen == "" {
		return func() {}
	}
	upstream := strings.TrimSpace(o.revCacheUpstream)
	issuerPath := strings.TrimSpace(o.revCacheIssuer)
	if upstream == "" || issuerPath == "" {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --crl-cache-listen needs both --crl-cache-upstream "+
			"and --crl-cache-issuer; without the issuer the relay cannot tell a CRL from anything "+
			"else it might be handed, so the cache will not start")
		return func() {}
	}
	issuerPEM, err := os.ReadFile(issuerPath) // #nosec G304 -- operator-supplied issuer path (CWE-22)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: read CRL cache issuer:", err)
		return func() {}
	}
	issuerDER, err := mtls.FirstCertDER(issuerPEM)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: CRL cache issuer is not a certificate:", err)
		return func() {}
	}
	cache, err := revcache.New(upstream, issuerDER, revcache.Options{
		Grace:  o.revCacheGrace,
		Client: netsec.SafeClient(30 * time.Second),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: CRL cache:", err)
		return func() {}
	}

	// Fetch once at start so the segment is covered immediately rather than
	// after the first refresh interval — a relay that came up serving nothing
	// for a minute would look identical to one that is broken.
	if err := cache.Refresh(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: initial CRL fetch:", err)
	}

	srv := &http.Server{Addr: listen, Handler: cache, ReadHeaderTimeout: 10 * time.Second}
	refreshCtx, cancelRefresh := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fmt.Printf("trstctl-agent: CRL cache serving on %s from %s\n", listen, upstream)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "trstctl-agent: CRL cache stopped:", err)
		}
	}()
	go func() {
		// Refresh well inside a typical CRL lifetime. The cost of an extra fetch
		// is one request; the cost of missing one is a segment that fails closed
		// and looks like an outage.
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-t.C:
				if err := cache.Refresh(refreshCtx); err != nil && refreshCtx.Err() == nil {
					fmt.Fprintln(os.Stderr, "trstctl-agent: CRL refresh:", err)
				}
			}
		}
	}()
	revocationCache.Store(cache)
	return func() {
		cancelRefresh()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
	}
}

// revocationCache holds the running cache so the heartbeat can report freshness.
var revocationCache atomic.Pointer[revcache.Cache]
