// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/agent/enrollproxy"
	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/revcacheposture"

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

// startEnrollProxy serves the LAN-local enrollment proxy, if configured.
//
// Returns a report function and a stop function that are always safe to call. A failure to bind is
// reported and does NOT bring the agent down: the proxy is one of several things
// this process does, and an address already in use must not also stop this
// segment's connector deploys and inventory.
func startEnrollProxy(ctx context.Context, o agentOptions, client *http.Client) (func() *transport.EnrollmentProxyReport, func()) {
	_ = ctx
	listen := strings.TrimSpace(o.enrollProxyListen)
	segment := strings.TrimSpace(o.enrollProxySegment)
	publicURL := strings.TrimSpace(o.enrollProxyPublicURL)
	notServing := func() *transport.EnrollmentProxyReport {
		return &transport.EnrollmentProxyReport{Serving: false, Segment: segment, PublicURL: publicURL}
	}
	if listen == "" {
		return notServing, func() {}
	}
	upstreams := splitList(o.enrollProxyUpstream)
	if len(upstreams) == 0 {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --enroll-proxy-listen is set but "+
			"--enroll-proxy-upstream is not; the proxy has nowhere to forward to and will not start")
		return notServing, func() {}
	}
	if segment == "" || publicURL == "" {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --enroll-proxy-listen requires both "+
			"--enroll-proxy-segment and --enroll-proxy-public-url; without them redundant relays cannot share a stable ACME authority or produce an explicit topology")
		return notServing, func() {}
	}
	pool, err := enrollproxy.NewPoolWithPublicURL(upstreams, publicURL, client, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: enrollment proxy:", err)
		return notServing, func() {}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: enrollment proxy cannot bind:", err)
		return notServing, func() {}
	}
	srv := &http.Server{
		Handler:           pool,
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	var serving atomic.Bool
	serving.Store(true)
	go func() {
		defer close(done)
		defer serving.Store(false)
		fmt.Printf("trstctl-agent: enrollment proxy serving segment %s at %s on %s -> %v\n", segment, publicURL, listener.Addr(), upstreams)
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "trstctl-agent: enrollment proxy stopped:", err)
		}
	}()
	enrollProxyPool.Store(pool)
	report := func() *transport.EnrollmentProxyReport {
		health := pool.Health()
		out := &transport.EnrollmentProxyReport{
			Serving: serving.Load(), Segment: segment, PublicURL: publicURL,
			HealthyUpstreams: health.Healthy, UnhealthyUpstreams: health.Unhealthy, UnknownUpstreams: health.Unknown,
			UpstreamFailures: int64(health.Failures), ForwardedRequests: health.Forwarded,
			RefusedRequests: health.Refused,
		}
		if !health.LastForwardedAt.IsZero() {
			at := health.LastForwardedAt
			out.LastForwardedAt = &at
		}
		if !health.LastFailoverAt.IsZero() {
			at := health.LastFailoverAt
			out.LastFailoverAt = &at
		}
		return out
	}
	stop := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
		enrollProxyPool.CompareAndSwap(pool, nil)
	}
	return report, stop
}

// enrollProxyPool holds the running pool so the heartbeat can report its health.
var enrollProxyPool atomic.Pointer[enrollproxy.Pool]

// revocationCacheFile is the operator-owned multi-issuer runtime description.
// IssuerFile contains only a public certificate. Upstream URLs may be internal,
// but credentials in URLs are rejected by the cache manager.
type revocationCacheFile struct {
	Listen          string                      `json:"listen"`
	Segment         string                      `json:"segment"`
	RefreshInterval string                      `json:"refresh_interval,omitempty"`
	Issuers         []revocationCacheFileIssuer `json:"issuers"`
}

type revocationCacheFileIssuer struct {
	ID         string                   `json:"id"`
	IssuerFile string                   `json:"issuer_file"`
	CRL        *revocationCacheFileCRL  `json:"crl,omitempty"`
	OCSP       *revocationCacheFileOCSP `json:"ocsp,omitempty"`
}

type revocationCacheFileCRL struct {
	UpstreamURL string `json:"upstream_url"`
	LocalPath   string `json:"local_path"`
	Grace       string `json:"grace,omitempty"`
}

type revocationCacheFileOCSP struct {
	UpstreamURL string `json:"upstream_url"`
	LocalPath   string `json:"local_path"`
}

func revocationCacheConfigured(o agentOptions) bool {
	return strings.TrimSpace(o.revCacheConfig) != "" || strings.TrimSpace(o.revCacheListen) != ""
}

// startRevocationCache starts all configured issuer caches before the first
// heartbeat and returns the live metadata snapshot that heartbeat signs.
func startRevocationCache(ctx context.Context, o agentOptions) (func() []revcacheposture.Entry, func()) {
	if !revocationCacheConfigured(o) {
		return nil, func() {}
	}
	listen, refreshEvery, cfg, err := loadRevocationCacheConfig(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: revocation cache configuration:", err)
		return nil, func() {}
	}
	client := o.revCacheHTTPClient
	if client == nil {
		client = netsec.SafeClientWithOptions(30*time.Second, netsec.SafeClientOptions{
			AllowPrivateCIDRs: rfc1918AndULA(),
		})
	}
	manager, err := revcache.NewManager(cfg, revcache.ManagerOptions{Client: client})
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: revocation cache:", err)
		return nil, func() {}
	}
	if err := manager.RefreshCRLs(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: initial CRL cache refresh:", err)
	}
	listener := o.revCacheListener
	if listener == nil {
		listener, err = net.Listen("tcp", listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: revocation cache cannot bind:", err)
			return nil, func() {}
		}
	}
	srv := &http.Server{Handler: manager, ReadHeaderTimeout: 10 * time.Second}
	refreshCtx, cancelRefresh := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fmt.Printf("trstctl-agent: CRL/OCSP cache serving segment %s on %s (%d cache routes)\n",
			cfg.Segment, listener.Addr(), len(manager.Statuses()))
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "trstctl-agent: revocation cache stopped:", err)
		}
	}()
	go func() {
		ticker := time.NewTicker(refreshEvery)
		defer ticker.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				if err := manager.RefreshCRLs(refreshCtx); err != nil && refreshCtx.Err() == nil {
					fmt.Fprintln(os.Stderr, "trstctl-agent: CRL cache refresh:", err)
				}
			}
		}
	}()
	report := func() []revcacheposture.Entry { return manager.Statuses() }
	stop := func() {
		cancelRefresh()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
	}
	return report, stop
}

func loadRevocationCacheConfig(o agentOptions) (string, time.Duration, revcache.ManagerConfig, error) {
	if path := strings.TrimSpace(o.revCacheConfig); path != "" {
		if strings.TrimSpace(o.revCacheListen) != "" || strings.TrimSpace(o.revCacheUpstream) != "" || strings.TrimSpace(o.revCacheIssuer) != "" {
			return "", 0, revcache.ManagerConfig{}, errors.New("--revocation-cache-config cannot be combined with legacy --crl-cache-* flags")
		}
		file, err := os.Open(path) // #nosec G304 -- operator-supplied runtime configuration path (CWE-22)
		if err != nil {
			return "", 0, revcache.ManagerConfig{}, err
		}
		defer func() { _ = file.Close() }()
		raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
		if err != nil || len(raw) > 1<<20 {
			return "", 0, revcache.ManagerConfig{}, errors.New("revocation cache configuration is unreadable or exceeds 1 MiB")
		}
		var disk revocationCacheFile
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&disk); err != nil {
			return "", 0, revcache.ManagerConfig{}, fmt.Errorf("decode JSON: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return "", 0, revcache.ManagerConfig{}, errors.New("configuration contains trailing JSON")
		}
		refreshEvery := 15 * time.Minute
		if strings.TrimSpace(disk.RefreshInterval) != "" {
			refreshEvery, err = time.ParseDuration(disk.RefreshInterval)
			if err != nil || refreshEvery < time.Minute || refreshEvery > 24*time.Hour {
				return "", 0, revcache.ManagerConfig{}, errors.New("refresh_interval must be between 1m and 24h")
			}
		}
		cfg := revcache.ManagerConfig{Segment: disk.Segment}
		for _, source := range disk.Issuers {
			issuerPEM, err := os.ReadFile(source.IssuerFile) // #nosec G304 -- operator-supplied public issuer certificate (CWE-22)
			if err != nil {
				return "", 0, revcache.ManagerConfig{}, fmt.Errorf("read issuer %q: %w", source.ID, err)
			}
			issuerDER, err := mtls.FirstCertDER(issuerPEM)
			if err != nil {
				return "", 0, revcache.ManagerConfig{}, fmt.Errorf("issuer %q is not a certificate: %w", source.ID, err)
			}
			entry := revcache.IssuerConfig{ID: source.ID, IssuerDER: issuerDER}
			if source.CRL != nil {
				grace := time.Duration(0)
				if strings.TrimSpace(source.CRL.Grace) != "" {
					grace, err = time.ParseDuration(source.CRL.Grace)
					if err != nil || grace < 0 || grace > 24*time.Hour {
						return "", 0, revcache.ManagerConfig{}, fmt.Errorf("issuer %q CRL grace must be between 0 and 24h", source.ID)
					}
				}
				entry.CRL = &revcache.CRLConfig{UpstreamURL: source.CRL.UpstreamURL, LocalPath: source.CRL.LocalPath, Grace: grace}
			}
			if source.OCSP != nil {
				entry.OCSP = &revcache.OCSPConfig{UpstreamURL: source.OCSP.UpstreamURL, LocalPath: source.OCSP.LocalPath}
			}
			cfg.Issuers = append(cfg.Issuers, entry)
		}
		return strings.TrimSpace(disk.Listen), refreshEvery, cfg, nil
	}

	if strings.TrimSpace(o.revCacheSegment) == "" {
		return "", 0, revcache.ManagerConfig{}, errors.New("legacy --crl-cache-listen requires --revocation-cache-segment")
	}
	issuerPEM, err := os.ReadFile(strings.TrimSpace(o.revCacheIssuer)) // #nosec G304 -- operator-supplied public issuer certificate (CWE-22)
	if err != nil {
		return "", 0, revcache.ManagerConfig{}, fmt.Errorf("read legacy CRL issuer: %w", err)
	}
	issuerDER, err := mtls.FirstCertDER(issuerPEM)
	if err != nil {
		return "", 0, revcache.ManagerConfig{}, fmt.Errorf("legacy CRL issuer is not a certificate: %w", err)
	}
	return strings.TrimSpace(o.revCacheListen), 15 * time.Minute, revcache.ManagerConfig{
		Segment: strings.TrimSpace(o.revCacheSegment),
		Issuers: []revcache.IssuerConfig{{ID: "default", IssuerDER: issuerDER,
			CRL: &revcache.CRLConfig{UpstreamURL: strings.TrimSpace(o.revCacheUpstream), LocalPath: "/crl/default", Grace: o.revCacheGrace}}},
	}, nil
}
