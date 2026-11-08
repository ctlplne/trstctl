// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/sessionobserve"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Host TLS session observer (X5). An agent holding the session-observer role
// and started with --observe-tls-sessions attaches probes to this host's
// OpenSSL 3 libraries and reports what each TLS handshake on the host
// negotiated, with the peer's certificate; the server refuses these reports
// from any other agent, and the agent detaches the probes as soon as a
// renewed certificate no longer carries the role.
var (
	observeTLSSessions = flag.Bool("observe-tls-sessions", false,
		"attach probes to this host's OpenSSL 3 libraries and report each TLS handshake's version, cipher suite, key-exchange group and peer certificate; needs the session-observer role, Linux 5.17 or later on x86-64 or arm64, BPF privileges (CAP_BPF and CAP_PERFMON) and the host PID namespace. Only handshake metadata is read, never application data")
	observeTLSLibraries = flag.String("observe-tls-libraries", "",
		"the libssl.so.3 and libcrypto.so.3 to probe, as LIBSSL,LIBCRYPTO (default: the pair found in the usual library directories)")
	observeTLSReportInterval = flag.Duration("observe-tls-report-interval", time.Minute,
		"how often the session observer reports what it saw")
)

// sessionRoleCheck is how often the observer rechecks the agent's roles.
const sessionRoleCheck = 5 * time.Second

// sessionObserver is what the agent keeps attached: the probes.
type sessionObserver interface {
	RingDrops() uint64
	Close() error
}

// startSessionObserver begins host session observation when it is configured;
// the returned function stops it.
func startSessionObserver(ctx context.Context, a *agent.Agent, ch agent.ChannelClient) func() {
	if !*observeTLSSessions {
		return func() {}
	}
	libs, err := sessionLibraries(*observeTLSLibraries)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: session observer:", err)
		return func() {}
	}
	open := func(asm *sessionobserve.Assembler) (sessionObserver, error) { return sessionobserve.Open(libs, asm) }
	report := func(ctx context.Context, findings []agent.InventoryFinding) error {
		resp, err := a.ReportInventory(ctx, ch, discovery.SourceTLSSessionObserver, findings)
		if err != nil {
			return err
		}
		fmt.Printf("trstctl-agent: reported %d TLS sessions (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
		return nil
	}
	return runSessionObserver(ctx, a.Roles, open, report, *observeTLSReportInterval, sessionRoleCheck, os.Stderr)
}

func sessionLibraries(raw string) (sessionobserve.Libraries, error) {
	if strings.TrimSpace(raw) == "" {
		return sessionobserve.DefaultLibraries()
	}
	parts := splitList(raw)
	if len(parts) != 2 {
		return sessionobserve.Libraries{}, errors.New("--observe-tls-libraries takes LIBSSL,LIBCRYPTO")
	}
	return sessionobserve.Libraries{SSL: parts[0], Crypto: parts[1]}, nil
}

// runSessionObserver refuses without the session-observer role; with it, it
// attaches the probes, reports what they saw every interval, and detaches them
// once a role check finds the role gone. The returned function detaches them
// and waits for the loop.
func runSessionObserver(ctx context.Context, roles func() []string, open func(*sessionobserve.Assembler) (sessionObserver, error),
	report func(context.Context, []agent.InventoryFinding) error, interval, roleCheck time.Duration, log io.Writer) func() {
	say := func(a ...any) { _, _ = fmt.Fprintln(log, a...) }
	if !agentCarriesRole(roles(), mtls.AgentRoleSessionObserver) {
		say("trstctl-agent: --observe-tls-sessions needs the session-observer role; this agent was not granted it, so no probe is attached")
		return func() {}
	}
	roleGone := func() bool {
		if agentCarriesRole(roles(), mtls.AgentRoleSessionObserver) {
			return false
		}
		say("trstctl-agent: this agent's certificate no longer carries the session-observer role; the probes are detached")
		return true
	}
	agg := sessionobserve.NewAggregate(4096)
	asm := sessionobserve.NewAssembler(4096, agg.Add)
	obs, err := open(asm)
	if err != nil {
		say("trstctl-agent: session observer:", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	var once sync.Once
	detach := func() {
		once.Do(func() {
			if err := obs.Close(); err != nil {
				say("trstctl-agent: session observer: detach:", err)
			}
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer detach()
		reports := time.NewTicker(interval)
		defer reports.Stop()
		checks := time.NewTicker(roleCheck)
		defer checks.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-checks.C:
				if roleGone() {
					return
				}
			case <-reports.C:
				if roleGone() {
					return
				}
				items, dropped := agg.Changed()
				if len(items) == 0 {
					continue
				}
				stats := asm.Stats()
				stats.RingDrops = obs.RingDrops()
				if err := report(ctx, sessionFindings(items, stats, dropped)); err != nil {
					say("trstctl-agent: TLS session report failed:", err)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// sessionFindings turns aggregated sessions into inventory findings: one per
// process, side, server name, negotiated facts and peer certificate.
func sessionFindings(items []sessionobserve.Item, stats sessionobserve.Stats, dropped uint64) []agent.InventoryFinding {
	drops := stats.RingDrops + stats.Gaps + stats.TableFull + stats.OutOfStep + dropped
	out := make([]agent.InventoryFinding, 0, len(items))
	for _, item := range items {
		obs := item.Obs
		meta := map[string]string{
			"process":                  item.Process,
			"executable":               item.Executable,
			"side":                     item.Side,
			"protocol":                 "tls",
			"tls_version":              obs.TLSVersion,
			"cipher_suite":             obs.CipherSuite,
			"group":                    obs.Group,
			"offered_groups":           strings.Join(obs.OfferedGroups, ","),
			"server_name":              obs.ServerName,
			"hello_retry":              strconv.FormatBool(item.HelloRetry),
			"sessions":                 strconv.FormatUint(item.Sessions, 10),
			"first_seen":               item.FirstSeen.UTC().Format(time.RFC3339),
			"last_seen":                item.LastSeen.UTC().Format(time.RFC3339),
			"application_data_read":    "false",
			"pq_hybrid":                strconv.FormatBool(obs.PQHybrid()),
			"peer_certificate_visible": strconv.FormatBool(item.Peer != nil),
			"observer_drops":           strconv.FormatUint(drops, 10),
		}
		fingerprint := ""
		if p := item.Peer; p != nil {
			fingerprint = p.SHA256
			meta["peer_certificate_key_algorithm"] = p.KeyAlgorithm
			meta["peer_certificate_key_bits"] = strconv.Itoa(p.PublicKeyBits)
			meta["peer_certificate_not_after"] = p.NotAfter.Format(time.RFC3339)
		}
		risk := 30
		switch {
		case obs.TLSVersion != "TLSv1.2" && obs.TLSVersion != "TLSv1.3":
			risk = 70
		case obs.PQHybrid():
			risk = 10
		}
		who := item.Executable
		if who == "" {
			who = item.Process
		}
		out = append(out, agent.InventoryFinding{
			Kind: "tls_session", Ref: item.Ref, Provenance: discovery.SourceTLSSessionObserver + ":" + who,
			Fingerprint: fingerprint, RiskScore: risk, Metadata: meta,
		})
	}
	return out
}
