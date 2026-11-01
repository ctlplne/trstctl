// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/observe"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Passive network crypto observer (X1). An agent holding the observer role
// watches an interface and reports what each connection's handshake states in
// the clear; the server refuses observations from any other agent.
var (
	observeInterface = flag.String("observe-interface", "",
		"network interface (a mirror or span port, or this host's interface) whose connections' handshakes the agent observes passively; needs the observer role and, on Linux, CAP_NET_RAW. Only handshake metadata is kept, never payload")
	observePorts = flag.String("observe-ports", "443,8443,636,993,995,465,22,80,389,5432,3306",
		"comma-separated server ports whose connections are observed (at most 32)")
	observeMaxFlows = flag.Int("observe-max-flows", 2048,
		"connections followed at once; more are counted and skipped, never buffered")
	observeReportInterval = flag.Duration("observe-report-interval", time.Minute,
		"how often the observer reports what it saw")
)

// observerSourceKind is the inventory source kind observations are reported under.
const observerSourceKind = "network-observer"

// startObserver begins passive observation when it is configured and the
// agent holds the observer role; the returned function stops it.
func startObserver(ctx context.Context, a *agent.Agent, ch agent.ChannelClient) func() {
	iface := strings.TrimSpace(*observeInterface)
	if iface == "" {
		return func() {}
	}
	if !agentCarriesRole(a.Roles(), mtls.AgentRoleObserver) {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --observe-interface needs the observer role; this agent was not granted it, so nothing is observed")
		return func() {}
	}
	ports, err := parsePorts(*observePorts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: observer:", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	agg := observe.NewAggregate(4096)
	asm := observe.NewAssembler(ports, *observeMaxFlows, 30*time.Second, agg.Add)
	go func() {
		err := observe.Capture(ctx, iface, ports, 2048, asm)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: observer stopped:", err)
		}
	}()
	go func() {
		ticker := time.NewTicker(*observeReportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := reportObservations(ctx, a, ch, iface, agg, asm.Stats()); err != nil {
					fmt.Fprintln(os.Stderr, "trstctl-agent: observation report failed:", err)
				}
			}
		}
	}()
	return cancel
}

func parsePorts(raw string) ([]uint16, error) {
	var ports []uint16
	for _, field := range splitList(raw) {
		p, err := strconv.ParseUint(field, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("observe port %q is not a TCP port", field)
		}
		ports = append(ports, uint16(p))
	}
	if len(ports) == 0 || len(ports) > observe.MaxWatchedPorts {
		return nil, fmt.Errorf("observe ports: give 1 to %d ports", observe.MaxWatchedPorts)
	}
	return ports, nil
}

func reportObservations(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, iface string, agg *observe.Aggregate, stats observe.Stats) error {
	items, dropped := agg.Changed()
	if len(items) == 0 {
		return nil
	}
	cpu, heap := observe.Footprint()
	findings := observationFindings(iface, items, stats, dropped, footprint{cpuSeconds: cpu, heapBytes: heap})
	resp, err := a.ReportInventory(ctx, ch, observerSourceKind, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d observations (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	return nil
}

// footprint is the observer process's own cost, reported with every batch so
// the budget is visible next to what was observed.
type footprint struct {
	cpuSeconds float64
	heapBytes  uint64
}

// observationFindings turns aggregated items into inventory findings: one per
// endpoint and handshake facts, never payload.
func observationFindings(iface string, items []observe.Item, stats observe.Stats, dropped uint64, cost footprint) []agent.InventoryFinding {
	out := make([]agent.InventoryFinding, 0, len(items))
	for _, item := range items {
		obs := item.Obs
		meta := map[string]string{
			"interface":       iface,
			"server":          item.Server.String(),
			"protocol":        obs.Protocol,
			"connections":     strconv.FormatUint(item.Connections, 10),
			"clients":         strconv.Itoa(item.Clients),
			"first_seen":      item.FirstSeen.UTC().Format(time.RFC3339),
			"last_seen":       item.LastSeen.UTC().Format(time.RFC3339),
			"payload_stored":  "false",
			"pq_hybrid":       strconv.FormatBool(obs.PQHybrid()),
			"observer_flows":  strconv.Itoa(stats.ActiveFlows),
			"observer_drops":  strconv.FormatUint(stats.TableFull+stats.OutOfOrder+dropped, 10),
			"observer_cpu_s":  strconv.FormatFloat(cost.cpuSeconds, 'f', 3, 64),
			"observer_heap_b": strconv.FormatUint(cost.heapBytes, 10),
		}
		risk := 30
		fingerprint := ""
		switch item.Kind {
		case "plaintext_protocol":
			meta["plaintext_kind"] = obs.PlaintextKind
			risk = 90
		case "ssh_kex":
			meta["kex_algorithm"], meta["host_key_algorithm"], meta["ssh_cipher"] = obs.KexAlgorithm, obs.HostKeyAlgorithm, obs.SSHCipher
			meta["ssh_server"] = obs.SSHServer
			if obs.PQHybrid() {
				risk = 10
			}
		default:
			meta["tls_version"], meta["cipher_suite"], meta["group"] = obs.TLSVersion, obs.CipherSuite, obs.Group
			meta["server_name"] = obs.ServerName
			meta["certificate_visible"] = strconv.FormatBool(item.Certificate != nil)
			if c := item.Certificate; c != nil {
				fingerprint = c.SHA256
				meta["certificate_key_algorithm"] = c.KeyAlgorithm
				meta["certificate_key_bits"] = strconv.Itoa(c.PublicKeyBits)
				meta["certificate_not_after"] = c.NotAfter.Format(time.RFC3339)
			}
			switch {
			case obs.TLSVersion != "TLSv1.2" && obs.TLSVersion != "TLSv1.3":
				risk = 70
			case obs.PQHybrid():
				risk = 10
			}
		}
		out = append(out, agent.InventoryFinding{
			Kind: item.Kind, Ref: item.Ref, Provenance: observerSourceKind + ":" + iface,
			Fingerprint: fingerprint, RiskScore: risk, Metadata: meta,
		})
	}
	return out
}
