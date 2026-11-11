// SPDX-License-Identifier: BUSL-1.1

package netpath

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// GCP evaluation (A167-L1). A Compute Engine instance is reachable at its
// external address when the VPC network routes the internet's traffic back
// through the default internet gateway and an ingress firewall rule admits the
// internet to the port. Firewall rules are stateful, so only ingress is
// judged; every VPC network carries an implied rule denying all ingress at
// the lowest priority. As for AWS, only a rule naming the internet-wide range
// decides: one that admits a partner range does not make the instance
// internet-reachable.

// StageFirewall names a VPC firewall rule (or the implied ingress deny) that
// stopped the path.
const StageFirewall Stage = "firewall"

// DefaultInternetGateway is the next hop a GCP route names to send traffic to
// the internet.
const DefaultInternetGateway = "default-internet-gateway"

// GCPInstance is the instance whose network interface holds the external
// address.
type GCPInstance struct {
	Name            string
	Network         string // the network's name (last path segment of its URL)
	Tags            []string
	ServiceAccounts []string
}

// GCPProtocolPorts is one allowed or denied entry of a firewall rule.
type GCPProtocolPorts struct {
	Protocol string   // "tcp", "udp", "all", or a protocol number
	Ports    []string // "443", "8000-9000"; empty means every port
}

// GCPFirewall is one VPC firewall rule.
type GCPFirewall struct {
	Name                  string
	Network               string
	Direction             string // "INGRESS" or "EGRESS"
	Priority              int
	Disabled              bool
	SourceRanges          []string
	TargetTags            []string
	TargetServiceAccounts []string
	Allowed               []GCPProtocolPorts
	Denied                []GCPProtocolPorts
}

// GCPRoute is one route of the VPC network.
type GCPRoute struct {
	Name           string
	Network        string
	DestRange      string
	Priority       int
	NextHopGateway string // the gateway's name, e.g. default-internet-gateway; empty for other next hops
	Tags           []string
}

// GCPConfig is what Compute Engine reported for the path to one instance.
type GCPConfig struct {
	Instance  GCPInstance
	Firewalls []GCPFirewall
	Routes    []GCPRoute
}

// EvaluateGCP decides whether the internet reaches ip:port over TCP on the
// instance the configuration describes.
func EvaluateGCP(ip netip.Addr, port int, cfg GCPConfig) Result {
	internet := "0.0.0.0/0"
	if ip.Is6() && !ip.Is4In6() {
		internet = "::/0"
	}
	inst := cfg.Instance
	var chosen *GCPRoute
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		if route.Network != inst.Network || route.DestRange != internet || !gcpTagsApply(route.Tags, inst.Tags) {
			continue
		}
		if chosen == nil || route.Priority < chosen.Priority {
			chosen = route
		}
	}
	if chosen == nil {
		return Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: inst.Network,
			Reason: "network " + inst.Network + " has no route from " + internet + " that applies to " + inst.Name}
	}
	if chosen.NextHopGateway != DefaultInternetGateway {
		return Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: chosen.Name,
			Reason: "route " + chosen.Name + " sends " + internet + " to a next hop other than the default internet gateway"}
	}
	type decision struct {
		rule  GCPFirewall
		allow bool
	}
	var candidates []decision
	for _, rule := range cfg.Firewalls {
		if rule.Disabled || rule.Network != inst.Network || !strings.EqualFold(rule.Direction, "INGRESS") ||
			!containsString(rule.SourceRanges, internet) || !gcpTargetsApply(rule, inst) {
			continue
		}
		if gcpEntriesMatch(rule.Denied, port) {
			candidates = append(candidates, decision{rule: rule, allow: false})
		}
		if gcpEntriesMatch(rule.Allowed, port) {
			candidates = append(candidates, decision{rule: rule, allow: true})
		}
	}
	// Lower priority numbers win; at one priority a deny wins over an allow.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rule.Priority != candidates[j].rule.Priority {
			return candidates[i].rule.Priority < candidates[j].rule.Priority
		}
		return !candidates[i].allow && candidates[j].allow
	})
	if len(candidates) == 0 {
		return Result{Verdict: Blocked, BlockedBy: StageFirewall, Resource: inst.Network, Rule: "implied deny ingress (priority 65535)",
			Reason: "no firewall rule on network " + inst.Network + " admits tcp/" + strconv.Itoa(port) + " from " + internet + " to " + inst.Name}
	}
	first := candidates[0]
	rule := "priority " + strconv.Itoa(first.rule.Priority)
	if !first.allow {
		return Result{Verdict: Blocked, BlockedBy: StageFirewall, Resource: first.rule.Name, Rule: rule,
			Reason: "firewall rule " + first.rule.Name + " denies tcp/" + strconv.Itoa(port) + " from " + internet}
	}
	return Result{Verdict: Open, Resource: first.rule.Name, Rule: rule,
		Path:   []string{inst.Name, first.rule.Name, chosen.Name, DefaultInternetGateway},
		Reason: "firewall rule " + first.rule.Name + " admits tcp/" + strconv.Itoa(port) + " from " + internet}
}

// gcpTagsApply: a route with no tags applies to every instance; one with tags
// to an instance carrying any of them.
func gcpTagsApply(routeTags, instanceTags []string) bool {
	if len(routeTags) == 0 {
		return true
	}
	for _, tag := range routeTags {
		if containsString(instanceTags, tag) {
			return true
		}
	}
	return false
}

// gcpTargetsApply: a rule with no targets applies to every instance in the
// network; one with target tags or service accounts to an instance carrying
// one of them.
func gcpTargetsApply(rule GCPFirewall, inst GCPInstance) bool {
	if len(rule.TargetTags) == 0 && len(rule.TargetServiceAccounts) == 0 {
		return true
	}
	for _, tag := range rule.TargetTags {
		if containsString(inst.Tags, tag) {
			return true
		}
	}
	for _, account := range rule.TargetServiceAccounts {
		if containsString(inst.ServiceAccounts, account) {
			return true
		}
	}
	return false
}

// gcpEntriesMatch reports whether any entry covers tcp/port.
func gcpEntriesMatch(entries []GCPProtocolPorts, port int) bool {
	for _, entry := range entries {
		switch strings.ToLower(entry.Protocol) {
		case "all":
			return true
		case "tcp", "6":
		default:
			continue
		}
		if len(entry.Ports) == 0 {
			return true
		}
		for _, spec := range entry.Ports {
			if portSpecMatches(spec, port) {
				return true
			}
		}
	}
	return false
}

// portSpecMatches reports whether a port ("443") or an inclusive port range
// ("8000-9000") covers port.
func portSpecMatches(spec string, port int) bool {
	lo, hi, ok := strings.Cut(spec, "-")
	from, err1 := strconv.Atoi(strings.TrimSpace(lo))
	to := from
	var err2 error
	if ok {
		to, err2 = strconv.Atoi(strings.TrimSpace(hi))
	}
	return err1 == nil && err2 == nil && port >= from && port <= to
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
