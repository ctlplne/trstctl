// SPDX-License-Identifier: BUSL-1.1

// Package netpath answers, from a cloud provider's own network configuration,
// whether the internet can reach one public address and port (A167): the
// provider-native half of exposure validation. A live probe (A102) shows that
// something answered; this shows why the cloud lets it, or which resource
// stops it, without sending a packet to the endpoint.
//
// The evaluation is deliberately about the internet at large. A rule that
// admits one partner range does not make an endpoint internet-reachable, and a
// rule that admits 0.0.0.0/0 does, whatever narrower rules sit beside it. The
// verdict names the resource that decided it so an operator can go straight to
// the rule.
package netpath

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Verdict is the outcome for one endpoint.
type Verdict string

const (
	// Open: the provider's configuration admits the internet to the address
	// and port along the path the evaluation describes.
	Open Verdict = "open"
	// Blocked: a named resource stops the internet before the endpoint.
	Blocked Verdict = "blocked"
	// NotInAccount: no network interface in the account and region holds the
	// public address, so this account's configuration says nothing about it.
	NotInAccount Verdict = "not_in_account"
	// Unknown: the provider could not be asked, or answered incompletely. It is
	// never read as open or as blocked.
	Unknown Verdict = "unknown"
)

// Stage names which part of the path decided a blocked verdict.
type Stage string

const (
	StageRoute         Stage = "route"
	StageNetworkACL    Stage = "network_acl"
	StageNetworkACLOut Stage = "network_acl_return"
	StageSecurityGroup Stage = "security_group"
)

// Result is the verdict for one public address and port.
type Result struct {
	Verdict Verdict `json:"status"`
	// BlockedBy and Resource name the stage and the resource (route table,
	// network ACL or security groups) that stopped the path.
	BlockedBy Stage  `json:"blocked_by,omitempty"`
	Resource  string `json:"resource,omitempty"`
	// Rule is the network ACL rule number or security group rule that decided.
	Rule string `json:"rule,omitempty"`
	// Path lists the resources an open path crosses, interface first.
	Path   []string `json:"path,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// Interface is the provider network interface holding a public address.
type Interface struct {
	ID             string
	SubnetID       string
	VPCID          string
	SecurityGroups []string
}

// Route is one route of the table the interface's subnet uses.
type Route struct {
	Destination string // CIDR
	Target      string // igw-…, nat-…, local, tgw-…
	Active      bool
}

// RouteTable is the table that applies to the subnet.
type RouteTable struct {
	ID     string
	Routes []Route
}

// ACLEntry is one network ACL rule.
type ACLEntry struct {
	Number   int
	Egress   bool
	Protocol string // "6" tcp, "17" udp, "-1" all
	Allow    bool
	CIDR     string
	FromPort int
	ToPort   int
}

// NetworkACL is the subnet's network ACL.
type NetworkACL struct {
	ID      string
	Entries []ACLEntry
}

// Permission is one inbound security group permission.
type Permission struct {
	Protocol string // "tcp", "udp", "-1"
	FromPort int
	ToPort   int
	CIDRs    []string
}

// SecurityGroup is one group attached to the interface.
type SecurityGroup struct {
	ID      string
	Inbound []Permission
}

// Config is what the provider reported for the path to one interface.
type Config struct {
	Interface      Interface
	RouteTable     *RouteTable
	NetworkACL     *NetworkACL
	SecurityGroups []SecurityGroup
}

// ephemeralReturnPort is the port a network ACL must let replies leave on:
// stateless ACLs judge the return packet separately, and 49152 sits inside the
// Linux, Windows and load balancer ephemeral ranges alike.
const ephemeralReturnPort = 49152

// Evaluate decides whether the internet reaches ip:port over TCP through the
// reported configuration. Stages are checked in the order a packet meets them.
func Evaluate(ip netip.Addr, port int, cfg Config) Result {
	internet := "0.0.0.0/0"
	if ip.Is6() && !ip.Is4In6() {
		internet = "::/0"
	}
	if cfg.RouteTable == nil || cfg.NetworkACL == nil {
		return Result{Verdict: Unknown, Reason: "the provider did not report the subnet's route table and network ACL"}
	}
	gateway := ""
	for _, route := range cfg.RouteTable.Routes {
		if route.Active && route.Destination == internet && strings.HasPrefix(route.Target, "igw-") {
			gateway = route.Target
		}
	}
	if gateway == "" {
		return Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: cfg.RouteTable.ID,
			Reason: "the subnet's route table has no route from " + internet + " to an internet gateway"}
	}
	if rule, allowed, found := firstACLDecision(cfg.NetworkACL.Entries, false, internet, port); !found || !allowed {
		return Result{Verdict: Blocked, BlockedBy: StageNetworkACL, Resource: cfg.NetworkACL.ID, Rule: rule,
			Reason: "the subnet's network ACL denies inbound tcp/" + strconv.Itoa(port) + " from " + internet}
	}
	if rule, allowed, found := firstACLDecision(cfg.NetworkACL.Entries, true, internet, ephemeralReturnPort); !found || !allowed {
		return Result{Verdict: Blocked, BlockedBy: StageNetworkACLOut, Resource: cfg.NetworkACL.ID, Rule: rule,
			Reason: "the subnet's network ACL denies the return traffic to " + internet + " on ephemeral ports"}
	}
	for _, group := range cfg.SecurityGroups {
		for i, permission := range group.Inbound {
			if permits(permission, internet, port) {
				return Result{Verdict: Open, Resource: group.ID, Rule: "inbound[" + strconv.Itoa(i) + "]",
					Path:   []string{cfg.Interface.ID, group.ID, cfg.NetworkACL.ID, cfg.RouteTable.ID, gateway},
					Reason: "security group " + group.ID + " admits tcp/" + strconv.Itoa(port) + " from " + internet}
			}
		}
	}
	ids := make([]string, 0, len(cfg.SecurityGroups))
	for _, group := range cfg.SecurityGroups {
		ids = append(ids, group.ID)
	}
	sort.Strings(ids)
	return Result{Verdict: Blocked, BlockedBy: StageSecurityGroup, Resource: strings.Join(ids, ","),
		Reason: "no security group on " + cfg.Interface.ID + " admits tcp/" + strconv.Itoa(port) + " from " + internet}
}

// firstACLDecision returns the first rule, in rule-number order, that matches
// the direction, port and the internet-wide range, as network ACLs evaluate.
// Narrower ranges never decide for the internet at large.
func firstACLDecision(entries []ACLEntry, egress bool, internet string, port int) (rule string, allowed, found bool) {
	ordered := append([]ACLEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Number < ordered[j].Number })
	for _, entry := range ordered {
		if entry.Egress != egress || entry.CIDR != internet {
			continue
		}
		switch entry.Protocol {
		case "-1":
		case "6":
			if port < entry.FromPort || port > entry.ToPort {
				continue
			}
		default:
			continue
		}
		return strconv.Itoa(entry.Number), entry.Allow, true
	}
	return "", false, false
}

func permits(p Permission, internet string, port int) bool {
	switch p.Protocol {
	case "-1":
	case "tcp", "6":
		if port < p.FromPort || port > p.ToPort {
			return false
		}
	default:
		return false
	}
	for _, cidr := range p.CIDRs {
		if cidr == internet {
			return true
		}
	}
	return false
}
