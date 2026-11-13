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
//
// A167-L5: "the internet at large" is the internet's core blocks, judged one
// at a time — the two halves of the IPv4 space, and IPv6 global unicast
// (2000::/3, where every public IPv6 address is allocated). A route or rule
// counts for a block when its destination holds the whole block, so ::/0 and
// 2000::/3 both speak for the IPv6 internet, a split default (0.0.0.0/1 and
// 128.0.0.0/1) overrides 0.0.0.0/0 as routing does, and a rule for half the
// internet admits half the internet. The path is open when any block passes
// every stage.
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
	// StageListener (A167-L2): the load balancer holding the address has no
	// listener on the port.
	StageListener Stage = "listener"
	// StageNATGateway (A167-L2): the address is a NAT gateway's, which admits
	// only replies to connections opened from inside the network.
	StageNATGateway Stage = "nat_gateway"
)

// Result is the verdict for one public address and port.
type Result struct {
	Verdict Verdict `json:"status"`
	// BlockedBy and Resource name the stage and the resource (route table,
	// network ACL, security groups, load balancer or NAT gateway) that
	// stopped the path. An unknown verdict whose path leaves this account's
	// tables names, in Resource, the transit gateway, endpoint or appliance
	// whose own rules decide (A167-L2).
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
	// PrivateIP is the interface's address inside its subnet (A167-L2): an
	// internet gateway's own route table steers inbound traffic by it.
	PrivateIP netip.Addr
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

// LoadBalancer is the load balancer whose node holds the address (A167-L2).
// It answers only on its listeners' ports, and its own security groups (in
// Config.SecurityGroups) filter what reaches them — not the groups of the
// targets behind it.
type LoadBalancer struct {
	// ID is app/<name>/<id>, net/<name>/<id>, or a classic load balancer's
	// name.
	ID string
	// Type is application, network or classic.
	Type      string
	Listeners []Listener
	// Unfiltered marks a network load balancer created without security
	// groups: only the subnet's network ACL filters what reaches its
	// listeners.
	Unfiltered bool
}

// Listener is one port and protocol a load balancer answers on.
type Listener struct {
	Port     int
	Protocol string // HTTP, HTTPS, TCP, TLS, SSL, UDP, TCP_UDP
}

// Config is what the provider reported for the path to one interface.
type Config struct {
	Interface      Interface
	RouteTable     *RouteTable
	NetworkACL     *NetworkACL
	SecurityGroups []SecurityGroup
	// LoadBalancer is set when a load balancer's node holds the address.
	LoadBalancer *LoadBalancer
	// NATGateway names the NAT gateway holding the address, when one does.
	NATGateway string
	// GatewayRouteTable is the route table associated with the internet
	// gateway on the path (ingress routing), when there is one.
	GatewayRouteTable *RouteTable
}

// ephemeralReturnPort is the port a network ACL must let replies leave on:
// stateless ACLs judge the return packet separately, and 49152 sits inside the
// Linux, Windows and load balancer ephemeral ranges alike.
const ephemeralReturnPort = 49152

// Evaluate decides whether the internet reaches ip:port over TCP through the
// reported configuration. Stages are checked in the order a packet meets them,
// for each of the internet's core blocks (A167-L5): open when any block gets
// through, else unknown when any block's path leaves these tables, else the
// first block's block.
func Evaluate(ip netip.Addr, port int, cfg Config) Result {
	if cfg.NATGateway != "" {
		return Result{Verdict: Blocked, BlockedBy: StageNATGateway, Resource: cfg.NATGateway,
			Reason: "the address belongs to a NAT gateway (" + cfg.NATGateway + "), which admits only replies to connections opened from inside the VPC"}
	}
	if cfg.RouteTable == nil || cfg.NetworkACL == nil {
		return Result{Verdict: Unknown, Reason: "the provider did not report the subnet's route table and network ACL"}
	}
	var blocked, unknown *Result
	for _, block := range coreBlocks(ip) {
		result := evaluateBlock(ip, port, cfg, block)
		switch result.Verdict {
		case Open:
			return result
		case Unknown:
			if unknown == nil {
				unknown = &result
			}
		default:
			if blocked == nil {
				blocked = &result
			}
		}
	}
	if unknown != nil {
		return *unknown
	}
	return *blocked
}

var (
	ipv4Core = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	ipv6Core = []netip.Prefix{netip.MustParsePrefix("2000::/3")}
)

// coreBlocks are the blocks a client on the internet at large is in
// (A167-L5).
func coreBlocks(ip netip.Addr) []netip.Prefix {
	if ip.Is6() && !ip.Is4In6() {
		return ipv6Core
	}
	return ipv4Core
}

// covers reports whether the CIDR holds the whole block.
func covers(cidr string, block netip.Prefix) bool {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	prefix = prefix.Masked()
	return prefix.Addr().Is4() == block.Addr().Is4() && prefix.Bits() <= block.Bits() && prefix.Contains(block.Addr())
}

// InternetGateway returns the internet gateway the route table sends replies
// to the internet at large to, if any (A167-L5: by longest prefix over the
// internet's core blocks).
func InternetGateway(table *RouteTable, ip netip.Addr) string {
	if table == nil {
		return ""
	}
	for _, block := range coreBlocks(ip) {
		if route := decisiveRoute(table, block); route != nil && route.Active && strings.HasPrefix(route.Target, "igw-") {
			return route.Target
		}
	}
	return ""
}

// decisiveRoute is the most specific route whose destination holds the whole
// block, the route longest-prefix routing takes for every address in it.
func decisiveRoute(table *RouteTable, block netip.Prefix) *Route {
	var best *Route
	bits := -1
	for i := range table.Routes {
		route := &table.Routes[i]
		if strings.TrimSpace(route.Target) == "" || !covers(route.Destination, block) {
			continue
		}
		if prefix, _ := netip.ParsePrefix(strings.TrimSpace(route.Destination)); prefix.Bits() > bits {
			best, bits = route, prefix.Bits()
		}
	}
	return best
}

// evaluateBlock follows the packet for clients in one core block.
func evaluateBlock(ip netip.Addr, port int, cfg Config, block netip.Prefix) Result {
	internet := "0.0.0.0/0"
	inside := cfg.Interface.PrivateIP
	if ip.Is6() && !ip.Is4In6() {
		internet, inside = "::/0", ip
	}
	tcp := "tcp/" + strconv.Itoa(port)
	out, stop := internetExit(cfg.RouteTable, block, internet)
	if stop != nil {
		return *stop
	}
	hop, blackhole := ingressHop(cfg.GatewayRouteTable, inside)
	if blackhole {
		return Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: cfg.GatewayRouteTable.ID,
			Reason: "the internet gateway's route table " + cfg.GatewayRouteTable.ID + " sends traffic for this subnet to " + hop + ", which no longer exists"}
	}
	if rule, allowed, found := firstACLDecision(cfg.NetworkACL.Entries, false, block, port); !found || !allowed {
		return Result{Verdict: Blocked, BlockedBy: StageNetworkACL, Resource: cfg.NetworkACL.ID, Rule: rule,
			Reason: "the subnet's network ACL denies inbound " + tcp + " from " + internet}
	}
	if rule, allowed, found := firstACLDecision(cfg.NetworkACL.Entries, true, block, ephemeralReturnPort); !found || !allowed {
		return Result{Verdict: Blocked, BlockedBy: StageNetworkACLOut, Resource: cfg.NetworkACL.ID, Rule: rule,
			Reason: "the subnet's network ACL denies the return traffic to " + internet + " on ephemeral ports"}
	}
	lb := cfg.LoadBalancer
	holder := cfg.Interface.ID
	if lb != nil {
		holder = "load balancer " + lb.ID
	}
	result := Result{Verdict: Open, Path: []string{cfg.Interface.ID}}
	admits := ""
	if lb == nil || !lb.Unfiltered {
		group, rule, cidr, ok := admittingGroup(cfg.SecurityGroups, block, port)
		if !ok {
			ids := make([]string, 0, len(cfg.SecurityGroups))
			for _, g := range cfg.SecurityGroups {
				ids = append(ids, g.ID)
			}
			sort.Strings(ids)
			return Result{Verdict: Blocked, BlockedBy: StageSecurityGroup, Resource: strings.Join(ids, ","),
				Reason: "no security group on " + holder + " admits " + tcp + " from " + internet}
		}
		result.Resource, result.Rule = group, rule
		admits = "security group " + group + " admits " + tcp + " from " + cidr
	}
	if lb != nil {
		listener, ok := lb.listener(port)
		if !ok {
			return Result{Verdict: Blocked, BlockedBy: StageListener, Resource: lb.ID,
				Reason: "load balancer " + lb.ID + " has no listener on " + tcp + " (" + lb.listening() + ")"}
		}
		result.Path = append(result.Path, lb.ID)
		said := "load balancer " + lb.ID + " listens on " + tcp + " (" + listener.Protocol + ")"
		if lb.Unfiltered {
			result.Resource = lb.ID
			admits = said + " and has no security groups, so only the subnet's network ACL filters it"
		} else {
			admits = said + " and " + admits
		}
	}
	if result.Rule != "" {
		result.Path = append(result.Path, result.Resource)
	}
	result.Path = append(result.Path, cfg.NetworkACL.ID, cfg.RouteTable.ID)
	// A167-L2: a middlebox the internet gateway's own route table steers this
	// subnet's traffic through, or replies that leave through a transit
	// gateway, endpoint or appliance, put the decision in rules these tables
	// do not show.
	beyond, why := hop, ""
	switch {
	case hop != "":
		why = "the internet gateway's route table " + cfg.GatewayRouteTable.ID + " sends traffic for this subnet through " + describeTarget(hop) + ", " + consequence(hop)
	case out.via != "":
		beyond = out.via
		why = "replies for " + out.destination + " leave the subnet through " + describeTarget(out.via) + ", " + consequence(out.via)
	}
	if beyond != "" {
		result.Path = append(result.Path, beyond)
	}
	if out.gateway != "" {
		result.Path = append(result.Path, out.gateway)
	}
	if beyond != "" {
		return Result{Verdict: Unknown, Resource: beyond, Path: result.Path, Reason: admits + ", but " + why}
	}
	result.Reason = admits
	return result
}

// exit is where the subnet's route table sends replies to the internet.
type exit struct {
	gateway     string // the internet gateway
	via         string // a target whose own routes or rules decide
	destination string // the route's destination
}

// internetExit reads the subnet's route for the internet-wide range. A reply
// to a connection from the internet must leave through the internet gateway
// that holds the address's mapping (A167-L2): a NAT gateway, an egress-only
// internet gateway, a peering connection or a virtual private gateway cannot
// carry it there, and a transit gateway, an endpoint or an appliance carries
// it somewhere this account's tables do not show.
func internetExit(table *RouteTable, block netip.Prefix, internet string) (exit, *Result) {
	blocked := func(reason string) *Result {
		return &Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: table.ID, Reason: reason}
	}
	route := decisiveRoute(table, block)
	if route == nil {
		return exit{}, blocked("the subnet's route table has no route from " + internet + " to an internet gateway")
	}
	target, destination := route.Target, strings.TrimSpace(route.Destination)
	if !route.Active {
		return exit{}, blocked("the subnet's route for " + destination + " is a blackhole: its target " + target + " no longer exists")
	}
	replies := "the subnet's route table sends replies for " + destination + " to "
	switch {
	case strings.HasPrefix(target, "igw-"):
		return exit{gateway: target, destination: destination}, nil
	case strings.HasPrefix(target, "nat-"):
		return exit{}, blocked(replies + "NAT gateway " + target + ", which rewrites them to its own address, so no connection from the internet to this address completes")
	case strings.HasPrefix(target, "eigw-"):
		return exit{}, blocked(replies + "egress-only internet gateway " + target + ", which admits only replies to connections opened from inside the VPC")
	case strings.HasPrefix(target, "pcx-"):
		return exit{}, blocked(replies + "peering connection " + target + ", which carries no traffic to the internet")
	case strings.HasPrefix(target, "vgw-"):
		return exit{}, blocked(replies + "virtual private gateway " + target + ", away from the internet gateway that holds this address")
	case target == "local":
		return exit{}, blocked("the subnet's route table has no route from " + internet + " to an internet gateway")
	default:
		return exit{via: target, destination: destination}, nil
	}
}

// ingressHop returns the middlebox the internet gateway's own route table
// sends traffic for this address to (ingress routing, A167-L2), and whether
// that route is a blackhole. The most specific route whose destination holds
// the address decides, as in any route table.
func ingressHop(table *RouteTable, inside netip.Addr) (string, bool) {
	if table == nil || !inside.IsValid() {
		return "", false
	}
	var best *Route
	bits := -1
	for i, route := range table.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(inside) || prefix.Bits() <= bits {
			continue
		}
		best, bits = &table.Routes[i], prefix.Bits()
	}
	if best == nil || best.Target == "local" {
		return "", false
	}
	if !best.Active {
		return best.Target, true
	}
	if strings.HasPrefix(best.Target, "vpce-") || strings.HasPrefix(best.Target, "eni-") {
		return best.Target, false
	}
	return "", false
}

func describeTarget(target string) string {
	switch {
	case strings.HasPrefix(target, "tgw-"):
		return "transit gateway " + target
	case strings.HasPrefix(target, "vpce-"):
		return "gateway load balancer endpoint " + target
	case strings.HasPrefix(target, "eni-"), strings.HasPrefix(target, "i-"):
		return "the appliance at " + target
	default:
		return target
	}
}

func consequence(target string) string {
	switch {
	case strings.HasPrefix(target, "tgw-"):
		return "so whether a connection from the internet completes is decided beyond this VPC's route tables"
	case strings.HasPrefix(target, "vpce-"):
		return "so the inspection appliances behind it decide"
	case strings.HasPrefix(target, "eni-"), strings.HasPrefix(target, "i-"):
		return "so the appliance's own configuration decides"
	default:
		return "which this evaluation does not follow"
	}
}

// admittingGroup returns the first group, rule and range that admit the block
// to the port.
func admittingGroup(groups []SecurityGroup, block netip.Prefix, port int) (group, rule, cidr string, ok bool) {
	for _, g := range groups {
		for i, permission := range g.Inbound {
			if cidr, ok := permits(permission, block, port); ok {
				return g.ID, "inbound[" + strconv.Itoa(i) + "]", cidr, true
			}
		}
	}
	return "", "", "", false
}

// listener returns the load balancer's TCP listener on the port.
func (lb *LoadBalancer) listener(port int) (Listener, bool) {
	for _, l := range lb.Listeners {
		if l.Port == port && tcpListener(l.Protocol) {
			return l, true
		}
	}
	return Listener{}, false
}

// listening names the TCP ports the load balancer answers on.
func (lb *LoadBalancer) listening() string {
	seen := map[int]bool{}
	var ports []int
	for _, l := range lb.Listeners {
		if tcpListener(l.Protocol) && !seen[l.Port] {
			seen[l.Port] = true
			ports = append(ports, l.Port)
		}
	}
	if len(ports) == 0 {
		return "it has no TCP listeners"
	}
	sort.Ints(ports)
	names := make([]string, len(ports))
	for i, port := range ports {
		names[i] = "tcp/" + strconv.Itoa(port)
	}
	return "it listens on " + strings.Join(names, ", ")
}

func tcpListener(protocol string) bool {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTP", "HTTPS", "TCP", "TLS", "SSL", "TCP_UDP":
		return true
	}
	return false
}

// firstACLDecision returns the first rule, in rule-number order, that matches
// the direction, port and a range holding the whole block, as network ACLs
// evaluate. Narrower ranges never decide for the internet at large.
func firstACLDecision(entries []ACLEntry, egress bool, block netip.Prefix, port int) (rule string, allowed, found bool) {
	ordered := append([]ACLEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Number < ordered[j].Number })
	for _, entry := range ordered {
		if entry.Egress != egress || !covers(entry.CIDR, block) {
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

// permits returns the range of the permission that admits the whole block to
// the port.
func permits(p Permission, block netip.Prefix, port int) (string, bool) {
	switch p.Protocol {
	case "-1":
	case "tcp", "6":
		if port < p.FromPort || port > p.ToPort {
			return "", false
		}
	default:
		return "", false
	}
	for _, cidr := range p.CIDRs {
		if covers(cidr, block) {
			return strings.TrimSpace(cidr), true
		}
	}
	return "", false
}
