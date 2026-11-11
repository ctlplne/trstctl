// SPDX-License-Identifier: BUSL-1.1

package netpath

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Azure evaluation (A167-L1, part 2), written from Azure's documented
// network security group semantics. A public IP attached to a network
// interface carries internet traffic to the interface's private address, and
// network security groups are processed after that translation: for inbound
// traffic the subnet's group first, then the interface's, each deciding with
// its first matching rule in priority order (lower numbers first, the default
// rules last), and the traffic must be allowed by every group present. A
// Standard public IP is closed to inbound traffic until a group admits it; a
// Basic one with no group admits everything. The reply leaves through the
// public IP only while the subnet's route for the internet-wide range keeps
// next hop Internet: a user-defined route that sends it to an appliance or a
// gateway breaks the return path. As for AWS and GCP, only a rule naming the
// internet at large ("*", the Internet service tag, or 0.0.0.0/0 or ::/0)
// decides; one that admits a partner range does not make the address
// internet-reachable.

const (
	// StageNetworkSecurityGroup names an Azure network security group (the
	// subnet's or the network interface's) whose rule stopped the path.
	StageNetworkSecurityGroup Stage = "network_security_group"
	// StagePublicIP names a Standard public IP that no network security
	// group opens: Azure keeps such an address closed to inbound traffic.
	StagePublicIP Stage = "public_ip"
)

// Azure's default inbound rules, which every network security group carries
// after its own rules.
var azureDefaultInboundRules = []AzureSecurityRule{
	{Name: "AllowVnetInBound", Priority: 65000, Direction: "Inbound", Access: "Allow", Protocol: "*",
		SourcePrefixes: []string{"VirtualNetwork"}, DestinationPrefixes: []string{"VirtualNetwork"}, DestinationPorts: []string{"*"}},
	{Name: "AllowAzureLoadBalancerInBound", Priority: 65001, Direction: "Inbound", Access: "Allow", Protocol: "*",
		SourcePrefixes: []string{"AzureLoadBalancer"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"*"}},
	{Name: "DenyAllInBound", Priority: 65500, Direction: "Inbound", Access: "Deny", Protocol: "*",
		SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"*"}},
}

// AzureSecurityRule is one network security group rule, its single and
// plural address and port fields merged.
type AzureSecurityRule struct {
	Name                string
	Priority            int
	Direction           string // "Inbound" or "Outbound"
	Access              string // "Allow" or "Deny"
	Protocol            string // "Tcp", "Udp", "Icmp", "Esp", "Ah" or "*"
	SourcePrefixes      []string
	SourceASGs          []string // application security group IDs; never the internet
	DestinationPrefixes []string
	DestinationASGs     []string // application security group IDs
	DestinationPorts    []string // "*", "443", "8000-9000"
}

// AzureNSG is one network security group with its own and default rules.
type AzureNSG struct {
	ID    string
	Name  string
	Rules []AzureSecurityRule
}

// AzureRoute is one user-defined route.
type AzureRoute struct {
	Name          string
	AddressPrefix string
	NextHopType   string // "Internet", "VirtualAppliance", "VirtualNetworkGateway", "VnetLocal" or "None"
}

// AzureRouteTable is the route table associated with the subnet.
type AzureRouteTable struct {
	ID     string
	Name   string
	Routes []AzureRoute
}

// AzureConfig is what Azure Resource Manager reported for the path to the
// interface holding one public IP.
type AzureConfig struct {
	PublicIP    string // the public IP resource's name
	PublicIPSKU string // "Basic" or "Standard"
	// NATGateway names the NAT gateway the public IP serves; such an
	// address carries outbound connections only.
	NATGateway string
	// Attachment names what the public IP is attached to when it is not a
	// network interface ("loadBalancers lb-web"); the path through it is
	// not read.
	Attachment    string
	Interface     string // the network interface's name
	PrivateIP     netip.Addr
	InterfaceASGs []string // application security groups of the interface's IP configuration
	Subnet        string   // the subnet's name
	SubnetNSG     *AzureNSG
	InterfaceNSG  *AzureNSG
	RouteTable    *AzureRouteTable
}

// EvaluateAzure decides whether the internet reaches ip:port over TCP through
// the public IP the configuration describes.
func EvaluateAzure(ip netip.Addr, port int, cfg AzureConfig) Result {
	internet := "0.0.0.0/0"
	if ip.Is6() && !ip.Is4In6() {
		internet = "::/0"
	}
	if cfg.Interface == "" {
		switch {
		case cfg.Attachment != "":
			return Result{Verdict: Unknown, Resource: cfg.PublicIP,
				Reason: "public IP " + cfg.PublicIP + " is attached to " + cfg.Attachment + ", not a network interface; paths through it are not read yet"}
		case cfg.NATGateway != "":
			return Result{Verdict: Blocked, BlockedBy: StagePublicIP, Resource: cfg.PublicIP,
				Reason: "public IP " + cfg.PublicIP + " serves NAT gateway " + cfg.NATGateway + ", which carries outbound connections only"}
		default:
			return Result{Verdict: Blocked, BlockedBy: StagePublicIP, Resource: cfg.PublicIP,
				Reason: "public IP " + cfg.PublicIP + " is not associated with any resource, so nothing answers on it"}
		}
	}
	var admitted *AzureNSG
	var admittedBy AzureSecurityRule
	if cfg.SubnetNSG == nil && cfg.InterfaceNSG == nil {
		if !strings.EqualFold(cfg.PublicIPSKU, "Basic") {
			return Result{Verdict: Blocked, BlockedBy: StagePublicIP, Resource: cfg.PublicIP,
				Reason: "public IP " + cfg.PublicIP + " is a Standard address, closed to inbound traffic until a network security group admits it, and neither subnet " +
					cfg.Subnet + " nor interface " + cfg.Interface + " has one"}
		}
	}
	// Inbound, the subnet's group decides first, then the interface's.
	for _, scope := range []struct {
		nsg  *AzureNSG
		name string
	}{{cfg.SubnetNSG, "subnet " + cfg.Subnet}, {cfg.InterfaceNSG, "interface " + cfg.Interface}} {
		if scope.nsg == nil {
			continue
		}
		rule, allowed := firstAzureInboundDecision(scope.nsg.Rules, internet, port, cfg.PrivateIP, cfg.InterfaceASGs)
		decided := rule.Name + " (priority " + strconv.Itoa(rule.Priority) + ")"
		if !allowed {
			return Result{Verdict: Blocked, BlockedBy: StageNetworkSecurityGroup, Resource: scope.nsg.Name, Rule: decided,
				Reason: "network security group " + scope.nsg.Name + " on " + scope.name + " denies tcp/" + strconv.Itoa(port) + " from the internet with rule " + rule.Name}
		}
		admitted, admittedBy = scope.nsg, rule
	}
	// The reply leaves through the public IP only while the subnet's route
	// for the internet keeps next hop Internet.
	if cfg.RouteTable != nil {
		for _, route := range cfg.RouteTable.Routes {
			if route.AddressPrefix == internet && !strings.EqualFold(route.NextHopType, "Internet") {
				return Result{Verdict: Blocked, BlockedBy: StageRoute, Resource: cfg.RouteTable.Name, Rule: route.Name,
					Reason: "route " + route.Name + " in route table " + cfg.RouteTable.Name + " sends " + internet + " to next hop " + route.NextHopType +
						", so the reply does not return through public IP " + cfg.PublicIP}
			}
		}
	}
	// The path runs outward from the interface, as for AWS.
	path := []string{cfg.Interface}
	for _, nsg := range []*AzureNSG{cfg.InterfaceNSG, cfg.SubnetNSG} {
		if nsg != nil {
			path = append(path, nsg.Name)
		}
	}
	if cfg.RouteTable != nil {
		path = append(path, cfg.RouteTable.Name)
	}
	path = append(path, cfg.PublicIP)
	if admitted == nil {
		return Result{Verdict: Open, Resource: cfg.PublicIP, Path: path,
			Reason: "public IP " + cfg.PublicIP + " is a Basic address with no network security group on subnet " + cfg.Subnet + " or interface " + cfg.Interface +
				", so it admits all inbound traffic"}
	}
	return Result{Verdict: Open, Resource: admitted.Name, Rule: admittedBy.Name + " (priority " + strconv.Itoa(admittedBy.Priority) + ")", Path: path,
		Reason: "network security group " + admitted.Name + " admits tcp/" + strconv.Itoa(port) + " from the internet with rule " + admittedBy.Name}
}

// firstAzureInboundDecision returns the rule that decides internet traffic to
// port: the first, in priority order, of the group's inbound rules and then
// Azure's default rules that matches it. Only a rule whose source is the
// internet at large decides.
func firstAzureInboundDecision(rules []AzureSecurityRule, internet string, port int, private netip.Addr, asgs []string) (AzureSecurityRule, bool) {
	inbound := make([]AzureSecurityRule, 0, len(rules)+len(azureDefaultInboundRules))
	defaults := map[string]bool{}
	for _, rule := range rules {
		if strings.EqualFold(rule.Direction, "Inbound") {
			inbound = append(inbound, rule)
			if rule.Priority >= 65000 {
				defaults[strings.ToLower(rule.Name)] = true
			}
		}
	}
	// Resource Manager returns the default rules with the group; a reader
	// that did not still judges them.
	for _, rule := range azureDefaultInboundRules {
		if !defaults[strings.ToLower(rule.Name)] {
			inbound = append(inbound, rule)
		}
	}
	sort.SliceStable(inbound, func(i, j int) bool { return inbound[i].Priority < inbound[j].Priority })
	for _, rule := range inbound {
		if !azureProtocolMatches(rule.Protocol) || !azurePortsMatch(rule.DestinationPorts, port) ||
			!azureSourceIsInternet(rule, internet) || !azureDestinationMatches(rule, private, asgs) {
			continue
		}
		return rule, strings.EqualFold(rule.Access, "Allow")
	}
	// Unreachable while DenyAllInBound is judged; deny is the safe answer.
	return azureDefaultInboundRules[len(azureDefaultInboundRules)-1], false
}

func azureProtocolMatches(protocol string) bool {
	return protocol == "*" || strings.EqualFold(protocol, "Tcp")
}

func azurePortsMatch(ports []string, port int) bool {
	for _, spec := range ports {
		if spec == "*" || portSpecMatches(spec, port) {
			return true
		}
	}
	return false
}

// azureSourceIsInternet: "*", the Internet service tag and the internet-wide
// range of the address's family name the internet at large; a rule with
// source application security groups names only members of those groups.
func azureSourceIsInternet(rule AzureSecurityRule, internet string) bool {
	if len(rule.SourceASGs) > 0 {
		return false
	}
	for _, prefix := range rule.SourcePrefixes {
		if prefix == "*" || strings.EqualFold(prefix, "Internet") || prefix == internet {
			return true
		}
	}
	return false
}

// azureDestinationMatches: groups are processed after the public IP is
// translated, so a rule applies when its destination is any address, the
// virtual network, a range holding the interface's private address, or an
// application security group the interface's IP configuration belongs to.
func azureDestinationMatches(rule AzureSecurityRule, private netip.Addr, asgs []string) bool {
	for _, group := range rule.DestinationASGs {
		for _, member := range asgs {
			if strings.EqualFold(group, member) {
				return true
			}
		}
	}
	for _, prefix := range rule.DestinationPrefixes {
		switch {
		case prefix == "*" || strings.EqualFold(prefix, "VirtualNetwork"):
			return true
		case private.IsValid():
			if p, err := netip.ParsePrefix(prefix); err == nil && p.Contains(private) {
				return true
			}
			if a, err := netip.ParseAddr(prefix); err == nil && a == private {
				return true
			}
		}
	}
	return false
}
