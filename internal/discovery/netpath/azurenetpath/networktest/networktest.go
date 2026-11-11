// SPDX-License-Identifier: BUSL-1.1

// Package networktest is an in-process double of the Azure Resource Manager
// reads the azurenetpath reader uses (A167-L1, part 2), written from the
// Microsoft.Network REST reference: the subscription's public IP list (one
// address a page, with an absolute nextLink a client must follow) and GETs of
// network interfaces, subnets, network security groups (with the default
// rules Resource Manager returns beside a group's own) and route tables. Every
// call must carry the expected bearer token and an api-version.
package networktest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// ResourceGroup holds every resource the double serves.
const ResourceGroup = "rg-network"

// PublicIP is one public IP address.
type PublicIP struct {
	Name    string
	Address string
	SKU     string // "Standard" (the default) or "Basic"
	// Exactly one of these, or none for an unassociated address.
	Interface    string // network interface name; the address sits on its ipconfig1
	LoadBalancer string // load balancer name; the address is its frontend
	NATGateway   string // NAT gateway name
}

// Interface is one network interface with one IP configuration (ipconfig1).
type Interface struct {
	Name      string
	PrivateIP string
	VNet      string
	Subnet    string
	NSG       string   // network security group name, or ""
	ASGs      []string // application security group names of ipconfig1
}

// Subnet is one subnet of a virtual network.
type Subnet struct {
	VNet       string
	Name       string
	NSG        string // network security group name, or ""
	RouteTable string // route table name, or ""
}

// Rule is one security rule as Resource Manager returns it.
type Rule struct {
	Name                     string
	Priority                 int
	Direction                string
	Access                   string
	Protocol                 string
	SourceAddressPrefix      string
	SourceAddressPrefixes    []string
	DestinationAddressPrefix string
	DestinationASGs          []string // application security group names
	DestinationPortRange     string
	DestinationPortRanges    []string
}

// NSG is one network security group.
type NSG struct {
	Name  string
	Rules []Rule
}

// Route is one user-defined route.
type Route struct {
	Name          string
	AddressPrefix string
	NextHopType   string
}

// RouteTable is one route table.
type RouteTable struct {
	Name   string
	Routes []Route
}

// Server is the double.
type Server struct {
	srv          *httptest.Server
	subscription string
	token        string

	mu          sync.Mutex
	publicIPs   []PublicIP
	interfaces  map[string]Interface
	subnets     map[string]Subnet
	nsgs        map[string]NSG
	routeTables map[string]RouteTable
	gets        int
	// foreignNextLink, when set, replaces every nextLink's base URL.
	foreignNextLink string
}

// New starts a double for subscription that accepts token.
func New(subscription, token string) *Server {
	s := &Server{subscription: subscription, token: token, interfaces: map[string]Interface{}, subnets: map[string]Subnet{},
		nsgs: map[string]NSG{}, routeTables: map[string]RouteTable{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the endpoint base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the double.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the double down.
func (s *Server) Close() { s.srv.Close() }

// ID is the Resource Manager ID of a resource the double holds:
// ID("networkSecurityGroups", "nsg-web") or ID("virtualNetworks", "vnet", "subnets", "web").
func (s *Server) ID(kind, name string, child ...string) string {
	id := "/subscriptions/" + s.subscription + "/resourceGroups/" + ResourceGroup + "/providers/Microsoft.Network/" + kind + "/" + name
	if len(child) == 2 {
		id += "/" + child[0] + "/" + child[1]
	}
	return id
}

// AddPublicIPs adds public IP addresses, listed in the order added.
func (s *Server) AddPublicIPs(ips ...PublicIP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicIPs = append(s.publicIPs, ips...)
}

// AddInterfaces adds network interfaces.
func (s *Server) AddInterfaces(nics ...Interface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, nic := range nics {
		s.interfaces[strings.ToLower(nic.Name)] = nic
	}
}

// AddSubnets adds subnets.
func (s *Server) AddSubnets(subnets ...Subnet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range subnets {
		s.subnets[strings.ToLower(sub.VNet+"/"+sub.Name)] = sub
	}
}

// AddNSGs adds network security groups.
func (s *Server) AddNSGs(nsgs ...NSG) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, nsg := range nsgs {
		s.nsgs[strings.ToLower(nsg.Name)] = nsg
	}
}

// AddRouteTables adds route tables.
func (s *Server) AddRouteTables(tables ...RouteTable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, table := range tables {
		s.routeTables[strings.ToLower(table.Name)] = table
	}
}

// SetForeignNextLink makes the public IP list's nextLink point at another
// host, as a hostile or broken endpoint might.
func (s *Server) SetForeignNextLink(base string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.foreignNextLink = base
}

// Gets is the number of authenticated reads served.
func (s *Server) Gets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken")
		return
	}
	if r.Method != http.MethodGet || r.URL.Query().Get("api-version") == "" {
		writeError(w, http.StatusBadRequest, "MissingApiVersionParameter")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	sub := "/subscriptions/" + strings.ToLower(s.subscription)
	path := strings.ToLower(r.URL.Path)
	if path == sub+"/providers/microsoft.network/publicipaddresses" {
		s.listPublicIPs(w, r)
		return
	}
	prefix := sub + "/resourcegroups/" + strings.ToLower(ResourceGroup) + "/providers/microsoft.network/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusNotFound, "ResourceNotFound")
		return
	}
	// Names keep their case in the response; the lookup ignores it.
	rest := strings.Split(r.URL.Path[len(prefix):], "/")
	var body any
	switch {
	case len(rest) == 2 && strings.EqualFold(rest[0], "networkInterfaces"):
		if nic, ok := s.interfaces[strings.ToLower(rest[1])]; ok {
			body = s.interfaceJSON(nic)
		}
	case len(rest) == 4 && strings.EqualFold(rest[0], "virtualNetworks") && strings.EqualFold(rest[2], "subnets"):
		if sub, ok := s.subnets[strings.ToLower(rest[1]+"/"+rest[3])]; ok {
			body = s.subnetJSON(sub)
		}
	case len(rest) == 2 && strings.EqualFold(rest[0], "networkSecurityGroups"):
		if nsg, ok := s.nsgs[strings.ToLower(rest[1])]; ok {
			body = s.nsgJSON(nsg)
		}
	case len(rest) == 2 && strings.EqualFold(rest[0], "routeTables"):
		if table, ok := s.routeTables[strings.ToLower(rest[1])]; ok {
			body = s.routeTableJSON(table)
		}
	}
	if body == nil {
		writeError(w, http.StatusNotFound, "ResourceNotFound")
		return
	}
	writeJSON(w, body)
}

func (s *Server) listPublicIPs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	out := map[string]any{"value": []any{}}
	if page >= 0 && page < len(s.publicIPs) {
		out["value"] = []any{s.publicIPJSON(s.publicIPs[page])}
	}
	if page+1 < len(s.publicIPs) {
		base := s.srv.URL
		if s.foreignNextLink != "" {
			base = s.foreignNextLink
		}
		out["nextLink"] = base + "/subscriptions/" + s.subscription + "/providers/Microsoft.Network/publicIPAddresses?api-version=" +
			r.URL.Query().Get("api-version") + "&$skiptoken=" + strconv.Itoa(page+1)
	}
	writeJSON(w, out)
}

func (s *Server) publicIPJSON(ip PublicIP) map[string]any {
	sku := ip.SKU
	if sku == "" {
		sku = "Standard"
	}
	props := map[string]any{"ipAddress": ip.Address, "publicIPAllocationMethod": "Static"}
	switch {
	case ip.Interface != "":
		props["ipConfiguration"] = map[string]string{"id": s.ID("networkInterfaces", ip.Interface, "ipConfigurations", "ipconfig1")}
	case ip.LoadBalancer != "":
		props["ipConfiguration"] = map[string]string{"id": s.ID("loadBalancers", ip.LoadBalancer, "frontendIPConfigurations", "frontend")}
	case ip.NATGateway != "":
		props["natGateway"] = map[string]string{"id": s.ID("natGateways", ip.NATGateway)}
	}
	return map[string]any{"id": s.ID("publicIPAddresses", ip.Name), "name": ip.Name, "sku": map[string]string{"name": sku}, "properties": props}
}

func (s *Server) interfaceJSON(nic Interface) map[string]any {
	asgs := make([]map[string]string, 0, len(nic.ASGs))
	for _, name := range nic.ASGs {
		asgs = append(asgs, map[string]string{"id": s.ID("applicationSecurityGroups", name)})
	}
	props := map[string]any{"ipConfigurations": []any{map[string]any{
		"id":   s.ID("networkInterfaces", nic.Name, "ipConfigurations", "ipconfig1"),
		"name": "ipconfig1",
		"properties": map[string]any{
			"privateIPAddress":          nic.PrivateIP,
			"subnet":                    map[string]string{"id": s.ID("virtualNetworks", nic.VNet, "subnets", nic.Subnet)},
			"applicationSecurityGroups": asgs,
		},
	}}}
	if nic.NSG != "" {
		props["networkSecurityGroup"] = map[string]string{"id": s.ID("networkSecurityGroups", nic.NSG)}
	}
	return map[string]any{"id": s.ID("networkInterfaces", nic.Name), "name": nic.Name, "properties": props}
}

func (s *Server) subnetJSON(sub Subnet) map[string]any {
	props := map[string]any{"addressPrefix": "10.0.0.0/24"}
	if sub.NSG != "" {
		props["networkSecurityGroup"] = map[string]string{"id": s.ID("networkSecurityGroups", sub.NSG)}
	}
	if sub.RouteTable != "" {
		props["routeTable"] = map[string]string{"id": s.ID("routeTables", sub.RouteTable)}
	}
	return map[string]any{"id": s.ID("virtualNetworks", sub.VNet, "subnets", sub.Name), "name": sub.Name, "properties": props}
}

// defaultRules are the rules Resource Manager returns with every group.
var defaultRules = []Rule{
	{Name: "AllowVnetInBound", Priority: 65000, Direction: "Inbound", Access: "Allow", Protocol: "*",
		SourceAddressPrefix: "VirtualNetwork", DestinationAddressPrefix: "VirtualNetwork", DestinationPortRange: "*"},
	{Name: "AllowAzureLoadBalancerInBound", Priority: 65001, Direction: "Inbound", Access: "Allow", Protocol: "*",
		SourceAddressPrefix: "AzureLoadBalancer", DestinationAddressPrefix: "*", DestinationPortRange: "*"},
	{Name: "DenyAllInBound", Priority: 65500, Direction: "Inbound", Access: "Deny", Protocol: "*",
		SourceAddressPrefix: "*", DestinationAddressPrefix: "*", DestinationPortRange: "*"},
	{Name: "AllowVnetOutBound", Priority: 65000, Direction: "Outbound", Access: "Allow", Protocol: "*",
		SourceAddressPrefix: "VirtualNetwork", DestinationAddressPrefix: "VirtualNetwork", DestinationPortRange: "*"},
	{Name: "AllowInternetOutBound", Priority: 65001, Direction: "Outbound", Access: "Allow", Protocol: "*",
		SourceAddressPrefix: "*", DestinationAddressPrefix: "Internet", DestinationPortRange: "*"},
	{Name: "DenyAllOutBound", Priority: 65500, Direction: "Outbound", Access: "Deny", Protocol: "*",
		SourceAddressPrefix: "*", DestinationAddressPrefix: "*", DestinationPortRange: "*"},
}

func (s *Server) nsgJSON(nsg NSG) map[string]any {
	rules := func(in []Rule) []any {
		out := make([]any, 0, len(in))
		for _, rule := range in {
			props := map[string]any{"priority": rule.Priority, "direction": rule.Direction, "access": rule.Access, "protocol": rule.Protocol,
				"sourceAddressPrefix": rule.SourceAddressPrefix, "destinationAddressPrefix": rule.DestinationAddressPrefix,
				"destinationPortRange": rule.DestinationPortRange, "sourcePortRange": "*"}
			if len(rule.SourceAddressPrefixes) > 0 {
				props["sourceAddressPrefixes"] = rule.SourceAddressPrefixes
			}
			if len(rule.DestinationPortRanges) > 0 {
				props["destinationPortRanges"] = rule.DestinationPortRanges
			}
			if len(rule.DestinationASGs) > 0 {
				groups := make([]map[string]string, 0, len(rule.DestinationASGs))
				for _, name := range rule.DestinationASGs {
					groups = append(groups, map[string]string{"id": s.ID("applicationSecurityGroups", name)})
				}
				props["destinationApplicationSecurityGroups"] = groups
			}
			out = append(out, map[string]any{"name": rule.Name, "properties": props})
		}
		return out
	}
	return map[string]any{"id": s.ID("networkSecurityGroups", nsg.Name), "name": nsg.Name,
		"properties": map[string]any{"securityRules": rules(nsg.Rules), "defaultSecurityRules": rules(defaultRules)}}
}

func (s *Server) routeTableJSON(table RouteTable) map[string]any {
	routes := make([]any, 0, len(table.Routes))
	for _, route := range table.Routes {
		routes = append(routes, map[string]any{"name": route.Name,
			"properties": map[string]string{"addressPrefix": route.AddressPrefix, "nextHopType": route.NextHopType}})
	}
	return map[string]any{"id": s.ID("routeTables", table.Name), "name": table.Name, "properties": map[string]any{"routes": routes}}
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}
