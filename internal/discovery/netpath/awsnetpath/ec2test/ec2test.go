// SPDX-License-Identifier: BUSL-1.1

// Package ec2test is an in-process Amazon EC2 stand-in for the read-only
// Describe operations attack-path validation calls (A167). It verifies every
// request's Signature Version 4 under the configured key, answers in EC2's XML
// shapes from a seeded network, and counts any other action so a test can
// prove nothing was changed. A167-L2: it also answers the read-only Elastic
// Load Balancing calls (DescribeLoadBalancers and DescribeListeners of API
// version 2015-12-01, and the classic DescribeLoadBalancers of 2012-06-01),
// signed for the elasticloadbalancing service, written from the public API
// reference, with one listener a page so paging is exercised.
package ec2test

import (
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// Interface is a seeded elastic network interface. Type, Description and
// RequesterManaged are what EC2 reports for an interface a service created
// (A167-L2): a load balancer's ("ELB app/<name>/<id>", "ELB net/…", or "ELB
// <name>" for a classic one) or a NAT gateway's (type nat_gateway).
type Interface struct {
	ID, SubnetID, VPCID, PublicIP, IPv6 string
	Groups                              []string
	Type, Description, PrivateIP        string
	RequesterManaged                    bool
}

// Permission is a seeded inbound security group permission.
type Permission struct {
	Protocol         string
	FromPort, ToPort int
	CIDRs            []string
}

// SecurityGroup is a seeded group.
type SecurityGroup struct {
	ID      string
	Inbound []Permission
}

// Route is a seeded route. Blackhole marks a route whose target no longer
// exists.
type Route struct {
	Destination, Target string
	Blackhole           bool
}

// RouteTable is a seeded table: Main marks the VPC's main table; Subnets are
// its explicit associations and Gateways its edge associations (an internet
// gateway's own table, A167-L2).
type RouteTable struct {
	ID, VPCID string
	Main      bool
	Subnets   []string
	Gateways  []string
	Routes    []Route
}

// LoadBalancer is a seeded Elastic Load Balancing load balancer (A167-L2).
// Type is application, network or classic; ARN is unused for a classic one.
type LoadBalancer struct {
	ARN, Name, Type, Scheme string
	SecurityGroups          []string
	Listeners               []Listener
}

// Listener is a seeded listener.
type Listener struct {
	Port     int
	Protocol string
}

// ACLEntry is a seeded network ACL entry.
type ACLEntry struct {
	Number           int
	Egress, Allow    bool
	Protocol, CIDR   string
	FromPort, ToPort int
}

// NetworkACL is a seeded ACL and the subnets it is associated with.
type NetworkACL struct {
	ID      string
	Subnets []string
	Entries []ACLEntry
}

// Server is the stand-in.
type Server struct {
	srv                  *httptest.Server
	accessKey, secretKey string
	mu                   sync.Mutex
	interfaces           []Interface
	groups               map[string]SecurityGroup
	tables               []RouteTable
	acls                 []NetworkACL
	lbs                  []LoadBalancer
	calls                map[string]int
	refused              int
}

// New starts a stand-in that accepts requests signed with the given key.
func New(accessKey, secretKey string) *Server {
	s := &Server{accessKey: accessKey, secretKey: secretKey, groups: map[string]SecurityGroup{}, calls: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string          { return s.srv.URL }
func (s *Server) Client() *http.Client { return s.srv.Client() }
func (s *Server) Close()               { s.srv.Close() }

// Seed adds network resources.
func (s *Server) Seed(interfaces []Interface, groups []SecurityGroup, tables []RouteTable, acls []NetworkACL) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interfaces = append(s.interfaces, interfaces...)
	for _, g := range groups {
		s.groups[g.ID] = g
	}
	s.tables = append(s.tables, tables...)
	s.acls = append(s.acls, acls...)
}

// SeedLoadBalancers adds load balancers (A167-L2).
func (s *Server) SeedLoadBalancers(lbs ...LoadBalancer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lbs = append(s.lbs, lbs...)
}

// Calls reports how many times each action was called. Elastic Load Balancing
// actions are counted as "elbv2:<action>" and "elb:<action>" (classic).
func (s *Server) Calls(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[action]
}

// NonDescribeCalls counts actions other than Describe*: attack-path validation
// must never change the account.
func (s *Server) NonDescribeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for action, count := range s.calls {
		if !strings.HasPrefix(action[strings.LastIndex(action, ":")+1:], "Describe") {
			n += count
		}
	}
	return n
}

// Refused counts requests whose signature did not verify.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	service, ok := s.verify(r, body)
	if !ok {
		s.mu.Lock()
		s.refused++
		s.mu.Unlock()
		http.Error(w, "<Response><Errors><Error><Code>AuthFailure</Code></Error></Errors></Response>", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || form.Get("Version") == "" {
		http.Error(w, "malformed query", http.StatusBadRequest)
		return
	}
	action := form.Get("Action")
	if service == "elasticloadbalancing" {
		s.handleELB(w, form)
		return
	}
	if service != "ec2" {
		http.Error(w, "<Response><Errors><Error><Code>InvalidClientTokenId</Code></Error></Errors></Response>", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.calls[action]++
	s.mu.Unlock()
	filters := queryFilters(form)
	var out any
	switch action {
	case "DescribeNetworkInterfaces":
		out = s.describeInterfaces(filters)
	case "DescribeSecurityGroups":
		out = s.describeGroups(form)
	case "DescribeRouteTables":
		out = s.describeRouteTables(filters)
	case "DescribeNetworkAcls":
		out = s.describeACLs(filters)
	default:
		http.Error(w, "<Response><Errors><Error><Code>UnsupportedOperation</Code></Error></Errors></Response>", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	_ = xml.NewEncoder(w).Encode(out)
}

func queryFilters(form url.Values) map[string]string {
	out := map[string]string{}
	for i := 1; i < 10; i++ {
		name := form.Get("Filter." + strconv.Itoa(i) + ".Name")
		if name == "" {
			break
		}
		out[name] = form.Get("Filter." + strconv.Itoa(i) + ".Value.1")
	}
	return out
}

type xmlItems[T any] struct {
	Items []T `xml:"item"`
}

type xmlGroupRef struct {
	ID string `xml:"groupId"`
}

type xmlInterface struct {
	ID               string                `xml:"networkInterfaceId"`
	SubnetID         string                `xml:"subnetId"`
	VPCID            string                `xml:"vpcId"`
	Type             string                `xml:"interfaceType,omitempty"`
	Description      string                `xml:"description,omitempty"`
	RequesterManaged bool                  `xml:"requesterManaged"`
	PrivateIP        string                `xml:"privateIpAddress,omitempty"`
	Groups           xmlItems[xmlGroupRef] `xml:"groupSet"`
}

func (s *Server) describeInterfaces(filters map[string]string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []xmlInterface
	for _, eni := range s.interfaces {
		if ip, ok := filters["association.public-ip"]; ok && eni.PublicIP != ip {
			continue
		}
		if ip, ok := filters["ipv6-addresses.ipv6-address"]; ok && eni.IPv6 != ip {
			continue
		}
		item := xmlInterface{ID: eni.ID, SubnetID: eni.SubnetID, VPCID: eni.VPCID, Type: eni.Type, Description: eni.Description,
			RequesterManaged: eni.RequesterManaged, PrivateIP: eni.PrivateIP}
		if item.Type == "" {
			item.Type = "interface"
		}
		for _, g := range eni.Groups {
			item.Groups.Items = append(item.Groups.Items, xmlGroupRef{ID: g})
		}
		items = append(items, item)
	}
	return struct {
		XMLName    xml.Name               `xml:"DescribeNetworkInterfacesResponse"`
		Interfaces xmlItems[xmlInterface] `xml:"networkInterfaceSet"`
	}{Interfaces: xmlItems[xmlInterface]{Items: items}}
}

type xmlCIDR4 struct {
	CIDR string `xml:"cidrIp"`
}

type xmlCIDR6 struct {
	CIDR string `xml:"cidrIpv6"`
}

type xmlPermission struct {
	Protocol string             `xml:"ipProtocol"`
	FromPort int                `xml:"fromPort"`
	ToPort   int                `xml:"toPort"`
	IPv4     xmlItems[xmlCIDR4] `xml:"ipRanges"`
	IPv6     xmlItems[xmlCIDR6] `xml:"ipv6Ranges"`
}

type xmlGroup struct {
	ID          string                  `xml:"groupId"`
	Permissions xmlItems[xmlPermission] `xml:"ipPermissions"`
}

func (s *Server) describeGroups(form url.Values) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []xmlGroup
	for i := 1; i < 20; i++ {
		id := form.Get("GroupId." + strconv.Itoa(i))
		if id == "" {
			break
		}
		g, ok := s.groups[id]
		if !ok {
			continue
		}
		item := xmlGroup{ID: g.ID}
		for _, p := range g.Inbound {
			permission := xmlPermission{Protocol: p.Protocol, FromPort: p.FromPort, ToPort: p.ToPort}
			for _, cidr := range p.CIDRs {
				if strings.Contains(cidr, ":") {
					permission.IPv6.Items = append(permission.IPv6.Items, xmlCIDR6{CIDR: cidr})
				} else {
					permission.IPv4.Items = append(permission.IPv4.Items, xmlCIDR4{CIDR: cidr})
				}
			}
			item.Permissions.Items = append(item.Permissions.Items, permission)
		}
		items = append(items, item)
	}
	return struct {
		XMLName xml.Name           `xml:"DescribeSecurityGroupsResponse"`
		Groups  xmlItems[xmlGroup] `xml:"securityGroupInfo"`
	}{Groups: xmlItems[xmlGroup]{Items: items}}
}

// xmlRoute carries a route's target in the field EC2's Route type names for
// it (A167-L2): a gateway load balancer endpoint, like an internet or virtual
// private gateway, in gatewayId.
type xmlRoute struct {
	Destination      string `xml:"destinationCidrBlock,omitempty"`
	Destination6     string `xml:"destinationIpv6CidrBlock,omitempty"`
	Gateway          string `xml:"gatewayId,omitempty"`
	NAT              string `xml:"natGatewayId,omitempty"`
	Transit          string `xml:"transitGatewayId,omitempty"`
	EgressOnly       string `xml:"egressOnlyInternetGatewayId,omitempty"`
	Peering          string `xml:"vpcPeeringConnectionId,omitempty"`
	Instance         string `xml:"instanceId,omitempty"`
	NetworkInterface string `xml:"networkInterfaceId,omitempty"`
	State            string `xml:"state"`
}

type xmlRouteTable struct {
	ID     string             `xml:"routeTableId"`
	VPCID  string             `xml:"vpcId"`
	Routes xmlItems[xmlRoute] `xml:"routeSet"`
}

func (s *Server) describeRouteTables(filters map[string]string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []xmlRouteTable
	for _, table := range s.tables {
		if subnet, ok := filters["association.subnet-id"]; ok && !contains(table.Subnets, subnet) {
			continue
		}
		if vpc, ok := filters["vpc-id"]; ok && table.VPCID != vpc {
			continue
		}
		if main, ok := filters["association.main"]; ok && (main == "true") != table.Main {
			continue
		}
		if gateway, ok := filters["association.gateway-id"]; ok && !contains(table.Gateways, gateway) {
			continue
		}
		item := xmlRouteTable{ID: table.ID, VPCID: table.VPCID}
		for _, route := range table.Routes {
			r := xmlRoute{Destination: route.Destination, State: "active"}
			if strings.Contains(route.Destination, ":") {
				r.Destination, r.Destination6 = "", route.Destination
			}
			if route.Blackhole {
				r.State = "blackhole"
			}
			switch target := route.Target; {
			case strings.HasPrefix(target, "nat-"):
				r.NAT = target
			case strings.HasPrefix(target, "tgw-"):
				r.Transit = target
			case strings.HasPrefix(target, "eigw-"):
				r.EgressOnly = target
			case strings.HasPrefix(target, "pcx-"):
				r.Peering = target
			case strings.HasPrefix(target, "i-"):
				r.Instance = target
			case strings.HasPrefix(target, "eni-"):
				r.NetworkInterface = target
			default:
				r.Gateway = target
			}
			item.Routes.Items = append(item.Routes.Items, r)
		}
		items = append(items, item)
	}
	return struct {
		XMLName xml.Name                `xml:"DescribeRouteTablesResponse"`
		Tables  xmlItems[xmlRouteTable] `xml:"routeTableSet"`
	}{Tables: xmlItems[xmlRouteTable]{Items: items}}
}

type xmlPortRange struct {
	From int `xml:"from"`
	To   int `xml:"to"`
}

// xmlACLEntry carries an IPv6 entry's range in ipv6CidrBlock, as EC2 does
// (A167-L5).
type xmlACLEntry struct {
	Number    int           `xml:"ruleNumber"`
	Protocol  string        `xml:"protocol"`
	Action    string        `xml:"ruleAction"`
	Egress    bool          `xml:"egress"`
	CIDR      string        `xml:"cidrBlock,omitempty"`
	IPv6CIDR  string        `xml:"ipv6CidrBlock,omitempty"`
	PortRange *xmlPortRange `xml:"portRange,omitempty"`
}

type xmlACL struct {
	ID      string                `xml:"networkAclId"`
	Entries xmlItems[xmlACLEntry] `xml:"entrySet"`
}

func (s *Server) describeACLs(filters map[string]string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []xmlACL
	for _, acl := range s.acls {
		if subnet, ok := filters["association.subnet-id"]; ok && !contains(acl.Subnets, subnet) {
			continue
		}
		item := xmlACL{ID: acl.ID}
		for _, e := range acl.Entries {
			entry := xmlACLEntry{Number: e.Number, Protocol: e.Protocol, Egress: e.Egress, CIDR: e.CIDR, Action: "deny"}
			if strings.Contains(e.CIDR, ":") {
				entry.CIDR, entry.IPv6CIDR = "", e.CIDR
			}
			if e.Allow {
				entry.Action = "allow"
			}
			if e.Protocol == "6" || e.Protocol == "17" {
				entry.PortRange = &xmlPortRange{From: e.FromPort, To: e.ToPort}
			}
			item.Entries.Items = append(item.Entries.Items, entry)
		}
		items = append(items, item)
	}
	return struct {
		XMLName xml.Name         `xml:"DescribeNetworkAclsResponse"`
		ACLs    xmlItems[xmlACL] `xml:"networkAclSet"`
	}{ACLs: xmlItems[xmlACL]{Items: items}}
}

// verify recomputes the request's Signature Version 4 under the stand-in's key,
// as the service does, and returns the service the request was signed for.
func (s *Server) verify(r *http.Request, body []byte) (string, bool) {
	const algo = "AWS4-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return "", false
	}
	cred, signedHeaders, sig := "", "", ""
	for _, f := range strings.Split(auth[len(algo):], ",") {
		f = strings.TrimSpace(f)
		switch {
		case strings.HasPrefix(f, "Credential="):
			cred = strings.TrimPrefix(f, "Credential=")
		case strings.HasPrefix(f, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(f, "SignedHeaders=")
		case strings.HasPrefix(f, "Signature="):
			sig = strings.TrimPrefix(f, "Signature=")
		}
	}
	scope := strings.SplitN(cred, "/", 2)
	if len(scope) != 2 || scope[0] != s.accessKey || signedHeaders == "" || sig == "" {
		return "", false
	}
	cs := strings.Split(scope[1], "/")
	if len(cs) != 4 || (cs[2] != "ec2" && cs[2] != "elasticloadbalancing") || cs[3] != "aws4_request" {
		return "", false
	}
	var canonHeaders strings.Builder
	for _, h := range strings.Split(signedHeaders, ";") {
		v := strings.TrimSpace(r.Header.Get(h))
		if h == "host" {
			v = r.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body)}, "\n")
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope[1], crypto.SHA256Hex([]byte(canonical))}, "\n")
	k := crypto.HMACSHA256([]byte("AWS4"+s.secretKey), []byte(cs[0]))
	k = crypto.HMACSHA256(k, []byte(cs[1]))
	k = crypto.HMACSHA256(k, []byte(cs[2]))
	k = crypto.HMACSHA256(k, []byte("aws4_request"))
	return cs[2], hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign))) == sig
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// handleELB answers the read-only Elastic Load Balancing calls (A167-L2):
// DescribeLoadBalancers by name and DescribeListeners by load balancer ARN
// (2015-12-01), and the classic DescribeLoadBalancers by name (2012-06-01). A
// name that matches nothing is LoadBalancerNotFound, as the service answers.
func (s *Server) handleELB(w http.ResponseWriter, form url.Values) {
	action, version := form.Get("Action"), form.Get("Version")
	prefix := "elbv2:"
	if version == "2012-06-01" {
		prefix = "elb:"
	} else if version != "2015-12-01" {
		http.Error(w, "<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.calls[prefix+action]++
	lbs := append([]LoadBalancer(nil), s.lbs...)
	s.mu.Unlock()
	notFound := func() {
		http.Error(w, "<ErrorResponse><Error><Code>LoadBalancerNotFound</Code></Error></ErrorResponse>", http.StatusBadRequest)
	}
	var out any
	switch {
	case prefix == "elbv2:" && action == "DescribeLoadBalancers":
		names := members(form, "Names")
		var items []xmlLoadBalancerV2
		for _, lb := range lbs {
			if lb.Type == "classic" || !contains(names, lb.Name) {
				continue
			}
			items = append(items, xmlLoadBalancerV2{ARN: lb.ARN, Name: lb.Name, Type: lb.Type, Scheme: lb.Scheme,
				SecurityGroups: xmlMembers[string]{Members: lb.SecurityGroups}})
		}
		if len(items) == 0 {
			notFound()
			return
		}
		out = struct {
			XMLName xml.Name                      `xml:"DescribeLoadBalancersResponse"`
			Result  xmlMembers[xmlLoadBalancerV2] `xml:"DescribeLoadBalancersResult>LoadBalancers"`
		}{Result: xmlMembers[xmlLoadBalancerV2]{Members: items}}
	case prefix == "elbv2:" && action == "DescribeListeners":
		arn := form.Get("LoadBalancerArn")
		var listeners []xmlListenerV2
		found := false
		for _, lb := range lbs {
			if lb.Type == "classic" || lb.ARN != arn {
				continue
			}
			found = true
			for i, l := range lb.Listeners {
				listeners = append(listeners, xmlListenerV2{ARN: strings.Replace(lb.ARN, ":loadbalancer/", ":listener/", 1) + "/" + strconv.Itoa(i+1),
					LoadBalancerARN: lb.ARN, Port: l.Port, Protocol: l.Protocol})
			}
		}
		if !found {
			notFound()
			return
		}
		// One listener a page, so a reader that ignores NextMarker misses
		// listeners.
		start, _ := strconv.Atoi(form.Get("Marker"))
		page, next := []xmlListenerV2(nil), ""
		if start < len(listeners) {
			page = listeners[start : start+1]
			if start+1 < len(listeners) {
				next = strconv.Itoa(start + 1)
			}
		}
		out = struct {
			XMLName    xml.Name                  `xml:"DescribeListenersResponse"`
			Listeners  xmlMembers[xmlListenerV2] `xml:"DescribeListenersResult>Listeners"`
			NextMarker string                    `xml:"DescribeListenersResult>NextMarker,omitempty"`
		}{Listeners: xmlMembers[xmlListenerV2]{Members: page}, NextMarker: next}
	case prefix == "elb:" && action == "DescribeLoadBalancers":
		names := members(form, "LoadBalancerNames")
		var items []xmlLoadBalancerClassic
		for _, lb := range lbs {
			if lb.Type != "classic" || !contains(names, lb.Name) {
				continue
			}
			item := xmlLoadBalancerClassic{Name: lb.Name, Scheme: lb.Scheme, SecurityGroups: xmlMembers[string]{Members: lb.SecurityGroups}}
			for _, l := range lb.Listeners {
				item.Listeners.Members = append(item.Listeners.Members, xmlListenerDescription{Listener: xmlListenerClassic{
					Protocol: l.Protocol, LoadBalancerPort: l.Port, InstanceProtocol: l.Protocol, InstancePort: l.Port}})
			}
			items = append(items, item)
		}
		if len(items) == 0 {
			notFound()
			return
		}
		out = struct {
			XMLName xml.Name                           `xml:"DescribeLoadBalancersResponse"`
			Result  xmlMembers[xmlLoadBalancerClassic] `xml:"DescribeLoadBalancersResult>LoadBalancerDescriptions"`
		}{Result: xmlMembers[xmlLoadBalancerClassic]{Members: items}}
	default:
		http.Error(w, "<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	_ = xml.NewEncoder(w).Encode(out)
}

// members reads a Query API list parameter (Name.member.1, Name.member.2, …).
func members(form url.Values, name string) []string {
	var out []string
	for i := 1; i <= 20; i++ {
		v := form.Get(name + ".member." + strconv.Itoa(i))
		if v == "" {
			break
		}
		out = append(out, v)
	}
	return out
}

type xmlMembers[T any] struct {
	Members []T `xml:"member"`
}

type xmlLoadBalancerV2 struct {
	ARN            string             `xml:"LoadBalancerArn"`
	Name           string             `xml:"LoadBalancerName"`
	Scheme         string             `xml:"Scheme"`
	Type           string             `xml:"Type"`
	SecurityGroups xmlMembers[string] `xml:"SecurityGroups"`
}

type xmlListenerV2 struct {
	ARN             string `xml:"ListenerArn"`
	LoadBalancerARN string `xml:"LoadBalancerArn"`
	Port            int    `xml:"Port"`
	Protocol        string `xml:"Protocol"`
}

type xmlListenerClassic struct {
	Protocol         string `xml:"Protocol"`
	LoadBalancerPort int    `xml:"LoadBalancerPort"`
	InstanceProtocol string `xml:"InstanceProtocol"`
	InstancePort     int    `xml:"InstancePort"`
}

type xmlListenerDescription struct {
	Listener xmlListenerClassic `xml:"Listener"`
}

type xmlLoadBalancerClassic struct {
	Name           string                             `xml:"LoadBalancerName"`
	Scheme         string                             `xml:"Scheme"`
	SecurityGroups xmlMembers[string]                 `xml:"SecurityGroups"`
	Listeners      xmlMembers[xmlListenerDescription] `xml:"ListenerDescriptions"`
}
