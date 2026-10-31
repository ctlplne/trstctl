// SPDX-License-Identifier: BUSL-1.1

// Package ec2test is an in-process Amazon EC2 stand-in for the read-only
// Describe operations attack-path validation calls (A167). It verifies every
// request's Signature Version 4 under the configured key, answers in EC2's XML
// shapes from a seeded network, and counts any other action so a test can
// prove nothing was changed.
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

// Interface is a seeded elastic network interface.
type Interface struct {
	ID, SubnetID, VPCID, PublicIP, IPv6 string
	Groups                              []string
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

// Route is a seeded route.
type Route struct {
	Destination, Target string
}

// RouteTable is a seeded table: Main marks the VPC's main table; Subnets are
// its explicit associations.
type RouteTable struct {
	ID, VPCID string
	Main      bool
	Subnets   []string
	Routes    []Route
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

// Calls reports how many times each action was called.
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
		if !strings.HasPrefix(action, "Describe") {
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
	if !s.verify(r, body) {
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
	ID       string                `xml:"networkInterfaceId"`
	SubnetID string                `xml:"subnetId"`
	VPCID    string                `xml:"vpcId"`
	Groups   xmlItems[xmlGroupRef] `xml:"groupSet"`
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
		item := xmlInterface{ID: eni.ID, SubnetID: eni.SubnetID, VPCID: eni.VPCID}
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

type xmlRoute struct {
	Destination string `xml:"destinationCidrBlock,omitempty"`
	Gateway     string `xml:"gatewayId,omitempty"`
	NAT         string `xml:"natGatewayId,omitempty"`
	State       string `xml:"state"`
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
		item := xmlRouteTable{ID: table.ID, VPCID: table.VPCID}
		for _, route := range table.Routes {
			r := xmlRoute{Destination: route.Destination, State: "active"}
			if strings.HasPrefix(route.Target, "nat-") {
				r.NAT = route.Target
			} else {
				r.Gateway = route.Target
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

type xmlACLEntry struct {
	Number    int           `xml:"ruleNumber"`
	Protocol  string        `xml:"protocol"`
	Action    string        `xml:"ruleAction"`
	Egress    bool          `xml:"egress"`
	CIDR      string        `xml:"cidrBlock"`
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
// as the service does.
func (s *Server) verify(r *http.Request, body []byte) bool {
	const algo = "AWS4-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return false
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
		return false
	}
	cs := strings.Split(scope[1], "/")
	if len(cs) != 4 || cs[2] != "ec2" || cs[3] != "aws4_request" {
		return false
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
	return hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign))) == sig
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
