// SPDX-License-Identifier: BUSL-1.1

// Package awsnetpath reads, from Amazon EC2, the network configuration on the
// path from the internet to one public address (A167): the interface that
// holds it, the security groups on that interface, and the route table and
// network ACL of its subnet. It calls only read-only Describe operations of
// the EC2 Query API, signs them with AWS Signature Version 4 (digests and the
// keyed MAC through the crypto boundary, AN-3), and hands the result to the
// provider-neutral evaluator in netpath.
//
// A167-L2: when a load balancer's node holds the address, its listeners and
// its own security groups are read through the read-only Elastic Load
// Balancing Query API (DescribeLoadBalancers and DescribeListeners, or the
// classic DescribeLoadBalancers); a NAT gateway's address is named as one; and
// the internet gateway's own route table (ingress routing) is read when the
// subnet's internet route leads to that gateway.
package awsnetpath

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	ec2Service        = "ec2"
	apiVersion        = "2016-11-15"
	elbService        = "elasticloadbalancing"
	elbV2Version      = "2015-12-01"
	elbClassicVersion = "2012-06-01"
	maxBody           = 4 << 20
	// maxListenerPages bounds one load balancer's listener pages (A167-L2).
	maxListenerPages = 20
)

// Config configures the EC2 reader.
type Config struct {
	Region          string
	Endpoint        string // e.g. https://ec2.us-east-1.amazonaws.com
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
	// ELBEndpoint is where load balancers are read (A167-L2); the Region's
	// Elastic Load Balancing endpoint by default. ELBHTTPClient defaults to
	// HTTPClient.
	ELBEndpoint   string
	ELBHTTPClient *http.Client
}

// Reader reads one account and region's network configuration.
type Reader struct {
	cfg Config
	ec2 endpoint
	elb endpoint
}

// endpoint is one signed Query API: where it is, the service it is signed for
// and the client that reaches it.
type endpoint struct {
	url, host, service string
	client             *http.Client
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.AccessKeyID) == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("awsnetpath: region and credentials are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://ec2." + cfg.Region + ".amazonaws.com"
	}
	if cfg.ELBEndpoint == "" {
		cfg.ELBEndpoint = "https://elasticloadbalancing." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("awsnetpath: bad endpoint")
	}
	lb, err := url.Parse(cfg.ELBEndpoint)
	if err != nil || lb.Host == "" {
		return nil, fmt.Errorf("awsnetpath: bad load balancing endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	if cfg.ELBHTTPClient == nil {
		cfg.ELBHTTPClient = cfg.HTTPClient
	}
	return &Reader{cfg: cfg,
		ec2: endpoint{url: cfg.Endpoint, host: u.Host, service: ec2Service, client: cfg.HTTPClient},
		elb: endpoint{url: cfg.ELBEndpoint, host: lb.Host, service: elbService, client: cfg.ELBHTTPClient},
	}, nil
}

// Path reads the configuration on the path to the interface holding ip. found
// is false when no interface in this account and region holds the address.
func (r *Reader) Path(ctx context.Context, ip netip.Addr) (cfg netpath.Config, found bool, err error) {
	filter := "association.public-ip"
	if ip.Is6() && !ip.Is4In6() {
		filter = "ipv6-addresses.ipv6-address"
	}
	var enis describeNetworkInterfacesResponse
	if err := r.call(ctx, r.ec2, apiVersion, url.Values{"Action": {"DescribeNetworkInterfaces"},
		"Filter.1.Name": {filter}, "Filter.1.Value.1": {ip.Unmap().String()}}, &enis); err != nil {
		return netpath.Config{}, false, err
	}
	if len(enis.Interfaces) == 0 {
		return netpath.Config{}, false, nil
	}
	eni := enis.Interfaces[0]
	cfg.Interface = netpath.Interface{ID: eni.ID, SubnetID: eni.SubnetID, VPCID: eni.VPCID}
	if private, err := netip.ParseAddr(strings.TrimSpace(eni.PrivateIP)); err == nil {
		cfg.Interface.PrivateIP = private
	}
	// A167-L2: a NAT gateway's address admits no connection from the
	// internet, whatever its subnet says.
	if nat, ok := natGatewayOf(eni.InterfaceType, eni.Description, eni.ID); ok {
		cfg.NATGateway = nat
		return cfg, true, nil
	}
	for _, group := range eni.Groups {
		cfg.Interface.SecurityGroups = append(cfg.Interface.SecurityGroups, group.ID)
	}
	// A167-L2: a load balancer's node answers on its listeners, behind the
	// load balancer's own security groups.
	if ref, ok := loadBalancerOf(eni.RequesterManaged, eni.Description); ok {
		balancer, groups, err := r.loadBalancer(ctx, ref)
		if err != nil {
			return netpath.Config{}, true, err
		}
		cfg.LoadBalancer, cfg.Interface.SecurityGroups = balancer, groups
	}
	if cfg.SecurityGroups, err = r.securityGroups(ctx, cfg.Interface.SecurityGroups); err != nil {
		return netpath.Config{}, true, err
	}
	if cfg.RouteTable, err = r.routeTable(ctx, eni.SubnetID, eni.VPCID); err != nil {
		return netpath.Config{}, true, err
	}
	if cfg.NetworkACL, err = r.networkACL(ctx, eni.SubnetID); err != nil {
		return netpath.Config{}, true, err
	}
	internet := "0.0.0.0/0"
	if ip.Is6() && !ip.Is4In6() {
		internet = "::/0"
	}
	if gateway := internetGatewayRoute(cfg.RouteTable, internet); gateway != "" {
		if cfg.GatewayRouteTable, err = r.gatewayRouteTable(ctx, gateway); err != nil {
			return netpath.Config{}, true, err
		}
	}
	return cfg, true, nil
}

// natGatewayOf reports whether the interface is a NAT gateway's, and names
// the gateway from the description EC2 gives it ("Interface for NAT Gateway
// nat-…"), or the interface when the description does not say.
func natGatewayOf(kind, description, id string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "nat_gateway", "natgateway":
	default:
		return "", false
	}
	for _, field := range strings.Fields(description) {
		if strings.HasPrefix(field, "nat-") {
			return field, true
		}
	}
	return id, true
}

// lbRef is the load balancer an interface's description names.
type lbRef struct {
	id, name string
	classic  bool
}

// loadBalancerOf reads the description Elastic Load Balancing gives its
// nodes' interfaces: "ELB app/<name>/<id>" or "ELB net/<name>/<id>", or
// "ELB <name>" for a classic load balancer. Only an interface the service
// manages counts; a gateway load balancer's ("ELB gwy/…") holds no public
// address.
func loadBalancerOf(requesterManaged bool, description string) (lbRef, bool) {
	rest, ok := strings.CutPrefix(description, "ELB ")
	if !requesterManaged || !ok || rest == "" || len(rest) > 255 || strings.ContainsAny(rest, " \t") {
		return lbRef{}, false
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 3 && (parts[0] == "app" || parts[0] == "net") && parts[1] != "" && parts[2] != "":
		return lbRef{id: rest, name: parts[1]}, true
	case len(parts) == 1:
		return lbRef{id: rest, name: rest, classic: true}, true
	}
	return lbRef{}, false
}

// loadBalancer reads the load balancer, its listeners and its security group
// IDs.
func (r *Reader) loadBalancer(ctx context.Context, ref lbRef) (*netpath.LoadBalancer, []string, error) {
	if ref.classic {
		var out describeClassicLoadBalancersResponse
		if err := r.call(ctx, r.elb, elbClassicVersion, url.Values{"Action": {"DescribeLoadBalancers"}, "LoadBalancerNames.member.1": {ref.name}}, &out); err != nil {
			return nil, nil, err
		}
		for _, lb := range out.LoadBalancers {
			if lb.Name != ref.name {
				continue
			}
			balancer := &netpath.LoadBalancer{ID: ref.id, Type: "classic"}
			for _, l := range lb.Listeners {
				balancer.Listeners = append(balancer.Listeners, netpath.Listener{Port: l.Port, Protocol: l.Protocol})
			}
			return balancer, lb.SecurityGroups, nil
		}
		return nil, nil, fmt.Errorf("awsnetpath: load balancer %s holding the address was not found", ref.id)
	}
	var out describeLoadBalancersResponse
	if err := r.call(ctx, r.elb, elbV2Version, url.Values{"Action": {"DescribeLoadBalancers"}, "Names.member.1": {ref.name}}, &out); err != nil {
		return nil, nil, err
	}
	for _, lb := range out.LoadBalancers {
		if !strings.HasSuffix(lb.ARN, ":loadbalancer/"+ref.id) {
			continue
		}
		balancer := &netpath.LoadBalancer{ID: ref.id, Type: lb.Type, Unfiltered: lb.Type == "network" && len(lb.SecurityGroups) == 0}
		marker := ""
		for page := 0; ; page++ {
			if page == maxListenerPages {
				return nil, nil, fmt.Errorf("awsnetpath: load balancer %s: more than %d listener pages", ref.id, maxListenerPages)
			}
			params := url.Values{"Action": {"DescribeListeners"}, "LoadBalancerArn": {lb.ARN}, "PageSize": {"400"}}
			if marker != "" {
				params.Set("Marker", marker)
			}
			var listeners describeListenersResponse
			if err := r.call(ctx, r.elb, elbV2Version, params, &listeners); err != nil {
				return nil, nil, err
			}
			for _, l := range listeners.Listeners {
				balancer.Listeners = append(balancer.Listeners, netpath.Listener{Port: l.Port, Protocol: l.Protocol})
			}
			if marker = strings.TrimSpace(listeners.NextMarker); marker == "" {
				break
			}
		}
		return balancer, lb.SecurityGroups, nil
	}
	return nil, nil, fmt.Errorf("awsnetpath: load balancer %s holding the address was not found", ref.id)
}

// internetGatewayRoute returns the internet gateway the subnet's active
// internet-wide route leads to.
func internetGatewayRoute(table *netpath.RouteTable, internet string) string {
	if table == nil {
		return ""
	}
	for _, route := range table.Routes {
		if route.Active && route.Destination == internet && strings.HasPrefix(route.Target, "igw-") {
			return route.Target
		}
	}
	return ""
}

// gatewayRouteTable reads the route table associated with the internet
// gateway (an edge association), or nil when there is none.
func (r *Reader) gatewayRouteTable(ctx context.Context, gateway string) (*netpath.RouteTable, error) {
	var out describeRouteTablesResponse
	if err := r.call(ctx, r.ec2, apiVersion, url.Values{"Action": {"DescribeRouteTables"},
		"Filter.1.Name": {"association.gateway-id"}, "Filter.1.Value.1": {gateway}}, &out); err != nil {
		return nil, err
	}
	if len(out.Tables) == 0 {
		return nil, nil
	}
	return tableFrom(out.Tables[0]), nil
}

func (r *Reader) securityGroups(ctx context.Context, ids []string) ([]netpath.SecurityGroup, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	params := url.Values{"Action": {"DescribeSecurityGroups"}}
	for i, id := range ids {
		params.Set("GroupId."+strconv.Itoa(i+1), id)
	}
	var out describeSecurityGroupsResponse
	if err := r.call(ctx, r.ec2, apiVersion, params, &out); err != nil {
		return nil, err
	}
	groups := make([]netpath.SecurityGroup, 0, len(out.Groups))
	for _, g := range out.Groups {
		group := netpath.SecurityGroup{ID: g.ID}
		for _, p := range g.Inbound {
			permission := netpath.Permission{Protocol: p.Protocol, FromPort: p.FromPort, ToPort: p.ToPort}
			for _, r := range p.IPv4 {
				permission.CIDRs = append(permission.CIDRs, r.CIDR)
			}
			for _, r := range p.IPv6 {
				permission.CIDRs = append(permission.CIDRs, r.CIDR)
			}
			group.Inbound = append(group.Inbound, permission)
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

// routeTable reads the table explicitly associated with the subnet, or the
// VPC's main table when the subnet has none, as EC2 routes.
func (r *Reader) routeTable(ctx context.Context, subnetID, vpcID string) (*netpath.RouteTable, error) {
	var out describeRouteTablesResponse
	if err := r.call(ctx, r.ec2, apiVersion, url.Values{"Action": {"DescribeRouteTables"},
		"Filter.1.Name": {"association.subnet-id"}, "Filter.1.Value.1": {subnetID}}, &out); err != nil {
		return nil, err
	}
	if len(out.Tables) == 0 {
		if err := r.call(ctx, r.ec2, apiVersion, url.Values{"Action": {"DescribeRouteTables"},
			"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpcID},
			"Filter.2.Name": {"association.main"}, "Filter.2.Value.1": {"true"}}, &out); err != nil {
			return nil, err
		}
	}
	if len(out.Tables) == 0 {
		return nil, nil
	}
	return tableFrom(out.Tables[0]), nil
}

// tableFrom reads a route table, taking each route's target from whichever
// of EC2's target fields carries it (A167-L2: transit gateways, peering
// connections, egress-only gateways and endpoints are named, not dropped).
func tableFrom(in routeTableXML) *netpath.RouteTable {
	table := &netpath.RouteTable{ID: in.ID}
	for _, route := range in.Routes {
		destination := route.DestinationIPv4
		if destination == "" {
			destination = route.DestinationIPv6
		}
		target := firstNonEmpty(route.GatewayID, route.NATGatewayID, route.TransitGatewayID, route.EgressOnlyGatewayID,
			route.PeeringConnectionID, route.VPCEndpointID, route.InstanceID, route.NetworkInterfaceID, route.CarrierGatewayID,
			route.LocalGatewayID, route.CoreNetworkARN)
		table.Routes = append(table.Routes, netpath.Route{Destination: destination, Target: target, Active: route.State == "active"})
	}
	return table
}

func (r *Reader) networkACL(ctx context.Context, subnetID string) (*netpath.NetworkACL, error) {
	var out describeNetworkACLsResponse
	if err := r.call(ctx, r.ec2, apiVersion, url.Values{"Action": {"DescribeNetworkAcls"},
		"Filter.1.Name": {"association.subnet-id"}, "Filter.1.Value.1": {subnetID}}, &out); err != nil {
		return nil, err
	}
	if len(out.ACLs) == 0 {
		return nil, nil
	}
	acl := &netpath.NetworkACL{ID: out.ACLs[0].ID}
	for _, e := range out.ACLs[0].Entries {
		cidr := e.CIDR
		if cidr == "" {
			cidr = e.IPv6CIDR
		}
		entry := netpath.ACLEntry{Number: e.Number, Egress: e.Egress, Protocol: e.Protocol, Allow: e.Action == "allow", CIDR: cidr}
		if e.PortRange != nil {
			entry.FromPort, entry.ToPort = e.PortRange.From, e.PortRange.To
		}
		acl.Entries = append(acl.Entries, entry)
	}
	return acl, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// call signs and sends one Query operation and decodes its XML response. A
// non-2xx answer is reported by status only: error bodies can echo request
// detail.
func (r *Reader) call(ctx context.Context, ep endpoint, version string, params url.Values, out any) error {
	params.Set("Version", version)
	body := []byte(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(ep.url, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.signV4(req, body, r.cfg.Now().UTC(), ep)
	resp, err := ep.client.Do(req)
	if err != nil {
		return fmt.Errorf("awsnetpath: %s: %w", params.Get("Action"), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("awsnetpath: %s: read response: %w", params.Get("Action"), err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("awsnetpath: %s: status %d (response body redacted)", params.Get("Action"), resp.StatusCode)
	}
	if err := xml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("awsnetpath: %s: decode response: %w", params.Get("Action"), err)
	}
	return nil
}

// signV4 adds AWS Signature Version 4 headers. Digests and the keyed MAC route
// through the crypto boundary (AN-3).
func (r *Reader) signV4(req *http.Request, body []byte, t time.Time, ep endpoint) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if r.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", r.cfg.SessionToken)
	}
	signed := []string{"content-type", "host", "x-amz-date"}
	if r.cfg.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = ep.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + r.cfg.Region + "/" + ep.service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+r.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(r.cfg.Region))
	kService := crypto.HMACSHA256(kRegion, []byte(ep.service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.cfg.AccessKeyID+"/"+credScope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

type describeNetworkInterfacesResponse struct {
	Interfaces []struct {
		ID               string `xml:"networkInterfaceId"`
		SubnetID         string `xml:"subnetId"`
		VPCID            string `xml:"vpcId"`
		InterfaceType    string `xml:"interfaceType"`
		Description      string `xml:"description"`
		RequesterManaged bool   `xml:"requesterManaged"`
		PrivateIP        string `xml:"privateIpAddress"`
		Groups           []struct {
			ID string `xml:"groupId"`
		} `xml:"groupSet>item"`
	} `xml:"networkInterfaceSet>item"`
}

type describeSecurityGroupsResponse struct {
	Groups []struct {
		ID      string `xml:"groupId"`
		Inbound []struct {
			Protocol string `xml:"ipProtocol"`
			FromPort int    `xml:"fromPort"`
			ToPort   int    `xml:"toPort"`
			IPv4     []struct {
				CIDR string `xml:"cidrIp"`
			} `xml:"ipRanges>item"`
			IPv6 []struct {
				CIDR string `xml:"cidrIpv6"`
			} `xml:"ipv6Ranges>item"`
		} `xml:"ipPermissions>item"`
	} `xml:"securityGroupInfo>item"`
}

type describeRouteTablesResponse struct {
	Tables []routeTableXML `xml:"routeTableSet>item"`
}

type routeTableXML struct {
	ID     string `xml:"routeTableId"`
	Routes []struct {
		DestinationIPv4     string `xml:"destinationCidrBlock"`
		DestinationIPv6     string `xml:"destinationIpv6CidrBlock"`
		GatewayID           string `xml:"gatewayId"`
		NATGatewayID        string `xml:"natGatewayId"`
		TransitGatewayID    string `xml:"transitGatewayId"`
		EgressOnlyGatewayID string `xml:"egressOnlyInternetGatewayId"`
		PeeringConnectionID string `xml:"vpcPeeringConnectionId"`
		VPCEndpointID       string `xml:"vpcEndpointId"`
		InstanceID          string `xml:"instanceId"`
		NetworkInterfaceID  string `xml:"networkInterfaceId"`
		CarrierGatewayID    string `xml:"carrierGatewayId"`
		LocalGatewayID      string `xml:"localGatewayId"`
		CoreNetworkARN      string `xml:"coreNetworkArn"`
		State               string `xml:"state"`
	} `xml:"routeSet>item"`
}

// describeLoadBalancersResponse is Elastic Load Balancing's
// DescribeLoadBalancers (2015-12-01) answer.
type describeLoadBalancersResponse struct {
	LoadBalancers []struct {
		ARN            string   `xml:"LoadBalancerArn"`
		Name           string   `xml:"LoadBalancerName"`
		Type           string   `xml:"Type"`
		Scheme         string   `xml:"Scheme"`
		SecurityGroups []string `xml:"SecurityGroups>member"`
	} `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
}

type describeListenersResponse struct {
	Listeners []struct {
		Port     int    `xml:"Port"`
		Protocol string `xml:"Protocol"`
	} `xml:"DescribeListenersResult>Listeners>member"`
	NextMarker string `xml:"DescribeListenersResult>NextMarker"`
}

// describeClassicLoadBalancersResponse is the classic DescribeLoadBalancers
// (2012-06-01) answer.
type describeClassicLoadBalancersResponse struct {
	LoadBalancers []struct {
		Name           string   `xml:"LoadBalancerName"`
		Scheme         string   `xml:"Scheme"`
		SecurityGroups []string `xml:"SecurityGroups>member"`
		Listeners      []struct {
			Protocol string `xml:"Listener>Protocol"`
			Port     int    `xml:"Listener>LoadBalancerPort"`
		} `xml:"ListenerDescriptions>member"`
	} `xml:"DescribeLoadBalancersResult>LoadBalancerDescriptions>member"`
}

type describeNetworkACLsResponse struct {
	ACLs []struct {
		ID      string `xml:"networkAclId"`
		Entries []struct {
			Number    int    `xml:"ruleNumber"`
			Protocol  string `xml:"protocol"`
			Action    string `xml:"ruleAction"`
			Egress    bool   `xml:"egress"`
			CIDR      string `xml:"cidrBlock"`
			IPv6CIDR  string `xml:"ipv6CidrBlock"`
			PortRange *struct {
				From int `xml:"from"`
				To   int `xml:"to"`
			} `xml:"portRange"`
		} `xml:"entrySet>item"`
	} `xml:"networkAclSet>item"`
}
