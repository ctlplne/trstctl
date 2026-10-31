// SPDX-License-Identifier: BUSL-1.1

// Package awsnetpath reads, from Amazon EC2, the network configuration on the
// path from the internet to one public address (A167): the interface that
// holds it, the security groups on that interface, and the route table and
// network ACL of its subnet. It calls only read-only Describe operations of
// the EC2 Query API, signs them with AWS Signature Version 4 (digests and the
// keyed MAC through the crypto boundary, AN-3), and hands the result to the
// provider-neutral evaluator in netpath.
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
	service    = "ec2"
	apiVersion = "2016-11-15"
	maxBody    = 4 << 20
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
}

// Reader reads one account and region's network configuration.
type Reader struct {
	cfg  Config
	host string
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.AccessKeyID) == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("awsnetpath: region and credentials are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://ec2." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("awsnetpath: bad endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{cfg: cfg, host: u.Host}, nil
}

// Path reads the configuration on the path to the interface holding ip. found
// is false when no interface in this account and region holds the address.
func (r *Reader) Path(ctx context.Context, ip netip.Addr) (cfg netpath.Config, found bool, err error) {
	filter := "association.public-ip"
	if ip.Is6() && !ip.Is4In6() {
		filter = "ipv6-addresses.ipv6-address"
	}
	var enis describeNetworkInterfacesResponse
	if err := r.call(ctx, url.Values{"Action": {"DescribeNetworkInterfaces"},
		"Filter.1.Name": {filter}, "Filter.1.Value.1": {ip.Unmap().String()}}, &enis); err != nil {
		return netpath.Config{}, false, err
	}
	if len(enis.Interfaces) == 0 {
		return netpath.Config{}, false, nil
	}
	eni := enis.Interfaces[0]
	cfg.Interface = netpath.Interface{ID: eni.ID, SubnetID: eni.SubnetID, VPCID: eni.VPCID}
	for _, group := range eni.Groups {
		cfg.Interface.SecurityGroups = append(cfg.Interface.SecurityGroups, group.ID)
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
	return cfg, true, nil
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
	if err := r.call(ctx, params, &out); err != nil {
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
	if err := r.call(ctx, url.Values{"Action": {"DescribeRouteTables"},
		"Filter.1.Name": {"association.subnet-id"}, "Filter.1.Value.1": {subnetID}}, &out); err != nil {
		return nil, err
	}
	if len(out.Tables) == 0 {
		if err := r.call(ctx, url.Values{"Action": {"DescribeRouteTables"},
			"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpcID},
			"Filter.2.Name": {"association.main"}, "Filter.2.Value.1": {"true"}}, &out); err != nil {
			return nil, err
		}
	}
	if len(out.Tables) == 0 {
		return nil, nil
	}
	table := &netpath.RouteTable{ID: out.Tables[0].ID}
	for _, route := range out.Tables[0].Routes {
		destination := route.DestinationIPv4
		if destination == "" {
			destination = route.DestinationIPv6
		}
		target := firstNonEmpty(route.GatewayID, route.NATGatewayID, route.TransitGatewayID, route.InstanceID, route.NetworkInterfaceID)
		table.Routes = append(table.Routes, netpath.Route{Destination: destination, Target: target, Active: route.State == "active"})
	}
	return table, nil
}

func (r *Reader) networkACL(ctx context.Context, subnetID string) (*netpath.NetworkACL, error) {
	var out describeNetworkACLsResponse
	if err := r.call(ctx, url.Values{"Action": {"DescribeNetworkAcls"},
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

// call signs and sends one EC2 Query operation and decodes its XML response.
// A non-2xx answer is reported by status only: EC2 error bodies can echo
// request detail.
func (r *Reader) call(ctx context.Context, params url.Values, out any) error {
	params.Set("Version", apiVersion)
	body := []byte(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.cfg.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.signV4(req, body, r.cfg.Now().UTC())
	resp, err := r.cfg.HTTPClient.Do(req)
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
func (r *Reader) signV4(req *http.Request, body []byte, t time.Time) {
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
			v = r.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + r.cfg.Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+r.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(r.cfg.Region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.cfg.AccessKeyID+"/"+credScope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

type describeNetworkInterfacesResponse struct {
	Interfaces []struct {
		ID       string `xml:"networkInterfaceId"`
		SubnetID string `xml:"subnetId"`
		VPCID    string `xml:"vpcId"`
		Groups   []struct {
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
	Tables []struct {
		ID     string `xml:"routeTableId"`
		Routes []struct {
			DestinationIPv4    string `xml:"destinationCidrBlock"`
			DestinationIPv6    string `xml:"destinationIpv6CidrBlock"`
			GatewayID          string `xml:"gatewayId"`
			NATGatewayID       string `xml:"natGatewayId"`
			TransitGatewayID   string `xml:"transitGatewayId"`
			InstanceID         string `xml:"instanceId"`
			NetworkInterfaceID string `xml:"networkInterfaceId"`
			State              string `xml:"state"`
		} `xml:"routeSet>item"`
	} `xml:"routeTableSet>item"`
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
