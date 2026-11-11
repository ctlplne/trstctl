// SPDX-License-Identifier: BUSL-1.1

// Package azurenetpath reads, from Azure Resource Manager, the network
// configuration on the path to the resource holding a public IP (A167-L1,
// part 2): the public IP, the network interface it is attached to, the
// interface's subnet, the network security groups on both and the subnet's
// route table. Every call is a read (Microsoft.Network/publicIPAddresses,
// networkInterfaces, virtualNetworks/subnets, networkSecurityGroups and
// routeTables read); nothing is written. The bearer token is held as bytes
// and wiped by Close.
package azurenetpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultEndpoint = "https://management.azure.com"
	// APIVersion is the Microsoft.Network API version every call names.
	APIVersion = "2023-09-01"
	maxBody    = 8 << 20
	// maxPages bounds the public IP list the reader follows.
	maxPages = 50
)

// Config configures the Resource Manager reader.
type Config struct {
	SubscriptionID string
	Endpoint       string // defaults to https://management.azure.com
	Token          []byte // Microsoft Entra access token for Resource Manager; copied, wiped by Close
	HTTPClient     *http.Client
}

// Reader reads one subscription's network configuration.
type Reader struct {
	subscription string
	base         *url.URL
	token        []byte
	client       *http.Client
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	subscription := strings.TrimSpace(cfg.SubscriptionID)
	if !plainSegment(subscription) || len(cfg.Token) == 0 {
		return nil, errors.New("azurenetpath: a subscription ID and a bearer token are required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.Path != "" || base.RawQuery != "" {
		return nil, errors.New("azurenetpath: bad endpoint")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{subscription: subscription, base: base, token: secrettext.Clone(cfg.Token), client: client}, nil
}

// Close wipes the reader's copy of the bearer token.
func (r *Reader) Close() {
	secret.Wipe(r.token)
	r.token = nil
}

// Judge decides whether the internet reaches ip:port in this subscription.
// found is false when no public IP in the subscription holds the address.
func (r *Reader) Judge(ctx context.Context, ip netip.Addr, port int) (netpath.Result, bool, error) {
	cfg, found, err := r.Path(ctx, ip)
	if err != nil || !found {
		return netpath.Result{}, found, err
	}
	return netpath.EvaluateAzure(ip, port, cfg), true, nil
}

// Path reads the configuration on the path to the resource holding ip.
func (r *Reader) Path(ctx context.Context, ip netip.Addr) (netpath.AzureConfig, bool, error) {
	want := ip.Unmap()
	var pip publicIP
	found := false
	if err := r.listPublicIPs(ctx, func(page []publicIP) {
		for _, candidate := range page {
			if addr, err := netip.ParseAddr(candidate.Properties.IPAddress); !found && err == nil && addr.Unmap() == want {
				pip, found = candidate, true
			}
		}
	}); err != nil || !found {
		return netpath.AzureConfig{}, found, err
	}
	cfg := netpath.AzureConfig{PublicIP: pip.Name, PublicIPSKU: pip.SKU.Name}
	if pip.Properties.NATGateway.ID != "" {
		cfg.NATGateway = lastSegment(pip.Properties.NATGateway.ID)
	}
	ipConfigID := pip.Properties.IPConfiguration.ID
	if ipConfigID == "" {
		return cfg, true, nil
	}
	nicID, ok := networkInterfaceOf(ipConfigID)
	if !ok {
		cfg.Attachment = attachment(ipConfigID)
		return cfg, true, nil
	}
	var nic networkInterface
	if err := r.get(ctx, nicID, &nic); err != nil {
		return netpath.AzureConfig{}, true, err
	}
	var ipc *ipConfiguration
	for i := range nic.Properties.IPConfigurations {
		if strings.EqualFold(nic.Properties.IPConfigurations[i].ID, ipConfigID) {
			ipc = &nic.Properties.IPConfigurations[i]
		}
	}
	if ipc == nil {
		return netpath.AzureConfig{}, true, fmt.Errorf("azurenetpath: network interface %s has no IP configuration %s", nic.Name, lastSegment(ipConfigID))
	}
	cfg.Interface = nic.Name
	if addr, err := netip.ParseAddr(ipc.Properties.PrivateIPAddress); err == nil {
		cfg.PrivateIP = addr
	}
	for _, group := range ipc.Properties.ApplicationSecurityGroups {
		cfg.InterfaceASGs = append(cfg.InterfaceASGs, group.ID)
	}
	if id := nic.Properties.NetworkSecurityGroup.ID; id != "" {
		nsg, err := r.securityGroup(ctx, id)
		if err != nil {
			return netpath.AzureConfig{}, true, err
		}
		cfg.InterfaceNSG = nsg
	}
	var sub subnet
	if err := r.get(ctx, ipc.Properties.Subnet.ID, &sub); err != nil {
		return netpath.AzureConfig{}, true, err
	}
	cfg.Subnet = sub.Name
	if id := sub.Properties.NetworkSecurityGroup.ID; id != "" {
		nsg, err := r.securityGroup(ctx, id)
		if err != nil {
			return netpath.AzureConfig{}, true, err
		}
		cfg.SubnetNSG = nsg
	}
	if id := sub.Properties.RouteTable.ID; id != "" {
		var table routeTable
		if err := r.get(ctx, id, &table); err != nil {
			return netpath.AzureConfig{}, true, err
		}
		out := &netpath.AzureRouteTable{ID: table.ID, Name: table.Name}
		for _, route := range table.Properties.Routes {
			out.Routes = append(out.Routes, netpath.AzureRoute{Name: route.Name, AddressPrefix: route.Properties.AddressPrefix,
				NextHopType: route.Properties.NextHopType})
		}
		cfg.RouteTable = out
	}
	return cfg, true, nil
}

func (r *Reader) securityGroup(ctx context.Context, id string) (*netpath.AzureNSG, error) {
	var nsg networkSecurityGroup
	if err := r.get(ctx, id, &nsg); err != nil {
		return nil, err
	}
	out := &netpath.AzureNSG{ID: nsg.ID, Name: nsg.Name}
	for _, rules := range [][]securityRule{nsg.Properties.SecurityRules, nsg.Properties.DefaultSecurityRules} {
		for _, rule := range rules {
			out.Rules = append(out.Rules, rule.netpath())
		}
	}
	return out, nil
}

// listPublicIPs GETs every page of the subscription's public IPs, following
// nextLink only while it stays on the endpoint.
func (r *Reader) listPublicIPs(ctx context.Context, visit func([]publicIP)) error {
	next := r.resourceURL("/subscriptions/" + r.subscription + "/providers/Microsoft.Network/publicIPAddresses")
	for page := 0; page < maxPages; page++ {
		var body struct {
			Value    []publicIP `json:"value"`
			NextLink string     `json:"nextLink"`
		}
		if err := r.fetch(ctx, next, &body); err != nil {
			return err
		}
		visit(body.Value)
		if body.NextLink == "" {
			return nil
		}
		link, err := url.Parse(body.NextLink)
		if err != nil || link.Scheme != r.base.Scheme || link.Host != r.base.Host ||
			!strings.HasPrefix(strings.ToLower(link.Path), "/subscriptions/"+strings.ToLower(r.subscription)+"/") {
			return errors.New("azurenetpath: the public IP list's nextLink leaves the subscription's endpoint")
		}
		next = link
	}
	return fmt.Errorf("azurenetpath: the public IP list has more than %d pages", maxPages)
}

// get reads one resource by its Resource Manager ID, which must be a
// Microsoft.Network resource in this subscription.
func (r *Reader) get(ctx context.Context, id string, out any) error {
	if !r.ownNetworkResource(id) {
		return fmt.Errorf("azurenetpath: %q is not a network resource in this subscription", id)
	}
	return r.fetch(ctx, r.resourceURL(id), out)
}

func (r *Reader) resourceURL(path string) *url.URL {
	u := *r.base
	u.Path = path
	u.RawQuery = url.Values{"api-version": {APIVersion}}.Encode()
	return &u
}

func (r *Reader) fetch(ctx context.Context, u *url.URL, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", r.token))
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("azurenetpath: GET %s: %w", u.Path, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("azurenetpath: GET %s: read response: %w", u.Path, readErr)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("azurenetpath: GET %s: status %d (response body redacted)", u.Path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("azurenetpath: GET %s: decode response: %w", u.Path, err)
	}
	return nil
}

// ownNetworkResource accepts /subscriptions/{this}/resourceGroups/{rg}/
// providers/Microsoft.Network/{type}/{name}[/{child type}/{child name}] with
// plain segments only.
func (r *Reader) ownNetworkResource(id string) bool {
	parts := strings.Split(id, "/")
	if len(parts) != 9 && len(parts) != 11 {
		return false
	}
	if parts[0] != "" || !strings.EqualFold(parts[1], "subscriptions") || !strings.EqualFold(parts[2], r.subscription) ||
		!strings.EqualFold(parts[3], "resourceGroups") || !strings.EqualFold(parts[5], "providers") || !strings.EqualFold(parts[6], "Microsoft.Network") {
		return false
	}
	for _, part := range parts[1:] {
		if !plainSegment(part) {
			return false
		}
	}
	return true
}

// plainSegment is a non-empty path segment with no separator, query,
// fragment, escape or dot segment.
func plainSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/?#%\\ \t\r\n")
}

// networkInterfaceOf returns the network interface an IP configuration ID
// belongs to.
func networkInterfaceOf(ipConfigID string) (string, bool) {
	parts := strings.Split(ipConfigID, "/")
	if len(parts) == 11 && strings.EqualFold(parts[7], "networkInterfaces") && strings.EqualFold(parts[9], "ipConfigurations") {
		return strings.Join(parts[:9], "/"), true
	}
	return "", false
}

// attachment names what a public IP is attached to when it is not a network
// interface: "loadBalancers lb-web".
func attachment(ipConfigID string) string {
	parts := strings.Split(ipConfigID, "/")
	if len(parts) >= 9 {
		return parts[7] + " " + parts[8]
	}
	return lastSegment(ipConfigID)
}

func lastSegment(id string) string {
	id = strings.TrimRight(id, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

type idRef struct {
	ID string `json:"id"`
}

type publicIP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	SKU  struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		IPAddress       string `json:"ipAddress"`
		IPConfiguration idRef  `json:"ipConfiguration"`
		NATGateway      idRef  `json:"natGateway"`
	} `json:"properties"`
}

type ipConfiguration struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PrivateIPAddress          string  `json:"privateIPAddress"`
		Subnet                    idRef   `json:"subnet"`
		ApplicationSecurityGroups []idRef `json:"applicationSecurityGroups"`
	} `json:"properties"`
}

type networkInterface struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		IPConfigurations     []ipConfiguration `json:"ipConfigurations"`
		NetworkSecurityGroup idRef             `json:"networkSecurityGroup"`
	} `json:"properties"`
}

type subnet struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		NetworkSecurityGroup idRef `json:"networkSecurityGroup"`
		RouteTable           idRef `json:"routeTable"`
	} `json:"properties"`
}

type securityRule struct {
	Name       string `json:"name"`
	Properties struct {
		Priority                             int      `json:"priority"`
		Direction                            string   `json:"direction"`
		Access                               string   `json:"access"`
		Protocol                             string   `json:"protocol"`
		SourceAddressPrefix                  string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes                []string `json:"sourceAddressPrefixes"`
		SourceApplicationSecurityGroups      []idRef  `json:"sourceApplicationSecurityGroups"`
		DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
		DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
		DestinationApplicationSecurityGroups []idRef  `json:"destinationApplicationSecurityGroups"`
		DestinationPortRange                 string   `json:"destinationPortRange"`
		DestinationPortRanges                []string `json:"destinationPortRanges"`
	} `json:"properties"`
}

func (s securityRule) netpath() netpath.AzureSecurityRule {
	p := s.Properties
	out := netpath.AzureSecurityRule{Name: s.Name, Priority: p.Priority, Direction: p.Direction, Access: p.Access, Protocol: p.Protocol}
	out.SourcePrefixes = appendNonEmpty(p.SourceAddressPrefixes, p.SourceAddressPrefix)
	out.DestinationPrefixes = appendNonEmpty(p.DestinationAddressPrefixes, p.DestinationAddressPrefix)
	out.DestinationPorts = appendNonEmpty(p.DestinationPortRanges, p.DestinationPortRange)
	for _, group := range p.SourceApplicationSecurityGroups {
		out.SourceASGs = append(out.SourceASGs, group.ID)
	}
	for _, group := range p.DestinationApplicationSecurityGroups {
		out.DestinationASGs = append(out.DestinationASGs, group.ID)
	}
	return out
}

func appendNonEmpty(values []string, value string) []string {
	out := append([]string(nil), values...)
	if value != "" {
		out = append(out, value)
	}
	return out
}

type networkSecurityGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		SecurityRules        []securityRule `json:"securityRules"`
		DefaultSecurityRules []securityRule `json:"defaultSecurityRules"`
	} `json:"properties"`
}

type routeTable struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Routes []struct {
			Name       string `json:"name"`
			Properties struct {
				AddressPrefix string `json:"addressPrefix"`
				NextHopType   string `json:"nextHopType"`
			} `json:"properties"`
		} `json:"routes"`
	} `json:"properties"`
}
