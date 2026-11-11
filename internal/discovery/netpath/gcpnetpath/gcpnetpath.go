// SPDX-License-Identifier: BUSL-1.1

// Package gcpnetpath reads, from Compute Engine, the network configuration on
// the path to the instance holding a public address (A167-L1): the instance
// and its network interface, the VPC network's firewall rules and its routes.
// Every call is a read (compute.instances.list, compute.firewalls.list,
// compute.routes.list on the project); nothing is written. The bearer token is
// held as bytes and wiped by Close.
package gcpnetpath

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
	defaultEndpoint = "https://compute.googleapis.com"
	maxBody         = 8 << 20
	// maxPages bounds every list the reader follows.
	maxPages = 50
)

// Config configures the Compute Engine reader.
type Config struct {
	Project    string
	Endpoint   string // defaults to https://compute.googleapis.com
	Token      []byte // OAuth 2.0 bearer with compute read scope; copied, wiped by Close
	HTTPClient *http.Client
}

// Reader reads one project's network configuration.
type Reader struct {
	project  string
	endpoint string
	token    []byte
	client   *http.Client
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	project := strings.TrimSpace(cfg.Project)
	if project == "" || strings.ContainsAny(project, "/?#") || len(cfg.Token) == 0 {
		return nil, errors.New("gcpnetpath: a project and a bearer token are required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	if u, err := url.Parse(endpoint); err != nil || u.Host == "" {
		return nil, errors.New("gcpnetpath: bad endpoint")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{project: project, endpoint: endpoint, token: secrettext.Clone(cfg.Token), client: client}, nil
}

// Close wipes the reader's copy of the bearer token.
func (r *Reader) Close() {
	secret.Wipe(r.token)
	r.token = nil
}

// Judge decides whether the internet reaches ip:port on this project. found is
// false when no instance in the project holds the address.
func (r *Reader) Judge(ctx context.Context, ip netip.Addr, port int) (netpath.Result, bool, error) {
	cfg, found, err := r.Path(ctx, ip)
	if err != nil || !found {
		return netpath.Result{}, found, err
	}
	return netpath.EvaluateGCP(ip, port, cfg), true, nil
}

// Path reads the configuration on the path to the instance holding ip.
func (r *Reader) Path(ctx context.Context, ip netip.Addr) (netpath.GCPConfig, bool, error) {
	want := ip.Unmap().String()
	var cfg netpath.GCPConfig
	found := false
	err := r.list(ctx, "/compute/v1/projects/"+url.PathEscape(r.project)+"/aggregated/instances", func(raw json.RawMessage) error {
		var page struct {
			Items map[string]struct {
				Instances []instance `json:"instances"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, scope := range page.Items {
			for _, inst := range scope.Instances {
				if found {
					return nil
				}
				for _, nic := range inst.NetworkInterfaces {
					if !nic.holds(want) {
						continue
					}
					cfg.Instance = netpath.GCPInstance{Name: inst.Name, Network: lastSegment(nic.Network), Tags: inst.Tags.Items}
					for _, account := range inst.ServiceAccounts {
						cfg.Instance.ServiceAccounts = append(cfg.Instance.ServiceAccounts, account.Email)
					}
					found = true
				}
			}
		}
		return nil
	})
	if err != nil || !found {
		return netpath.GCPConfig{}, found, err
	}
	if err := r.list(ctx, "/compute/v1/projects/"+url.PathEscape(r.project)+"/global/firewalls", func(raw json.RawMessage) error {
		var page struct {
			Items []firewall `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, rule := range page.Items {
			cfg.Firewalls = append(cfg.Firewalls, rule.netpath())
		}
		return nil
	}); err != nil {
		return netpath.GCPConfig{}, true, err
	}
	if err := r.list(ctx, "/compute/v1/projects/"+url.PathEscape(r.project)+"/global/routes", func(raw json.RawMessage) error {
		var page struct {
			Items []route `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, rt := range page.Items {
			cfg.Routes = append(cfg.Routes, netpath.GCPRoute{Name: rt.Name, Network: lastSegment(rt.Network), DestRange: rt.DestRange,
				Priority: rt.Priority, NextHopGateway: lastSegment(rt.NextHopGateway), Tags: rt.Tags})
		}
		return nil
	}); err != nil {
		return netpath.GCPConfig{}, true, err
	}
	return cfg, true, nil
}

// list GETs every page of a Compute Engine list (pageToken), handing each
// page's body to visit.
func (r *Reader) list(ctx context.Context, path string, visit func(json.RawMessage) error) error {
	token := ""
	for page := 0; page < maxPages; page++ {
		query := url.Values{"maxResults": {"500"}}
		if token != "" {
			query.Set("pageToken", token)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+path+"?"+query.Encode(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", r.token))
		resp, err := r.client.Do(req)
		if err != nil {
			return fmt.Errorf("gcpnetpath: GET %s: %w", path, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("gcpnetpath: GET %s: read response: %w", path, readErr)
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("gcpnetpath: GET %s: status %d (response body redacted)", path, resp.StatusCode)
		}
		if err := visit(raw); err != nil {
			return fmt.Errorf("gcpnetpath: GET %s: decode response: %w", path, err)
		}
		var next struct {
			NextPageToken string `json:"nextPageToken"`
		}
		_ = json.Unmarshal(raw, &next)
		if token = next.NextPageToken; token == "" {
			return nil
		}
	}
	return fmt.Errorf("gcpnetpath: GET %s: more than %d pages", path, maxPages)
}

type instance struct {
	Name              string `json:"name"`
	NetworkInterfaces []nic  `json:"networkInterfaces"`
	Tags              struct {
		Items []string `json:"items"`
	} `json:"tags"`
	ServiceAccounts []struct {
		Email string `json:"email"`
	} `json:"serviceAccounts"`
}

type nic struct {
	Network       string `json:"network"`
	AccessConfigs []struct {
		NatIP string `json:"natIP"`
	} `json:"accessConfigs"`
	IPv6AccessConfigs []struct {
		ExternalIPv6 string `json:"externalIpv6"`
	} `json:"ipv6AccessConfigs"`
}

func (n nic) holds(ip string) bool {
	for _, access := range n.AccessConfigs {
		if access.NatIP == ip {
			return true
		}
	}
	for _, access := range n.IPv6AccessConfigs {
		if addr, err := netip.ParseAddr(access.ExternalIPv6); err == nil && addr.String() == ip {
			return true
		}
	}
	return false
}

type protocolPorts struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

type firewall struct {
	Name                  string          `json:"name"`
	Network               string          `json:"network"`
	Direction             string          `json:"direction"`
	Priority              *int            `json:"priority"`
	Disabled              bool            `json:"disabled"`
	SourceRanges          []string        `json:"sourceRanges"`
	TargetTags            []string        `json:"targetTags"`
	TargetServiceAccounts []string        `json:"targetServiceAccounts"`
	Allowed               []protocolPorts `json:"allowed"`
	Denied                []protocolPorts `json:"denied"`
}

func (f firewall) netpath() netpath.GCPFirewall {
	// Compute Engine's documented default priority is 1000.
	priority := 1000
	if f.Priority != nil {
		priority = *f.Priority
	}
	out := netpath.GCPFirewall{Name: f.Name, Network: lastSegment(f.Network), Direction: f.Direction, Priority: priority,
		Disabled: f.Disabled, SourceRanges: f.SourceRanges, TargetTags: f.TargetTags, TargetServiceAccounts: f.TargetServiceAccounts}
	for _, entry := range f.Allowed {
		out.Allowed = append(out.Allowed, netpath.GCPProtocolPorts{Protocol: entry.IPProtocol, Ports: entry.Ports})
	}
	for _, entry := range f.Denied {
		out.Denied = append(out.Denied, netpath.GCPProtocolPorts{Protocol: entry.IPProtocol, Ports: entry.Ports})
	}
	return out
}

type route struct {
	Name           string   `json:"name"`
	Network        string   `json:"network"`
	DestRange      string   `json:"destRange"`
	Priority       int      `json:"priority"`
	NextHopGateway string   `json:"nextHopGateway"`
	Tags           []string `json:"tags"`
}

// lastSegment turns a Compute Engine resource URL into its name.
func lastSegment(ref string) string {
	ref = strings.TrimRight(ref, "/")
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}
