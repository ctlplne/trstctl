// SPDX-License-Identifier: BUSL-1.1

// Package computetest is an in-process double of the Compute Engine list
// operations the gcpnetpath reader uses (A167-L1), written from the Compute
// Engine v1 REST reference: GET .../aggregated/instances (items keyed by zone),
// .../global/firewalls and .../global/routes, each answering one item a page
// with nextPageToken so a client must follow it, and each requiring the
// expected bearer token.
package computetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Instance is one instance the double holds.
type Instance struct {
	Name            string
	Zone            string
	Network         string // network name
	NatIP           string
	Tags            []string
	ServiceAccounts []string
}

// Firewall is one firewall rule, as Compute Engine returns it.
type Firewall struct {
	Name                  string           `json:"name"`
	Network               string           `json:"network"`
	Direction             string           `json:"direction"`
	Priority              int              `json:"priority"`
	Disabled              bool             `json:"disabled,omitempty"`
	SourceRanges          []string         `json:"sourceRanges,omitempty"`
	TargetTags            []string         `json:"targetTags,omitempty"`
	TargetServiceAccounts []string         `json:"targetServiceAccounts,omitempty"`
	Allowed               []map[string]any `json:"allowed,omitempty"`
	Denied                []map[string]any `json:"denied,omitempty"`
}

// Route is one route, as Compute Engine returns it.
type Route struct {
	Name           string   `json:"name"`
	Network        string   `json:"network"`
	DestRange      string   `json:"destRange"`
	Priority       int      `json:"priority"`
	NextHopGateway string   `json:"nextHopGateway,omitempty"`
	NextHopIP      string   `json:"nextHopIp,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// Server is the double.
type Server struct {
	srv     *httptest.Server
	project string
	token   string

	mu        sync.Mutex
	instances []Instance
	firewalls []Firewall
	routes    []Route
	gets      int
}

// New starts a double for project that accepts token.
func New(project, token string) *Server {
	s := &Server{project: project, token: token}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the endpoint base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the double.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the double down.
func (s *Server) Close() { s.srv.Close() }

// NetworkURL is the self-link a resource carries for a network name.
func (s *Server) NetworkURL(network string) string {
	return "https://www.googleapis.com/compute/v1/projects/" + s.project + "/global/networks/" + network
}

// Add sets what the project holds.
func (s *Server) Add(instances []Instance, firewalls []Firewall, routes []Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.instances = append(s.instances, instances...)
	s.firewalls = append(s.firewalls, firewalls...)
	s.routes = append(s.routes, routes...)
}

// Gets is the number of authenticated list calls served.
func (s *Server) Gets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		http.Error(w, `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`, http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":{"code":405}}`, http.StatusMethodNotAllowed)
		return
	}
	prefix := "/compute/v1/projects/" + s.project
	page, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	var items []any
	kind := strings.TrimPrefix(r.URL.Path, prefix)
	switch kind {
	case "/aggregated/instances":
		for _, inst := range s.instances {
			items = append(items, inst)
		}
	case "/global/firewalls":
		for _, rule := range s.firewalls {
			items = append(items, rule)
		}
	case "/global/routes":
		for _, rt := range s.routes {
			items = append(items, rt)
		}
	default:
		http.Error(w, `{"error":{"code":404,"message":"not found"}}`, http.StatusNotFound)
		return
	}
	out := map[string]any{}
	if page < len(items) {
		switch item := items[page].(type) {
		case Instance:
			out["items"] = map[string]any{"zones/" + item.Zone: map[string]any{"instances": []any{s.instanceJSON(item)}}}
		case Firewall:
			item.Network = s.NetworkURL(item.Network)
			out["items"] = []any{item}
		case Route:
			item.Network = s.NetworkURL(item.Network)
			if item.NextHopGateway != "" {
				item.NextHopGateway = "https://www.googleapis.com/compute/v1/projects/" + s.project + "/global/gateways/" + item.NextHopGateway
			}
			out["items"] = []any{item}
		}
	}
	if page+1 < len(items) {
		out["nextPageToken"] = strconv.Itoa(page + 1)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) instanceJSON(inst Instance) map[string]any {
	accounts := make([]map[string]string, 0, len(inst.ServiceAccounts))
	for _, email := range inst.ServiceAccounts {
		accounts = append(accounts, map[string]string{"email": email})
	}
	return map[string]any{
		"name": inst.Name,
		"networkInterfaces": []any{map[string]any{
			"network":       s.NetworkURL(inst.Network),
			"accessConfigs": []any{map[string]string{"type": "ONE_TO_ONE_NAT", "natIP": inst.NatIP}},
		}},
		"tags":            map[string]any{"items": inst.Tags},
		"serviceAccounts": accounts,
	}
}
