// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"trstctl.com/trstctl/internal/crypto"
)

const EndpointProbeJobKind = "adcs.inventory.endpoint_probe"
const MaxEndpointProbePageTargets = 24
const maxEndpointProbeSuffixes = 32

// EndpointProbeOptions is an explicit operator grant to derive fixed-path HTTP
// candidates from directory hostnames. It grants no network address by itself.
type EndpointProbeOptions struct {
	Enabled     bool     `json:"enabled"`
	DNSSuffixes []string `json:"dns_suffixes"`
}

// EndpointProbeCursor is carried only by a source-bound queued command. Source
// configuration cannot supply it; the next run uses retained prior evidence.
type EndpointProbeCursor struct {
	PlanDigest string `json:"plan_digest"`
	NextOffset int    `json:"next_offset"`
}
type EndpointProbeTarget struct {
	EnrollmentEndpointTarget
	Source string `json:"source"`
}
type EndpointProbeHostIssue struct {
	EnrollmentService string `json:"enrollment_service"`
	Reason            string `json:"reason"`
}

// Complete qualifies this one page's coverage of the whole directory plan,
// never the HTTP result or a successful certificate enrollment.
type EndpointProbePage struct {
	PlanDigest   string                   `json:"plan_digest"`
	TotalTargets int                      `json:"total_targets"`
	Offset       int                      `json:"offset"`
	NextOffset   int                      `json:"next_offset"`
	Complete     bool                     `json:"complete"`
	Targets      []EndpointProbeTarget    `json:"targets"`
	HostIssues   []EndpointProbeHostIssue `json:"host_issues"`
}

func normalizeEndpointProbeOptions(raw *EndpointProbeOptions) (*EndpointProbeOptions, error) {
	if raw == nil {
		return nil, nil
	}
	if !raw.Enabled {
		if len(raw.DNSSuffixes) != 0 {
			return nil, errors.New("adcs: endpoint probe DNS suffixes require explicit enabled opt-in")
		}
		return nil, nil
	}
	if len(raw.DNSSuffixes) == 0 || len(raw.DNSSuffixes) > maxEndpointProbeSuffixes {
		return nil, errors.New("adcs: endpoint probing requires 1..32 explicit DNS suffixes")
	}
	out := &EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{}}
	for _, value := range raw.DNSSuffixes {
		host, ok := endpointProbeHostname(strings.TrimSpace(value))
		if !ok {
			return nil, errors.New("adcs: endpoint probe suffix must be an ASCII DNS name, without wildcard, address or URL syntax")
		}
		out.DNSSuffixes = append(out.DNSSuffixes, host)
	}
	out.DNSSuffixes = membershipUnique(out.DNSSuffixes)
	return out, nil
}
func endpointProbeHostname(raw string) (string, bool) {
	if raw == "" || len(raw) > 254 {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if len(host) > 253 || host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range []byte(label) {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", false
			}
		}
	}
	return host, true
}
func probeHostInScope(host string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
func probeTargetKey(target EnrollmentEndpointTarget) string {
	return target.EnrollmentService + "\x00" + string(target.Kind) + "\x00" + target.URL
}
func canonicalProbeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(parsed.Hostname())
	if canonical, ok := endpointProbeHostname(host); ok {
		host = canonical
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	parsed.Host = host
	return parsed.String()
}

// PlanEnrollmentEndpointProbes is effect-free: no DNS, socket, body or bind. It
// binds the exact LDAP service/hostname evidence to bounded fixed-path targets.
func PlanEnrollmentEndpointProbes(intent InventoryIntent, services []EnrollmentService) (EndpointProbePage, error) {
	empty := EndpointProbePage{}
	if len(services) > MaxEnrollmentServices {
		return empty, errors.New("adcs: endpoint probe service count exceeds its bound")
	}
	options, err := normalizeEndpointProbeOptions(intent.EndpointProbe)
	if err != nil {
		return empty, err
	}
	explicit, err := normalizeEnrollmentEndpointTargets(intent.EnrollmentEndpoints)
	if err != nil {
		return empty, err
	}
	names := map[string]bool{}
	for _, service := range services {
		if boundedReportText("enrollment service", service.Name) != nil || names[service.Name] {
			return empty, errors.New("adcs: endpoint probe service name is empty, oversized or duplicated")
		}
		names[service.Name] = true
	}
	targets := map[string]EndpointProbeTarget{}
	add := func(target EnrollmentEndpointTarget, source string) {
		target.URL = canonicalProbeURL(target.URL)
		key := probeTargetKey(target)
		if prior, ok := targets[key]; ok {
			if prior.Source != source {
				prior.Source = "configured_and_ldap_dns"
				targets[key] = prior
			}
			return
		}
		targets[key] = EndpointProbeTarget{EnrollmentEndpointTarget: target, Source: source}
	}
	for _, target := range explicit {
		if !names[target.EnrollmentService] {
			return empty, errors.New("adcs: configured endpoint names an unknown enrollment service")
		}
		add(target, "configured")
	}
	issues := []EndpointProbeHostIssue{}
	if options != nil {
		for _, service := range services {
			host, ok := endpointProbeHostname(service.DNSName)
			reason := ""
			if !ok {
				reason = "invalid_directory_hostname"
			} else if !probeHostInScope(host, options.DNSSuffixes) {
				reason = "outside_configured_dns_suffixes"
			}
			if reason != "" {
				issues = append(issues, EndpointProbeHostIssue{EnrollmentService: service.Name, Reason: reason})
				continue
			}
			for _, scheme := range []string{"http", "https"} {
				add(EnrollmentEndpointTarget{EnrollmentService: service.Name, Kind: EndpointWebEnrollment, URL: scheme + "://" + host + "/certsrv/"}, "ldap_dns")
				add(EnrollmentEndpointTarget{EnrollmentService: service.Name, Kind: EndpointNDES, URL: scheme + "://" + host + "/certsrv/mscep/mscep.dll"}, "ldap_dns")
			}
		}
	}
	all := make([]EndpointProbeTarget, 0, len(targets))
	for _, target := range targets {
		all = append(all, target)
	}
	sort.Slice(all, func(i, j int) bool {
		return probeTargetKey(all[i].EnrollmentEndpointTarget) < probeTargetKey(all[j].EnrollmentEndpointTarget)
	})
	sort.Slice(issues, func(i, j int) bool { return issues[i].EnrollmentService < issues[j].EnrollmentService })
	raw, _ := json.Marshal(struct {
		Targets    []EndpointProbeTarget    `json:"targets"`
		HostIssues []EndpointProbeHostIssue `json:"host_issues"`
	}{all, issues})
	digest := crypto.SHA256Hex(raw)
	offset := 0
	if prior := intent.PreviousProbePage; prior != nil {
		if options == nil || len(prior.PlanDigest) != 64 || prior.NextOffset < 0 || prior.NextOffset > (MaxEnrollmentServices*4+maxEndpointTargets) || prior.NextOffset%MaxEndpointProbePageTargets != 0 {
			return empty, errors.New("adcs: endpoint probe continuation is not a bounded page cursor")
		}
		if prior.PlanDigest == digest && prior.NextOffset < len(all) {
			offset = prior.NextOffset
		}
	}
	end := min(offset+MaxEndpointProbePageTargets, len(all))
	next := end
	if end == len(all) {
		next = 0
	}
	return EndpointProbePage{PlanDigest: digest, TotalTargets: len(all), Offset: offset, NextOffset: next, Complete: offset == 0 && end == len(all) && len(issues) == 0, Targets: all[offset:end], HostIssues: issues}, nil
}
