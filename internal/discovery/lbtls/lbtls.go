// SPDX-License-Identifier: BUSL-1.1

// Package lbtls names the load-balancer TLS policy discovery source (X4): the
// TLS policy each listener of an AWS load balancer, or each virtual server of
// an F5 BIG-IP, enforces, read as the protocol versions it allows. A listener
// that allows TLS 1.0 is one weak TLSv1.0 finding in the crypto inventory.
package lbtls

import (
	"sort"
	"strings"
)

const (
	// SourceKind is the discovery source that reads listener TLS policies.
	SourceKind = "load_balancer_tls"
	// FindingKind is one listener and the policy it enforces.
	FindingKind = "tls_listener_policy"
	// ProviderAWSELBv2 reads Application and Network Load Balancer listeners.
	ProviderAWSELBv2 = "aws-elbv2"
	// ProviderF5BIGIP reads BIG-IP virtual servers and their client SSL profiles.
	ProviderF5BIGIP = "f5-bigip"
	// MaxListeners bounds one read.
	MaxListeners = 10000
)

// Listener is one TLS listener and the policy it enforces.
type Listener struct {
	// LoadBalancer names the load balancer (ELB name) or BIG-IP virtual
	// server (full path); Ref is the listener ARN or the virtual server's full
	// path, the stable name a finding is keyed by.
	LoadBalancer, Ref string
	Port              int
	Protocol          string // HTTPS or TLS on ELB; clientside on BIG-IP
	Policy            string // ELB security policy, or BIG-IP client SSL profile
	// Protocols are the versions the policy allows, oldest first.
	Protocols []string
	// Ciphers are the policy's cipher suites (ELB), or the profile's cipher
	// string (BIG-IP).
	Ciphers []string
}

// versionOrder is the order versions are compared in.
var versionOrder = []string{"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// NormalizeProtocol names a version the way the crypto inventory does:
// "TLSv1" is TLSv1.0. An unknown name is returned empty.
func NormalizeProtocol(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "SSLV3":
		return "SSLv3"
	case "TLSV1", "TLSV1.0":
		return "TLSv1.0"
	case "TLSV1.1":
		return "TLSv1.1"
	case "TLSV1.2":
		return "TLSv1.2"
	case "TLSV1.3":
		return "TLSv1.3"
	}
	return ""
}

// SortProtocols normalizes, deduplicates and orders versions oldest first,
// dropping names it does not know.
func SortProtocols(raw []string) []string {
	seen := map[string]bool{}
	for _, p := range raw {
		if n := NormalizeProtocol(p); n != "" {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range versionOrder {
		if seen[v] {
			out = append(out, v)
		}
	}
	return out
}

// Lowest is the oldest version the policy allows, or empty.
func (l Listener) Lowest() string {
	if len(l.Protocols) == 0 {
		return ""
	}
	return l.Protocols[0]
}

// Allows reports whether the policy allows a version.
func (l Listener) Allows(version string) bool {
	for _, p := range l.Protocols {
		if p == version {
			return true
		}
	}
	return false
}

// SortListeners orders listeners by reference.
func SortListeners(ls []Listener) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].Ref < ls[j].Ref })
}
