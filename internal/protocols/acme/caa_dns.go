// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSCAAResolver resolves live CAA records through the system DNS configuration.
// It performs a single-name lookup; CAAChecker owns the RFC 8659 tree walk and
// authorization semantics.
type DNSCAAResolver struct {
	Server  string
	Client  *dns.Client
	Timeout time.Duration
}

var _ CAAResolver = DNSCAAResolver{}

// DefaultCAAResolver returns the production live-DNS CAA resolver.
func DefaultCAAResolver() CAAResolver {
	return DNSCAAResolver{}
}

func (r DNSCAAResolver) LookupCAA(ctx context.Context, name string) ([]CAARecord, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, fmt.Errorf("acme: CAA lookup name is empty")
	}
	server, err := r.server()
	if err != nil {
		return nil, err
	}
	client := r.Client
	if client == nil {
		timeout := r.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		client = &dns.Client{Net: "udp", Timeout: timeout}
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeCAA)
	msg.RecursionDesired = true
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("acme: empty CAA response for %s", name)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("acme: CAA lookup %s returned DNS rcode %s", name, dns.RcodeToString[resp.Rcode])
	}
	var out []CAARecord
	for _, rr := range resp.Answer {
		caa, ok := rr.(*dns.CAA)
		if !ok {
			continue
		}
		out = append(out, CAARecord{Flag: caa.Flag, Tag: caa.Tag, Value: caa.Value})
	}
	return out, nil
}

func (r DNSCAAResolver) server() (string, error) {
	if server := strings.TrimSpace(r.Server); server != "" {
		return normalizeDNSServer(server, "53"), nil
	}
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("acme: read system DNS config for CAA lookup: %w", err)
	}
	if len(cfg.Servers) == 0 {
		return "", fmt.Errorf("acme: system DNS config has no nameserver for CAA lookup")
	}
	port := cfg.Port
	if strings.TrimSpace(port) == "" {
		port = "53"
	}
	return normalizeDNSServer(cfg.Servers[0], port), nil
}

func normalizeDNSServer(server, defaultPort string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return server
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, defaultPort)
}
