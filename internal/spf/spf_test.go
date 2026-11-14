// SPDX-License-Identifier: BUSL-1.1

package spf

import (
	"context"
	"net"
	"strings"
	"testing"
)

// fakeDNS answers from maps; a name absent from every map is NXDOMAIN, and
// one in broken fails the lookup.
type fakeDNS struct {
	txt    map[string][]string
	addrs  map[string][]string
	mx     map[string][]string
	broken map[string]bool
}

func (f fakeDNS) err(name string) error {
	if f.broken[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, f.err(name)
}

func (f fakeDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	v, ok := f.addrs[host]
	if !ok {
		return nil, f.err(host)
	}
	out := make([]net.IPAddr, 0, len(v))
	for _, a := range v {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	v, ok := f.mx[name]
	if !ok {
		return nil, f.err(name)
	}
	out := make([]*net.MX, 0, len(v))
	for _, h := range v {
		out = append(out, &net.MX{Host: h + ".", Pref: 10})
	}
	return out, nil
}

// P15-L6: check_host() over each mechanism and modifier, the qualifiers, the
// include and redirect rules, the DNS-term and void-lookup limits, DNS
// failures, IPv6, and pinned records.
func TestCheckHostP15L6(t *testing.T) {
	many := "v=spf1"
	for i := 0; i < 11; i++ {
		many += " include:empty" + string(rune('a'+i)) + ".test"
	}
	dns := fakeDNS{
		txt: map[string][]string{
			"ip4.test":     {"v=spf1 ip4:192.0.2.0/24 -all"},
			"soft.test":    {"v=spf1 ~all"},
			"neutral.test": {"v=spf1 ?all"},
			"two.test":     {"v=spf1 -all", "v=spf1 +all"},
			"other.test":   {"some verification text"},
			"inc.test":     {"v=spf1 include:ip4.test -all"},
			"incfail.test": {"v=spf1 include:soft.test -all"},
			"incnone.test": {"v=spf1 include:nothing.test -all"},
			"redir.test":   {"v=spf1 redirect=ip4.test"},
			"a.test":       {"v=spf1 a -all"},
			"acidr.test":   {"v=spf1 a:hosts.a.test/24 -all"},
			"mx.test":      {"v=spf1 mx -all"},
			"exists.test":  {"v=spf1 exists:%{ir}.%{v}._spf.%{d} -all"},
			"many.test":    {many},
			"voids.test":   {"v=spf1 a:v1.test a:v2.test a:v3.test -all"},
			"broken.test":  {"v=spf1 a:dead.test -all"},
			"ip6.test":     {"v=spf1 ip6:2001:db8::/32 -all"},
			"unknown.test": {"v=spf1 foo:bar -all"},
			"emptya.test":  {"v=spf1 -all"},
		},
		addrs: map[string][]string{
			"a.test":                             {"192.0.2.10"},
			"hosts.a.test":                       {"198.51.100.1"},
			"mail.mx.test":                       {"203.0.113.5"},
			"9.2.0.192.in-addr._spf.exists.test": {"127.0.0.2"},
		},
		mx:     map[string][]string{"mx.test": {"mail.mx.test"}},
		broken: map[string]bool{"dead.test": true},
	}
	for i := 0; i < 11; i++ {
		dns.txt["empty"+string(rune('a'+i))+".test"] = []string{"v=spf1 ?all"}
	}
	c := Checker{Resolver: dns, Pinned: map[string]string{"pinned.test": "v=spf1 ip4:192.0.2.77 -all"}}
	for _, tc := range []struct {
		ip, domain string
		want       Result
	}{
		{"192.0.2.9", "ip4.test", Pass},
		{"198.51.100.9", "ip4.test", Fail},
		{"198.51.100.9", "soft.test", SoftFail},
		{"198.51.100.9", "neutral.test", Neutral},
		{"198.51.100.9", "nothing.test", None},
		{"198.51.100.9", "other.test", None},
		{"198.51.100.9", "two.test", PermError},
		{"192.0.2.9", "inc.test", Pass},
		{"198.51.100.9", "inc.test", Fail},
		{"198.51.100.9", "incfail.test", Fail},
		{"198.51.100.9", "incnone.test", PermError},
		{"192.0.2.9", "redir.test", Pass},
		{"192.0.2.10", "a.test", Pass},
		{"192.0.2.11", "a.test", Fail},
		{"198.51.100.200", "acidr.test", Pass},
		{"203.0.113.5", "mx.test", Pass},
		{"203.0.113.6", "mx.test", Fail},
		{"192.0.2.9", "exists.test", Pass},
		{"192.0.2.8", "exists.test", Fail},
		{"198.51.100.9", "many.test", PermError},
		{"198.51.100.9", "voids.test", PermError},
		{"198.51.100.9", "broken.test", TempError},
		{"2001:db8::cb01", "ip6.test", Pass},
		{"192.0.2.9", "ip6.test", Fail},
		{"198.51.100.9", "unknown.test", PermError},
		{"192.0.2.77", "pinned.test", Pass},
		{"192.0.2.78", "pinned.test", Fail},
	} {
		got, reason := c.Check(context.Background(), net.ParseIP(tc.ip), "alice@"+tc.domain, "mta.example.test")
		if got != tc.want {
			t.Fatalf("%s from %s = %s (%s), want %s", tc.domain, tc.ip, got, reason, tc.want)
		}
		if got != Pass && got != None && reason == "" {
			t.Fatalf("%s from %s = %s with no reason", tc.domain, tc.ip, got)
		}
	}
	// A null sender is checked as postmaster at the HELO name.
	if got, _ := c.Check(context.Background(), net.ParseIP("192.0.2.9"), "", "ip4.test"); got != Pass {
		t.Fatalf("a null sender = %s", got)
	}
}

// P15-L6: the macro examples of RFC 7208 §7.4.
func TestMacroExpansionMatchesRFC7208P15L6(t *testing.T) {
	e := &eval{ip: net.ParseIP("192.0.2.3").To4(), sender: "strong-bad@email.example.com", helo: "mx.example.org"}
	for spec, want := range map[string]string{
		"%{s}": "strong-bad@email.example.com", "%{o}": "email.example.com", "%{d}": "email.example.com",
		"%{d4}": "email.example.com", "%{d3}": "email.example.com", "%{d2}": "example.com", "%{d1}": "com",
		"%{dr}": "com.example.email", "%{d2r}": "example.email", "%{l}": "strong-bad", "%{l-}": "strong.bad",
		"%{lr}": "strong-bad", "%{lr-}": "bad.strong", "%{l1r-}": "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}":   "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
	} {
		got, err := e.expand(spec, "email.example.com")
		if err != nil || got != want {
			t.Fatalf("expand(%q) = %q %v, want %q", spec, got, err, want)
		}
	}
	e6 := &eval{ip: net.ParseIP("2001:db8::cb01"), sender: "strong-bad@email.example.com"}
	if got, err := e6.expand("%{ir}.%{v}._spf.%{d2}", "email.example.com"); err != nil ||
		got != "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com" {
		t.Fatalf("the IPv6 example = %q %v", got, err)
	}
	for _, bad := range []string{"%{x}", "%{d", "%", "%{d!}", "a b"} {
		if _, err := e.expand(bad, "email.example.com"); err == nil {
			t.Fatalf("expand(%q) succeeded", bad)
		}
	}
	if got, _ := e.expand(strings.Repeat("a", 60)+"."+strings.Repeat("b", 60)+"."+strings.Repeat("c", 60)+"."+strings.Repeat("d", 60)+".%{d}", "email.example.com"); len(got) > 253 {
		t.Fatalf("an expansion of %d characters", len(got))
	}
}
