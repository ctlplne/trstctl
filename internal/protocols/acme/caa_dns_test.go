// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"trstctl.com/trstctl/internal/protocols/acme"
)

func TestDNSCAAResolverLooksUpCAA(t *testing.T) {
	addr := serveCAADNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		q := r.Question[0]
		msg.Answer = []dns.RR{&dns.CAA{
			Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
			Flag:  0,
			Tag:   "issue",
			Value: "trstctl.example",
		}}
		_ = w.WriteMsg(msg)
	})

	resolver := acme.DNSCAAResolver{Server: addr, Timeout: time.Second}
	records, err := resolver.LookupCAA(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}
	if len(records) != 1 || records[0].Tag != "issue" || records[0].Value != "trstctl.example" {
		t.Fatalf("records = %+v, want issue trstctl.example", records)
	}
}

func TestDNSCAAResolverTreatsNXDOMAINAsNoCAA(t *testing.T) {
	addr := serveCAADNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(msg)
	})

	resolver := acme.DNSCAAResolver{Server: addr, Timeout: time.Second}
	records, err := resolver.LookupCAA(context.Background(), "missing.example.test")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %+v, want none for NXDOMAIN", records)
	}
}

func serveCAADNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DNS: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	done := make(chan error, 1)
	go func() { done <- srv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		if err := <-done; err != nil {
			t.Errorf("serve DNS: %v", err)
		}
	})
	return pc.LocalAddr().String()
}
