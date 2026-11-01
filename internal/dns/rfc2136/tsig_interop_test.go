// SPDX-License-Identifier: BUSL-1.1

package rfc2136_test

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"trstctl.com/trstctl/internal/dns/rfc2136"
)

// An authoritative server checks an update's TSIG with its own
// implementation: here miekg/dns, which most Go DNS tooling uses. RFC 8945
// §4.3.3 has the MAC cover the TSIG variables through Error and Other Len; a
// provider that leaves one out is refused as "bad signature" by every
// standards server, so its updates never land. A wrong secret must still be
// refused, which shows the check is real.
func TestProviderTSIGVerifiesAtAStandardsServer(t *testing.T) {
	secret := []byte("rfc2136-interop-secret")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan error, 4)
	server := &dns.Server{
		PacketConn: pc,
		TsigSecret: map[string]string{"update-key.example.test.": base64.StdEncoding.EncodeToString(secret)},
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			if int(dh.Bits>>11)&0xF == dns.OpcodeUpdate {
				return dns.MsgAccept
			}
			return dns.DefaultMsgAcceptFunc(dh)
		},
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			status := w.TsigStatus()
			if r.IsTsig() == nil {
				status = dns.ErrNoSig
			}
			statuses <- status
			m := new(dns.Msg)
			m.SetReply(r)
			if status != nil {
				m.Rcode = dns.RcodeNotAuth
			}
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	addr := pc.LocalAddr().String()
	ctx := context.Background()

	p := rfc2136.New(addr, "example.test.", rfc2136.Credentials{KeyName: "update-key.example.test", Secret: secret})
	if err := p.PresentTXT(ctx, "_acme-challenge.app.example.test", "token-digest"); err != nil {
		t.Fatalf("present: %v (server: %v)", err, <-statuses)
	}
	if status := <-statuses; status != nil {
		t.Fatalf("the server refused the add's TSIG: %v", status)
	}
	if err := p.CleanupTXT(ctx, "_acme-challenge.app.example.test", "token-digest"); err != nil {
		t.Fatalf("cleanup: %v (server: %v)", err, <-statuses)
	}
	if status := <-statuses; status != nil {
		t.Fatalf("the server refused the delete's TSIG: %v", status)
	}

	wrong := rfc2136.New(addr, "example.test.", rfc2136.Credentials{KeyName: "update-key.example.test", Secret: []byte("not-the-secret")})
	if err := wrong.PresentTXT(ctx, "_acme-challenge.app.example.test", "token-digest"); err == nil || !strings.Contains(err.Error(), "rcode 9") {
		t.Fatalf("an update signed with the wrong secret: %v", err)
	}
	if status := <-statuses; status == nil {
		t.Fatal("the server accepted a TSIG made with the wrong secret")
	}
}
