// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/dns/rfc2136"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// P1 against the reference test CA. Pebble 2.10 implements the dns-persist-01
// draft; it validates through the DNS server it was started with
// (-dnsserver), which this test runs in process: trstctl's RFC 2136 provider
// publishes the standing record to it with a TSIG-signed UPDATE, and Pebble
// reads it from there. Run by runners/p1-pebble-proof.sh, which starts the
// pinned Pebble image; skipped otherwise.
func TestDNSPersistAgainstPebble(t *testing.T) {
	directory, caFile, dnsAddr := os.Getenv("TRSTCTL_P1_PEBBLE_DIRECTORY"), os.Getenv("TRSTCTL_P1_PEBBLE_CA_FILE"), os.Getenv("TRSTCTL_P1_DNS_ADDR")
	if directory == "" || caFile == "" || dnsAddr == "" {
		t.Skip("set TRSTCTL_P1_PEBBLE_DIRECTORY, TRSTCTL_P1_PEBBLE_CA_FILE and TRSTCTL_P1_DNS_ADDR (runners/p1-pebble-proof.sh)")
	}
	tsigSecret := []byte("p1-pebble-proof-tsig-secret-0123")
	zone := &updateZone{txt: map[string][]string{}}
	for _, network := range []string{"udp", "tcp"} {
		server := &dns.Server{Addr: dnsAddr, Net: network, Handler: zone,
			TsigSecret:    map[string]string{"p1-key.": base64.StdEncoding.EncodeToString(tsigSecret)},
			MsgAcceptFunc: acceptQueryAndUpdate}
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go func() { _ = server.ListenAndServe() }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("the %s DNS server did not start on %s", network, dnsAddr)
		}
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the runner's copy of Pebble's test root (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	solver := &rfc2136PersistSolver{
		provider: rfc2136.New(dnsAddr, "p1.test.", rfc2136.Credentials{KeyName: "p1-key", Secret: tsigSecret}),
		resolver: dnsResolver{addr: dnsAddr}, publish: true,
	}
	account, err := newAccountPlugin(t, directory, &http.Client{Transport: transport, Timeout: time.Minute}, solver)
	if err != nil {
		t.Fatal(err)
	}
	const domain = "app.p1.test"
	name := dns.Fqdn(acmesrv.DNSPersistRecordName(domain))
	issue := func(plugin *letsencrypt.Plugin) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, err := plugin.Issue(ctx, ca.IssueRequest{TenantID: "tenant-a", CSR: buildCSR(t, domain, []string{domain}), DNSNames: []string{domain}})
		return err
	}
	if err := issue(account); err != nil {
		t.Fatalf("first order at Pebble: %s", causeOf(err))
	}
	record, updates := zone.snapshot(name)
	if updates != 1 || len(record) != 1 || !strings.Contains(record[0], "; accounturi=") {
		t.Fatalf("standing record at Pebble's DNS = %q after %d updates", record, updates)
	}
	t.Logf("standing record %s TXT %q", name, record[0])
	if err := issue(account); err != nil {
		t.Fatalf("second order at Pebble: %s", causeOf(err))
	}
	if _, updates := zone.snapshot(name); updates != 1 {
		t.Fatalf("the second order changed DNS: %d updates", updates)
	}

	// Pebble, like a public CA, may reuse an account's valid authorization
	// for a while, so the refusals are shown with a second account that has
	// none and publishes nothing: with the record deleted it is refused, and
	// with the record back it is refused again, because the record names the
	// first account.
	other, err := newAccountPlugin(t, directory, &http.Client{Transport: transport, Timeout: time.Minute},
		&rfc2136PersistSolver{resolver: dnsResolver{addr: dnsAddr}})
	if err != nil {
		t.Fatal(err)
	}
	zone.remove(name)
	if err := issue(other); err == nil || !strings.Contains(causeOf(err), "DNS-PERSIST-01") {
		t.Fatalf("Pebble issued with the record deleted: %v %s", err, causeOf(err))
	}
	zone.put(name, record[0])
	if err := issue(other); err == nil || !strings.Contains(causeOf(err), "accounturi mismatch") {
		t.Fatalf("Pebble issued on a record naming another account: %v %s", err, causeOf(err))
	}
	if _, updates := zone.snapshot(name); updates != 1 {
		t.Fatalf("DNS changed during the refusals: %d updates", updates)
	}
}

// updateZone is an authoritative server that accepts TSIG-signed RFC 2136
// updates and answers TXT queries.
type updateZone struct {
	mu      sync.Mutex
	txt     map[string][]string
	updates int
}

func (z *updateZone) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	z.mu.Lock()
	switch r.Opcode {
	case dns.OpcodeUpdate:
		if r.IsTsig() == nil || w.TsigStatus() != nil {
			m.Rcode = dns.RcodeRefused
			break
		}
		for _, rr := range r.Ns {
			txt, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			name, value := strings.ToLower(txt.Hdr.Name), strings.Join(txt.Txt, "")
			kept := z.txt[name][:0]
			for _, v := range z.txt[name] {
				if v != value {
					kept = append(kept, v)
				}
			}
			if txt.Hdr.Class == dns.ClassINET {
				kept = append(kept, value)
			}
			z.txt[name] = kept
		}
		z.updates++
	default:
		m.Authoritative = true
		for _, q := range r.Question {
			if q.Qtype != dns.TypeTXT {
				continue
			}
			for _, v := range z.txt[strings.ToLower(q.Name)] {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v}})
			}
		}
	}
	z.mu.Unlock()
	_ = w.WriteMsg(m)
}

func (z *updateZone) snapshot(name string) ([]string, int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[strings.ToLower(name)]...), z.updates
}

func (z *updateZone) remove(name string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.txt, strings.ToLower(name))
}

func (z *updateZone) put(name, value string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[strings.ToLower(name)] = []string{value}
}

// dnsResolver reads TXT from one server, as the standing-record check does.
type dnsResolver struct{ addr string }

func (r dnsResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	in, _, err := new(dns.Client).ExchangeContext(ctx, q, r.addr)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range in.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out, nil
}

// rfc2136PersistSolver publishes the standing record through trstctl's RFC
// 2136 provider unless it already stands, and never retracts it.
type rfc2136PersistSolver struct {
	provider *rfc2136.Provider
	resolver acmesrv.Resolver
	publish  bool
}

func (s *rfc2136PersistSolver) SolvableChallenges() []string {
	return []string{acmekey.ChallengeDNSPersist01}
}

func (s *rfc2136PersistSolver) Solve(ctx context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	stands := acmesrv.DNSPersistValidator{Resolver: s.resolver}.ValidatePersist(ctx, req.Identifier, req.AccountURI, req.IssuerDomainNames) == nil
	if stands || !s.publish {
		return nil, nil
	}
	value := acmesrv.DNSPersistRecordValue(req.IssuerDomainNames[0], req.AccountURI, strings.HasPrefix(req.Identifier, "*."))
	return nil, s.provider.PresentTXT(ctx, acmesrv.DNSPersistRecordName(req.Identifier), value)
}

func newAccountPlugin(t *testing.T, directoryURL string, client *http.Client, solver acmekey.ChallengeSolver) (*letsencrypt.Plugin, error) {
	t.Helper()
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(account.Destroy)
	plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner("pebble", directoryURL, client, account, letsencrypt.WithChallengeSolver(solver))
	if err != nil {
		return nil, err
	}
	t.Cleanup(plugin.Destroy)
	return plugin, nil
}

// acceptQueryAndUpdate admits queries and RFC 2136 updates; the default
// filter answers an update NOTIMP.
func acceptQueryAndUpdate(dh dns.Header) dns.MsgAcceptAction {
	if opcode := int(dh.Bits>>11) & 0xF; opcode == dns.OpcodeUpdate {
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(dh)
}
