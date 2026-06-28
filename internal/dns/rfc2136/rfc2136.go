// Package rfc2136 is the RFC 2136 dynamic DNS UPDATE provider for ACME DNS-01. It
// publishes and retracts TXT records directly against an authoritative DNS server.
// The provider keeps TSIG key material as []byte and computes the request MAC through
// internal/crypto (AN-3/AN-8); callers should load the bytes from a secret reference.
package rfc2136

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	dnsTypeSOA  = 6
	dnsTypeTXT  = 16
	dnsTypeTSIG = 250

	dnsClassIN   = 1
	dnsClassNONE = 254
	dnsClassANY  = 255

	opcodeUpdate = 5 << 11
	defaultTTL   = 60
	tsigFudge    = 300
	tsigAlg      = "hmac-sha256."
)

var _ acme.DNSProvider = (*Provider)(nil)

// Credentials carry the optional TSIG key used to authenticate UPDATE messages.
// Secret is held as bytes and never logged.
type Credentials struct {
	KeyName string
	Secret  []byte
}

// Exchanger sends one DNS wire message and returns its wire response.
type Exchanger interface {
	Exchange(context.Context, []byte) ([]byte, error)
}

// ExchangeFunc adapts a function to Exchanger.
type ExchangeFunc func(context.Context, []byte) ([]byte, error)

// Exchange sends one DNS wire message.
func (f ExchangeFunc) Exchange(ctx context.Context, msg []byte) ([]byte, error) { return f(ctx, msg) }

// Provider sends RFC 2136 UPDATE messages for one zone.
type Provider struct {
	server string
	zone   string
	ttl    uint32
	creds  Credentials
	ex     Exchanger
	now    func() time.Time
	nextID func() uint16
}

// Option configures a Provider.
type Option func(*Provider)

// WithExchange injects the DNS exchange seam.
func WithExchange(ex Exchanger) Option {
	return func(p *Provider) { p.ex = ex }
}

// WithNow injects a clock for deterministic TSIG tests.
func WithNow(now func() time.Time) Option {
	return func(p *Provider) { p.now = now }
}

// WithID injects DNS message IDs for deterministic tests.
func WithID(next func() uint16) Option {
	return func(p *Provider) { p.nextID = next }
}

// WithTTL overrides the TXT TTL.
func WithTTL(ttl uint32) Option {
	return func(p *Provider) {
		if ttl > 0 {
			p.ttl = ttl
		}
	}
}

// New returns an RFC 2136 DNS-01 provider bound to server and zone.
func New(server, zone string, creds Credentials, opts ...Option) *Provider {
	creds.Secret = secrettext.Clone(creds.Secret)
	p := &Provider{
		server: strings.TrimSpace(server),
		zone:   fqdn(zone),
		ttl:    defaultTTL,
		creds:  creds,
		now:    time.Now,
		nextID: randomID,
	}
	p.ex = udpExchange{server: p.server}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name identifies the provider.
func (p *Provider) Name() string { return "rfc2136" }

// Capabilities declares the one authoritative server the provider may call.
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, hostPort(p.server))
}

// PresentTXT publishes name=value as an idempotent ADD/replace-style UPDATE. DNS
// servers treat re-sending the same RR as convergent state for this transient TXT.
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	return p.update(ctx, dnsClassIN, p.ttl, name, value)
}

// CleanupTXT deletes the specific TXT RR. RFC 2136 represents specific-RR deletion
// with class NONE, TTL 0, and the exact RDATA.
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	return p.update(ctx, dnsClassNONE, 0, name, value)
}

func (p *Provider) update(ctx context.Context, class uint16, ttl uint32, name, value string) error {
	msg, id, err := p.buildUpdate(class, ttl, name, value)
	if err != nil {
		return err
	}
	resp, err := p.ex.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("rfc2136: exchange update for %s: %w", name, err)
	}
	if len(resp) < 4 {
		return errors.New("rfc2136: short response")
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != id {
		return fmt.Errorf("rfc2136: response id %d did not match request id %d", got, id)
	}
	if rcode := resp[3] & 0x0f; rcode != 0 {
		return fmt.Errorf("rfc2136: update failed with DNS rcode %d", rcode)
	}
	return nil
}

func (p *Provider) buildUpdate(class uint16, ttl uint32, name, value string) ([]byte, uint16, error) {
	id := p.nextID()
	var msg []byte
	msg = appendUint16(msg, id)
	msg = appendUint16(msg, opcodeUpdate)
	msg = appendUint16(msg, 1) // zone section
	msg = appendUint16(msg, 0) // prerequisites
	msg = appendUint16(msg, 1) // updates
	msg = appendUint16(msg, 0) // additional; TSIG appended below rewrites this

	var err error
	if msg, err = appendQuestion(msg, p.zone, dnsTypeSOA, dnsClassIN); err != nil {
		return nil, 0, err
	}
	if msg, err = appendTXTRecord(msg, fqdn(name), class, ttl, value); err != nil {
		return nil, 0, err
	}
	if len(p.creds.Secret) > 0 && strings.TrimSpace(p.creds.KeyName) != "" {
		msg, err = appendTSIG(msg, id, fqdn(p.creds.KeyName), p.creds.Secret, p.now())
		if err != nil {
			return nil, 0, err
		}
		msg = setARCount(msg, 1)
	}
	return msg, id, nil
}

type udpExchange struct {
	server string
}

func (e udpExchange) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	server := hostPort(e.server)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func randomID() uint16 {
	b, err := crypto.RandomBytes(2)
	if err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b)
}

func appendQuestion(msg []byte, name string, typ, class uint16) ([]byte, error) {
	out, err := appendName(msg, name)
	if err != nil {
		return nil, err
	}
	out = appendUint16(out, typ)
	out = appendUint16(out, class)
	return out, nil
}

func appendTXTRecord(msg []byte, name string, class uint16, ttl uint32, value string) ([]byte, error) {
	out, err := appendName(msg, name)
	if err != nil {
		return nil, err
	}
	rdata, err := txtRData(value)
	if err != nil {
		return nil, err
	}
	out = appendUint16(out, dnsTypeTXT)
	out = appendUint16(out, class)
	out = appendUint32(out, ttl)
	out = appendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	return out, nil
}

func appendTSIG(msg []byte, id uint16, keyName string, secret []byte, now time.Time) ([]byte, error) {
	rdata, err := tsigRData(msg, id, keyName, secret, now)
	if err != nil {
		return nil, err
	}
	out, err := appendName(msg, keyName)
	if err != nil {
		return nil, err
	}
	out = appendUint16(out, dnsTypeTSIG)
	out = appendUint16(out, dnsClassANY)
	out = appendUint32(out, 0)
	out = appendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	return out, nil
}

func tsigRData(msg []byte, id uint16, keyName string, secret []byte, now time.Time) ([]byte, error) {
	var signed []byte
	signed = append(signed, msg...)
	var err error
	if signed, err = appendName(signed, strings.ToLower(keyName)); err != nil {
		return nil, err
	}
	signed = appendUint16(signed, dnsClassANY)
	signed = appendUint32(signed, 0)
	if signed, err = appendTSIGVars(signed, now, 0); err != nil {
		return nil, err
	}
	mac := crypto.HMACSHA256(secret, signed)

	var rdata []byte
	if rdata, err = appendTSIGVars(rdata, now, uint16(len(mac))); err != nil {
		return nil, err
	}
	rdata = append(rdata, mac...)
	rdata = appendUint16(rdata, id)
	rdata = appendUint16(rdata, 0) // error
	rdata = appendUint16(rdata, 0) // other len
	return rdata, nil
}

func appendTSIGVars(out []byte, now time.Time, macSize uint16) ([]byte, error) {
	var err error
	if out, err = appendName(out, tsigAlg); err != nil {
		return nil, err
	}
	secs := uint64(now.Unix())
	out = append(out, byte(secs>>40), byte(secs>>32), byte(secs>>24), byte(secs>>16), byte(secs>>8), byte(secs))
	out = appendUint16(out, tsigFudge)
	out = appendUint16(out, macSize)
	return out, nil
}

func appendName(out []byte, name string) ([]byte, error) {
	name = fqdn(name)
	if name == "." {
		return append(out, 0), nil
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("rfc2136: invalid DNS label in %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func txtRData(value string) ([]byte, error) {
	if value == "" {
		return []byte{0}, nil
	}
	raw := []byte(value)
	var out []byte
	for len(raw) > 0 {
		n := len(raw)
		if n > 255 {
			n = 255
		}
		out = append(out, byte(n))
		out = append(out, raw[:n]...)
		raw = raw[n:]
	}
	return out, nil
}

func appendUint16(out []byte, v uint16) []byte {
	return append(out, byte(v>>8), byte(v))
}

func appendUint32(out []byte, v uint32) []byte {
	return append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func setARCount(msg []byte, count uint16) []byte {
	binary.BigEndian.PutUint16(msg[10:12], count)
	return msg
}

func fqdn(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return "."
	}
	return strings.TrimRight(name, ".") + "."
}

func hostPort(server string) string {
	if strings.TrimSpace(server) == "" {
		return "localhost:53"
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}
