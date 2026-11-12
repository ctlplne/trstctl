// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Item is one server endpoint and one set of handshake facts, with how often
// it was seen. A busy endpoint is one item, not one per connection.
type Item struct {
	Ref         string
	Kind        string // tls_handshake, ssh_kex or plaintext_protocol
	Server      netip.AddrPort
	Obs         Observation
	Certificate *CertificateFacts
	Connections uint64
	Clients     int
	FirstSeen   time.Time
	LastSeen    time.Time
	clients     map[netip.Addr]bool
	dirty       bool
}

// CertificateFacts is what a TLS 1.2 server certificate says, read through
// the crypto boundary; the certificate itself is not kept.
type CertificateFacts struct {
	SHA256        string
	KeyAlgorithm  string
	PublicKeyBits int
	NotAfter      time.Time
}

// maxClientsTracked bounds the distinct-client count per item.
const maxClientsTracked = 256

// Aggregate folds events into items. It is safe for concurrent use.
type Aggregate struct {
	mu       sync.Mutex
	items    map[string]*Item
	maxItems int
	dropped  uint64
}

// NewAggregate keeps at most maxItems distinct items.
func NewAggregate(maxItems int) *Aggregate {
	return &Aggregate{items: map[string]*Item{}, maxItems: maxItems}
}

// Add records one observed connection.
func (g *Aggregate) Add(e Event) {
	obs := e.Obs
	var cert *CertificateFacts
	if len(obs.CertificateDER) > 0 {
		if info, err := certinfo.Inspect(obs.CertificateDER); err == nil {
			cert = &CertificateFacts{SHA256: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
				PublicKeyBits: info.PublicKeyBits, NotAfter: info.NotAfter.UTC()}
		}
		obs.CertificateDER = nil
	}
	kind, ref := itemRef(e.Server, obs, cert)
	g.mu.Lock()
	defer g.mu.Unlock()
	item := g.items[ref]
	if item == nil {
		if len(g.items) >= g.maxItems {
			g.dropped++
			return
		}
		item = &Item{Ref: ref, Kind: kind, Server: e.Server, Obs: obs, Certificate: cert, FirstSeen: e.At, clients: map[netip.Addr]bool{}}
		g.items[ref] = item
	}
	item.Connections++
	item.LastSeen = e.At
	if len(item.clients) < maxClientsTracked {
		item.clients[e.Client] = true
	}
	item.Clients = len(item.clients)
	item.dirty = true
}

// Changed returns a copy of every item seen since the last call, oldest
// reference first, and how many distinct items were refused for room.
func (g *Aggregate) Changed() ([]Item, uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Item
	for _, item := range g.items {
		if !item.dirty {
			continue
		}
		item.dirty = false
		copied := *item
		copied.clients = nil
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, g.dropped
}

// itemRef names the item by endpoint and facts, so a change of version, group
// or certificate on one endpoint is a new item.
func itemRef(server netip.AddrPort, obs Observation, cert *CertificateFacts) (string, string) {
	switch {
	case obs.Plaintext:
		return "plaintext_protocol", fmt.Sprintf("plaintext %s %s", obs.PlaintextKind, server)
	case obs.Protocol == "ssh":
		return "ssh_kex", fmt.Sprintf("ssh %s %s %s", server, obs.KexAlgorithm, obs.HostKeyAlgorithm)
	}
	// QUIC and DTLS (X1-L4) name their protocol: the same server port can
	// also answer TLS over TCP.
	protocol := "tls"
	if obs.Protocol == "quic" || obs.Protocol == "dtls" {
		protocol = obs.Protocol
	}
	parts := []string{protocol, server.String(), obs.TLSVersion, obs.Group, obs.CipherSuite}
	if cert != nil {
		parts = append(parts, cert.SHA256[:16])
	}
	return "tls_handshake", strings.Join(parts, " ")
}

// PQHybrid says whether the negotiated key exchange is a post-quantum hybrid.
func (o Observation) PQHybrid() bool {
	name := strings.ToLower(o.Group + " " + o.KexAlgorithm)
	return strings.Contains(name, "mlkem") || strings.Contains(name, "sntrup")
}
