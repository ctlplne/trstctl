// SPDX-License-Identifier: BUSL-1.1

// Package sessionobserve is the host TLS session observer (X5). An agent that
// holds the session-observer role attaches probes to the host's OpenSSL 3
// libraries and reads, for each TLS handshake a process on the host makes or
// accepts, what it negotiated — the TLS version, cipher suite and
// key-exchange group — and the peer's certificate, which TLS 1.3 encrypts on
// the wire where the passive observer (X1) cannot see it. The probes
// (bpf/sessionobserve.bpf.c) copy only the plaintext handshake records an SSL
// exchanges with its own BIOs, each direction stopping at its first record
// that is not a handshake record, and the certificates the library parses
// during a handshake call: no application data and no encrypted byte leaves
// the kernel, and nothing here keeps a certificate, only its facts. Attaching
// needs Linux and BPF privileges (observer_linux.go); everything else here is
// portable and tested without them.
package sessionobserve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agent/observe"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The event types and directions the probes send.
const (
	eventHandshake   = 1
	eventRecord      = 2
	eventCertificate = 3
	eventStreamEnd   = 4
	eventRelease     = 5

	dirRead  = 1
	dirWrite = 2

	// streamEndOutOfStep is a direction the probes stopped following because
	// a record header was split across reads.
	streamEndOutOfStep = 2
)

// Bounds the assembler holds to, matching the probes'.
const (
	streamMax = 16 << 10
	certsMax  = 4
	// idleAfter drops an SSL whose handshake neither finished nor moved.
	idleAfter = 30 * time.Second
	// settleAfter finishes an SSL whose handshake happened inside a read or a
	// write, with no handshake call to say it ended: both directions stopped.
	settleAfter = 2 * time.Second
)

// eventHeaderSize is the fixed part of struct event; data follows.
const eventHeaderSize = 56

// Event is one record from the probes' ring buffer.
type Event struct {
	Type   uint32
	PID    uint32
	TID    uint32
	SSL    uint64
	Ret    int64
	Offset uint64
	Comm   string
	Data   []byte
}

// DecodeEvent reads one ring-buffer sample (struct event, little-endian).
// Data aliases raw.
func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventHeaderSize {
		return Event{}, fmt.Errorf("session observer event of %d bytes is shorter than its header", len(raw))
	}
	le := binary.LittleEndian
	e := Event{
		Type: le.Uint32(raw[0:]), PID: le.Uint32(raw[4:]), TID: le.Uint32(raw[8:]),
		SSL: le.Uint64(raw[16:]), Ret: int64(le.Uint64(raw[24:])), Offset: le.Uint64(raw[32:]), // #nosec G115 -- a signed C field read back as signed (CWE-190)
	}
	comm := raw[40:56]
	if i := strings.IndexByte(string(comm), 0); i >= 0 {
		comm = comm[:i]
	}
	e.Comm = string(comm)
	n := int(le.Uint32(raw[12:]))
	if n > len(raw)-eventHeaderSize {
		return Event{}, errors.New("session observer event claims more data than it carries")
	}
	e.Data = raw[eventHeaderSize : eventHeaderSize+n]
	return e, nil
}

// Session is one TLS handshake a process on the host completed.
type Session struct {
	PID        uint32
	Process    string // the command name the kernel records for the thread
	Executable string // the process's executable, where it could be read
	Side       string // client or server
	Obs        observe.Observation
	// Peer is the other side's certificate: the server's for a client, the
	// client's (mutual TLS) for a server.
	Peer       *observe.CertificateFacts
	HelloRetry bool
	At         time.Time
}

// Stats counts what the assembler did and did not turn into sessions.
type Stats struct {
	Events    uint64 `json:"events"`
	Sessions  uint64 `json:"sessions"`
	Unparsed  uint64 `json:"unparsed"`
	OutOfStep uint64 `json:"out_of_step"`
	Gaps      uint64 `json:"gaps"`
	Truncated uint64 `json:"truncated_certificates"`
	TableFull uint64 `json:"table_full"`
	Idle      uint64 `json:"idle_dropped"`
	RingDrops uint64 `json:"ring_drops"`
}

type sslKey struct {
	pid uint32
	ssl uint64
}

type pendingSSL struct {
	read, write []byte
	readEnded   bool
	writeEnded  bool
	broken      bool
	certs       [][]byte
	comm        string
	lastSeen    time.Time
}

// Assembler turns probe events into sessions. It is safe for concurrent use.
type Assembler struct {
	mu         sync.Mutex
	open       map[sslKey]*pendingSSL
	maxOpen    int
	emit       func(Session)
	executable func(pid uint32) string
	stats      Stats
}

// NewAssembler follows at most maxOpen handshakes at once and calls emit
// with each completed session.
func NewAssembler(maxOpen int, emit func(Session)) *Assembler {
	return &Assembler{open: map[sslKey]*pendingSSL{}, maxOpen: maxOpen, emit: emit, executable: func(uint32) string { return "" }}
}

// Stats returns the counters so far.
func (a *Assembler) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}

// Add applies one event.
func (a *Assembler) Add(e Event, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Events++
	key := sslKey{pid: e.PID, ssl: e.SSL}
	p := a.open[key]
	switch e.Type {
	case eventRecord, eventCertificate, eventStreamEnd:
		if p == nil {
			if len(a.open) >= a.maxOpen {
				a.stats.TableFull++
				return
			}
			p = &pendingSSL{comm: e.Comm}
			a.open[key] = p
		}
		p.lastSeen = now
	case eventHandshake:
		if p != nil && e.Ret == 1 {
			a.finish(key, p, now)
		}
		return
	case eventRelease:
		if p != nil {
			if p.readEnded && p.writeEnded {
				a.finish(key, p, now)
			} else {
				delete(a.open, key)
			}
		}
		return
	default:
		return
	}
	switch e.Type {
	case eventRecord:
		stream := &p.read
		if e.Ret == dirWrite {
			stream = &p.write
		}
		if p.broken || uint64(len(*stream)) != e.Offset || len(*stream)+len(e.Data) > streamMax {
			if !p.broken {
				a.stats.Gaps++
			}
			p.broken = true
			return
		}
		*stream = append(*stream, e.Data...)
	case eventCertificate:
		if len(p.certs) >= certsMax {
			return
		}
		if uint64(len(e.Data)) < e.Offset {
			a.stats.Truncated++
			p.certs = append(p.certs, nil)
			return
		}
		p.certs = append(p.certs, append([]byte(nil), e.Data...))
	case eventStreamEnd:
		if e.Ret == dirWrite {
			p.writeEnded = true
		} else {
			p.readEnded = true
		}
		if e.Offset == streamEndOutOfStep {
			a.stats.OutOfStep++
		}
	}
}

// Sweep finishes handshakes that ended without a handshake call to say so
// and drops ones that stopped moving.
func (a *Assembler) Sweep(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, p := range a.open {
		idle := now.Sub(p.lastSeen)
		switch {
		case p.readEnded && p.writeEnded && idle >= settleAfter:
			a.finish(key, p, now)
		case idle >= idleAfter:
			a.stats.Idle++
			delete(a.open, key)
		}
	}
}

// clientHello reports whether b starts with a TLS record holding a
// ClientHello.
func clientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func (a *Assembler) finish(key sslKey, p *pendingSSL, now time.Time) {
	delete(a.open, key)
	if p.broken {
		a.stats.Unparsed++
		return
	}
	client, server, side := p.write, p.read, "client"
	switch {
	case clientHello(p.write):
	case clientHello(p.read):
		client, server, side = p.read, p.write, "server"
	default:
		a.stats.Unparsed++
		return
	}
	obs, retry, ok := observe.ParseSession(client, server)
	if !ok {
		a.stats.Unparsed++
		return
	}
	// The certificate a TLS 1.2 server sends in the clear is the server's,
	// which for a server is its own; the peer's certificate is the first one
	// the library parsed during the handshake.
	obs.CertificateDER = nil
	var peer *observe.CertificateFacts
	if len(p.certs) > 0 && p.certs[0] != nil {
		if info, err := certinfo.Inspect(p.certs[0]); err == nil {
			peer = &observe.CertificateFacts{SHA256: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
				PublicKeyBits: info.PublicKeyBits, NotAfter: info.NotAfter.UTC()}
		}
	}
	a.stats.Sessions++
	if a.emit != nil {
		a.emit(Session{PID: key.pid, Process: p.comm, Executable: a.executable(key.pid), Side: side, Obs: obs,
			Peer: peer, HelloRetry: retry, At: now})
	}
}

// Item is one process's TLS sessions with the same facts, with how often
// they were seen: a busy client is one item, not one per connection.
type Item struct {
	Ref        string
	Process    string
	Executable string
	Side       string
	Obs        observe.Observation
	Peer       *observe.CertificateFacts
	HelloRetry bool
	Sessions   uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	dirty      bool
}

// Aggregate folds sessions into items. It is safe for concurrent use.
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

func itemRef(s Session) string {
	who := s.Executable
	if who == "" {
		who = s.Process
	}
	peer := "-"
	if s.Peer != nil {
		peer = s.Peer.SHA256
	}
	return strings.Join([]string{"tls-session", who, s.Side, s.Obs.ServerName, s.Obs.TLSVersion, s.Obs.CipherSuite, s.Obs.Group, peer}, "|")
}

// Add records one session.
func (g *Aggregate) Add(s Session) {
	ref := itemRef(s)
	g.mu.Lock()
	defer g.mu.Unlock()
	item := g.items[ref]
	if item == nil {
		if len(g.items) >= g.maxItems {
			g.dropped++
			return
		}
		item = &Item{Ref: ref, Process: s.Process, Executable: s.Executable, Side: s.Side, Obs: s.Obs, Peer: s.Peer,
			HelloRetry: s.HelloRetry, FirstSeen: s.At}
		g.items[ref] = item
	}
	item.Sessions++
	item.LastSeen = s.At
	item.dirty = true
}

// Changed returns a copy of every item seen since the last call, in
// reference order, and how many distinct items were refused for room.
func (g *Aggregate) Changed() ([]Item, uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Item
	for _, item := range g.items {
		if item.dirty {
			item.dirty = false
			out = append(out, *item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, g.dropped
}
