// SPDX-License-Identifier: BUSL-1.1

package sessionobserve

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }                // #nosec G115 -- big-endian packing of bounded test lengths (CWE-190)
func u24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} } // #nosec G115 -- big-endian packing of bounded test lengths (CWE-190)

func vec16(b ...[]byte) []byte { j := bytes.Join(b, nil); return append(u16(len(j)), j...) }
func vec8(b []byte) []byte     { return append([]byte{byte(len(b))}, b...) } // #nosec G115 -- test vectors are under 256 bytes (CWE-190)

func ext(typ int, data []byte) []byte { return append(append(u16(typ), u16(len(data))...), data...) }

func record(kind byte, body []byte) []byte {
	return append(append([]byte{kind, 0x03, 0x03}, u16(len(body))...), body...)
}

func message(kind byte, body []byte) []byte {
	return append(append([]byte{kind}, u24(len(body))...), body...)
}

func clientHelloRecord(sni string, groups ...int) []byte {
	var groupBytes []byte
	for _, g := range groups {
		groupBytes = append(groupBytes, u16(g)...)
	}
	name := append([]byte{0}, vec16([]byte(sni))...)
	exts := bytes.Join([][]byte{ext(0, vec16(name)), ext(10, vec16(groupBytes)), ext(43, vec8(u16(0x0304)))}, nil)
	body := bytes.Join([][]byte{u16(0x0303), make([]byte, 32), vec8(nil), vec16(u16(0x1301), u16(0x1302)), vec8([]byte{0}), vec16(exts)}, nil)
	return record(0x16, message(1, body))
}

// helloRetry is the fixed ServerHello.random of a HelloRetryRequest.
var helloRetry = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

func serverHelloRecord(suite, group int, random []byte) []byte {
	if random == nil {
		random = make([]byte, 32)
	}
	exts := bytes.Join([][]byte{ext(43, u16(0x0304)), ext(51, append(u16(group), vec16(make([]byte, 32))...))}, nil)
	body := bytes.Join([][]byte{u16(0x0303), random, vec8(nil), u16(suite), {0}, vec16(exts)}, nil)
	return record(0x16, message(2, body))
}

// peerDER is testdata/peer.pem, a P-256 certificate made by stock OpenSSL;
// peerSHA256 is its SHA-256 fingerprint as `openssl x509 -fingerprint
// -sha256` printed it.
const peerSHA256 = "a78977895698b11f4651bc53146b3b82d75f24020c9650fb8a005ad7b6568095"

func peerDER(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/peer.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("testdata/peer.pem holds no PEM block")
	}
	return block.Bytes
}

func rawEvent(typ, pid, tid uint32, ssl uint64, ret int64, offset uint64, comm string, data []byte) []byte {
	b := make([]byte, eventHeaderSize+len(data))
	le := binary.LittleEndian
	le.PutUint32(b[0:], typ)
	le.PutUint32(b[4:], pid)
	le.PutUint32(b[8:], tid)
	le.PutUint32(b[12:], uint32(len(data))) // #nosec G115 -- test payloads are small (CWE-190)
	le.PutUint64(b[16:], ssl)
	le.PutUint64(b[24:], uint64(ret)) // #nosec G115 -- the C field is signed (CWE-190)
	le.PutUint64(b[32:], offset)
	copy(b[40:56], comm)
	copy(b[56:], data)
	return b
}

func TestDecodeEventReadsTheProbeLayout(t *testing.T) {
	raw := rawEvent(eventRecord, 41, 42, 0xdeadbeef, dirWrite, 7, "curl", []byte{0x16, 0x03, 0x01})
	e, err := DecodeEvent(raw)
	if err != nil || e.Type != eventRecord || e.PID != 41 || e.TID != 42 || e.SSL != 0xdeadbeef || e.Ret != dirWrite ||
		e.Offset != 7 || e.Comm != "curl" || !bytes.Equal(e.Data, []byte{0x16, 0x03, 0x01}) {
		t.Fatalf("decoded %+v (%v)", e, err)
	}
	e, err = DecodeEvent(rawEvent(eventHandshake, 1, 1, 1, -1, 0, "openssl-with-a-long-name", nil))
	if err != nil || e.Ret != -1 || e.Comm != "openssl-with-a-l" {
		t.Fatalf("a failed handshake call = %+v (%v)", e, err)
	}
	if _, err := DecodeEvent(raw[:eventHeaderSize-1]); err == nil {
		t.Fatal("a sample shorter than the header decoded")
	}
	short := rawEvent(eventRecord, 1, 1, 1, dirRead, 0, "x", []byte{1, 2})
	if _, err := DecodeEvent(short[:len(short)-1]); err == nil {
		t.Fatal("a sample shorter than the data it claims decoded")
	}
}

type harness struct {
	t        *testing.T
	asm      *Assembler
	sessions []Session
	now      time.Time
}

func newHarness(t *testing.T, maxOpen int) *harness {
	h := &harness{t: t, now: time.Unix(1_800_000_000, 0)}
	h.asm = NewAssembler(maxOpen, func(s Session) { h.sessions = append(h.sessions, s) })
	return h
}

func (h *harness) add(typ uint32, ssl uint64, ret int64, offset uint64, data []byte) {
	h.t.Helper()
	e, err := DecodeEvent(rawEvent(typ, 100, 101, ssl, ret, offset, "openssl", data))
	if err != nil {
		h.t.Fatal(err)
	}
	h.asm.Add(e, h.now)
}

// stream sends a direction's bytes as the probes would, in chunks of at most
// n bytes with their offsets, then ends the direction.
func (h *harness) stream(ssl uint64, dir int64, b []byte, n int) {
	for off := 0; off < len(b); off += n {
		end := min(off+n, len(b))
		h.add(eventRecord, ssl, dir, uint64(off), b[off:end]) // #nosec G115 -- small test offsets (CWE-190)
	}
	h.add(eventStreamEnd, ssl, dir, 1, nil)
}

// TestAssemblerReadsATLS13ClientSessionWithItsPeerCertificateX5: a client's
// handshake — its ClientHello written, the ServerHello read in two pieces
// (the header, then the body), each direction stopped, the server's
// certificate parsed during the call — becomes one session when the call
// returns 1: TLS 1.3 with X25519MLKEM768 and the peer certificate's facts.
// A call that returns -1 (the handshake waits for the network) does not end it.
func TestAssemblerReadsATLS13ClientSessionWithItsPeerCertificateX5(t *testing.T) {
	h := newHarness(t, 16)
	der := peerDER(t)
	h.stream(0x5551, dirWrite, clientHelloRecord("api.x5.test", 0x11ec, 0x001d), 4096)
	sh := serverHelloRecord(0x1302, 0x11ec, nil)
	h.add(eventRecord, 0x5551, dirRead, 0, sh[:5])
	h.add(eventRecord, 0x5551, dirRead, 5, sh[5:])
	h.add(eventStreamEnd, 0x5551, dirRead, 1, nil)
	h.add(eventCertificate, 0x5551, 0, uint64(len(der)), der)
	h.add(eventHandshake, 0x5551, -1, 0, nil)
	if len(h.sessions) != 0 {
		t.Fatal("a handshake call that returned -1 finished the session")
	}
	h.add(eventHandshake, 0x5551, 1, 0, nil)
	if len(h.sessions) != 1 {
		t.Fatalf("%d sessions, want 1", len(h.sessions))
	}
	s := h.sessions[0]
	if s.Side != "client" || s.PID != 100 || s.Process != "openssl" || s.Obs.TLSVersion != "TLSv1.3" || s.Obs.Group != "X25519MLKEM768" ||
		s.Obs.CipherSuite != "TLS_AES_256_GCM_SHA384" || s.Obs.ServerName != "api.x5.test" || s.HelloRetry || s.Obs.CertificateDER != nil {
		t.Fatalf("session %+v", s)
	}
	if s.Peer == nil || s.Peer.SHA256 != peerSHA256 || s.Peer.KeyAlgorithm != "ECDSA" || s.Peer.PublicKeyBits != 256 {
		t.Fatalf("peer certificate %+v, want the facts of testdata/peer.pem", s.Peer)
	}
	if st := h.asm.Stats(); st.Sessions != 1 || st.Unparsed != 0 || len(h.asm.open) != 0 {
		t.Fatalf("stats %+v, %d still open", st, len(h.asm.open))
	}
}

// TestAssemblerReadsAServerSessionAndAHelloRetryX5: a server reads the
// ClientHello and writes a HelloRetryRequest, after which everything it
// writes follows a ChangeCipherSpec; the session reports the settled group as
// a retry, from the server's side, with the client's certificate (mutual
// TLS) as the peer's.
func TestAssemblerReadsAServerSessionAndAHelloRetryX5(t *testing.T) {
	h := newHarness(t, 16)
	h.stream(7, dirRead, clientHelloRecord("db.x5.test", 0x11ec, 0x0017), 4096)
	h.stream(7, dirWrite, serverHelloRecord(0x1301, 0x0017, helloRetry), 4096)
	h.add(eventCertificate, 7, 0, uint64(len(peerDER(t))), peerDER(t))
	h.add(eventHandshake, 7, 1, 0, nil)
	if len(h.sessions) != 1 {
		t.Fatalf("%d sessions, want 1", len(h.sessions))
	}
	s := h.sessions[0]
	if s.Side != "server" || !s.HelloRetry || s.Obs.Group != "secp256r1" || s.Obs.TLSVersion != "TLSv1.3" || s.Peer == nil || s.Peer.SHA256 != peerSHA256 {
		t.Fatalf("server session %+v (peer %+v)", s, s.Peer)
	}
}

// TestAssemblerRefusesWhatItCannotTrustX5: bytes that skip ahead (a dropped
// event) and directions that do not start with a ClientHello are not
// sessions; a certificate the probes cut short is counted and not inspected;
// an SSL freed before its handshake ended is forgotten; a handshake done
// inside a read or write (no call to end it) finishes once both directions
// stopped and settled; idle handshakes are dropped; the table is bounded.
func TestAssemblerRefusesWhatItCannotTrustX5(t *testing.T) {
	h := newHarness(t, 2)
	ch := clientHelloRecord("gap.x5.test", 0x001d)
	h.add(eventRecord, 1, dirWrite, 0, ch[:10])
	h.add(eventRecord, 1, dirWrite, 20, ch[20:])
	h.stream(1, dirRead, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.add(eventHandshake, 1, 1, 0, nil)

	h.stream(2, dirWrite, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.stream(2, dirRead, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.add(eventHandshake, 2, 1, 0, nil)
	if len(h.sessions) != 0 {
		t.Fatalf("untrusted bytes became sessions: %+v", h.sessions)
	}
	if st := h.asm.Stats(); st.Gaps != 1 || st.Unparsed != 2 {
		t.Fatalf("stats %+v, want one gap and two unparsed", st)
	}

	der := peerDER(t)
	h.stream(3, dirWrite, clientHelloRecord("cut.x5.test", 0x001d), 4096)
	h.stream(3, dirRead, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.add(eventCertificate, 3, 0, uint64(len(der))+100, der)
	h.add(eventHandshake, 3, 1, 0, nil)
	if len(h.sessions) != 1 || h.sessions[0].Peer != nil || h.asm.Stats().Truncated != 1 {
		t.Fatalf("a cut-short certificate: %+v, stats %+v", h.sessions, h.asm.Stats())
	}

	h.add(eventRecord, 4, dirWrite, 0, clientHelloRecord("freed.x5.test", 0x001d))
	h.add(eventRelease, 4, 1, 0, nil)
	h.add(eventHandshake, 4, 1, 0, nil)
	if len(h.sessions) != 1 {
		t.Fatal("an SSL freed mid-handshake became a session")
	}

	h.stream(5, dirWrite, clientHelloRecord("implicit.x5.test", 0x001d), 4096)
	h.stream(5, dirRead, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.asm.Sweep(h.now.Add(settleAfter - time.Millisecond))
	if len(h.sessions) != 1 {
		t.Fatal("a handshake finished before it settled")
	}
	h.asm.Sweep(h.now.Add(settleAfter))
	if len(h.sessions) != 2 || h.sessions[1].Obs.ServerName != "implicit.x5.test" || h.sessions[1].Peer != nil {
		t.Fatalf("a handshake inside a read: %+v", h.sessions)
	}

	h.add(eventRecord, 6, dirWrite, 0, clientHelloRecord("idle.x5.test", 0x001d))
	h.add(eventRecord, 7, dirWrite, 0, clientHelloRecord("second.x5.test", 0x001d))
	h.add(eventRecord, 8, dirWrite, 0, clientHelloRecord("third.x5.test", 0x001d))
	if st := h.asm.Stats(); st.TableFull != 1 || len(h.asm.open) != 2 {
		t.Fatalf("a third open handshake past a table of two: stats %+v, %d open", st, len(h.asm.open))
	}
	h.asm.Sweep(h.now.Add(idleAfter))
	if st := h.asm.Stats(); st.Idle != 2 || len(h.asm.open) != 0 {
		t.Fatalf("idle handshakes: stats %+v, %d open", st, len(h.asm.open))
	}
}

// TestAggregateFoldsSessionsByProcessAndFacts: one item per process, side,
// server name, negotiated facts and peer certificate, with a count; Changed
// returns only what moved, and the table is bounded.
func TestAggregateFoldsSessionsByProcessAndFacts(t *testing.T) {
	h := newHarness(t, 16)
	for i := uint64(1); i <= 3; i++ {
		h.stream(i, dirWrite, clientHelloRecord("api.x5.test", 0x11ec), 4096)
		h.stream(i, dirRead, serverHelloRecord(0x1302, 0x11ec, nil), 4096)
		h.add(eventCertificate, i, 0, uint64(len(peerDER(t))), peerDER(t))
		h.add(eventHandshake, i, 1, 0, nil)
	}
	h.stream(9, dirWrite, clientHelloRecord("other.x5.test", 0x001d), 4096)
	h.stream(9, dirRead, serverHelloRecord(0x1301, 0x001d, nil), 4096)
	h.add(eventHandshake, 9, 1, 0, nil)
	agg := NewAggregate(1)
	for _, s := range h.sessions {
		agg.Add(s)
	}
	items, dropped := agg.Changed()
	if len(items) != 1 || items[0].Sessions != 3 || items[0].Obs.Group != "X25519MLKEM768" || items[0].Peer.SHA256 != peerSHA256 || dropped != 1 {
		t.Fatalf("items %+v dropped %d", items, dropped)
	}
	if !strings.HasPrefix(items[0].Ref, "tls-session|openssl|client|api.x5.test|TLSv1.3|") {
		t.Fatalf("item reference %q", items[0].Ref)
	}
	if again, _ := agg.Changed(); len(again) != 0 {
		t.Fatalf("unchanged items reported again: %+v", again)
	}
}
