package rfc2136

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/protocols/acme"
)

func TestProviderBuildsAddAndDeleteUpdates(t *testing.T) {
	fx := &recordingExchange{}
	p := New("127.0.0.1:5353", "example.com", Credentials{
		KeyName: "update-key.example.com",
		Secret:  []byte("tsig-secret"),
	}, WithExchange(fx), WithID(func() uint16 { return 0x1201 }), WithNow(func() time.Time {
		return time.Unix(1700000000, 0)
	}))

	if err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := p.CleanupTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(fx.messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(fx.messages))
	}

	add := parseUpdate(t, fx.messages[0])
	if add.id != 0x1201 || add.zone != "example.com." || add.name != "_acme-challenge.example.com." {
		t.Fatalf("bad add update: %+v", add)
	}
	if add.class != dnsClassIN || add.ttl != defaultTTL || add.value != "digest" {
		t.Fatalf("bad add rr: %+v", add)
	}
	if add.additional != 1 || add.tsigName != "update-key.example.com." {
		t.Fatalf("add update missing TSIG: %+v", add)
	}

	del := parseUpdate(t, fx.messages[1])
	if del.class != dnsClassNONE || del.ttl != 0 || del.value != "digest" {
		t.Fatalf("bad delete rr: %+v", del)
	}
}

func TestProviderConformsThroughDynamicUpdateExchange(t *testing.T) {
	mem := &acme.MemoryDNSProvider{}
	fx := &memoryExchange{mem: mem}
	p := New("127.0.0.1:5353", "example.com", Credentials{
		KeyName: "update-key.example.com",
		Secret:  []byte("tsig-secret"),
	}, WithExchange(fx), WithID(func() uint16 { return 0x4401 }), WithNow(func() time.Time {
		return time.Unix(1700000000, 0)
	}))

	if err := acme.ConformDNSProvider(context.Background(), p, mem); err != nil {
		t.Fatalf("conformance: %v", err)
	}
}

type recordingExchange struct {
	messages [][]byte
}

func (e *recordingExchange) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	e.messages = append(e.messages, append([]byte(nil), msg...))
	return successResponse(msg), nil
}

type memoryExchange struct {
	mem *acme.MemoryDNSProvider
}

func (e *memoryExchange) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	upd := parseUpdateNoTest(msg)
	switch upd.class {
	case dnsClassIN:
		if err := e.mem.PresentTXT(ctx, stringsTrimDot(upd.name), upd.value); err != nil {
			return nil, err
		}
	case dnsClassNONE:
		if err := e.mem.CleanupTXT(ctx, stringsTrimDot(upd.name), upd.value); err != nil {
			return nil, err
		}
	default:
		return rcodeResponse(msg, 1), nil
	}
	return successResponse(msg), nil
}

func successResponse(req []byte) []byte { return rcodeResponse(req, 0) }

func rcodeResponse(req []byte, rcode byte) []byte {
	resp := make([]byte, 12)
	copy(resp[0:2], req[0:2])
	resp[2] = 0x80
	resp[3] = rcode & 0x0f
	return resp
}

type parsedUpdate struct {
	id         uint16
	zone       string
	name       string
	class      uint16
	ttl        uint32
	value      string
	additional uint16
	tsigName   string
}

func parseUpdate(t *testing.T, msg []byte) parsedUpdate {
	t.Helper()
	return parseUpdateNoTest(msg)
}

func parseUpdateNoTest(msg []byte) parsedUpdate {
	pos := 0
	id := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 4
	zones := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2
	pos += 2 // prerequisites
	updates := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2
	additional := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2
	if zones != 1 || updates != 1 {
		return parsedUpdate{id: id}
	}
	zone, npos := readName(msg, pos)
	pos = npos + 4
	name, npos := readName(msg, pos)
	pos = npos
	typ := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2
	class := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2
	ttl := binary.BigEndian.Uint32(msg[pos : pos+4])
	pos += 4
	rdlen := int(binary.BigEndian.Uint16(msg[pos : pos+2]))
	pos += 2
	value := ""
	if typ == dnsTypeTXT && rdlen > 0 {
		txtLen := int(msg[pos])
		if txtLen < rdlen {
			value = string(msg[pos+1 : pos+1+txtLen])
		}
	}
	pos += rdlen
	tsigName := ""
	if additional > 0 && pos < len(msg) {
		tsigName, _ = readName(msg, pos)
	}
	return parsedUpdate{id: id, zone: zone, name: name, class: class, ttl: ttl, value: value, additional: additional, tsigName: tsigName}
}

func readName(msg []byte, pos int) (string, int) {
	var labels []string
	for {
		if pos >= len(msg) {
			return "", pos
		}
		n := int(msg[pos])
		pos++
		if n == 0 {
			break
		}
		labels = append(labels, string(msg[pos:pos+n]))
		pos += n
	}
	if len(labels) == 0 {
		return ".", pos
	}
	return stringsJoin(labels, ".") + ".", pos
}

func stringsJoin(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}

func stringsTrimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}
