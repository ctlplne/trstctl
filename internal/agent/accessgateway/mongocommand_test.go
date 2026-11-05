// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mongosignin"
)

func mongoRuleTestMessage(id int32, doc []mongosignin.E) []byte {
	body := append([]byte{0, 0, 0, 0, 0}, mongosignin.Encode(doc)...)
	return append(mongosignin.MessageHeader(16+len(body), id, 0, mongosignin.OpMsg), body...)
}

func TestMongoRuleFramesReserveBeforeAllocationAndPreserveBytes(t *testing.T) {
	raw := mongoRuleTestMessage(77, []mongosignin.E{{Key: "delete", Value: "notes"}, {Key: "$db", Value: "orders"}})
	reserved, released := 0, 0
	reserve := func(n int) (func(), bool) { reserved += n; return func() { released += n }, true }
	frame, err := readMongoRuleFrame(bytes.NewReader(raw), reserve)
	if err != nil || !bytes.Equal(frame.raw, raw) || reserved != len(raw) {
		t.Fatalf("valid Mongo frame changed: %v", err)
	}
	held := frame.raw
	frame.done()
	if released != reserved || !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("Mongo reservation/wipe lost")
	}
	for _, size := range []uint32{0, 16, 20, mongoRuleMaxMessage + 1, 0xffffffff} {
		var header [16]byte
		binary.LittleEndian.PutUint32(header[:], size)
		binary.LittleEndian.PutUint32(header[12:], uint32(mongosignin.OpMsg))
		before := reserved
		if _, err := readMongoRuleFrame(bytes.NewReader(header[:]), reserve); err == nil || reserved != before {
			t.Fatal("invalid length reached allocation")
		}
	}
	if _, err := readMongoRuleFrame(bytes.NewReader(raw), func(int) (func(), bool) { return nil, false }); !errors.Is(err, errCommandBusy) {
		t.Fatal("Mongo capacity did not fail before allocation")
	}
	if _, err := readMongoRuleFrame(bytes.NewReader(raw[:len(raw)-1]), reserve); err == nil || reserved != released {
		t.Fatal("partial frame leaked a reservation")
	}
}

func TestMongoAuthenticationAndHandshakeNeverEnterCommandPolicy(t *testing.T) {
	for _, name := range []string{"saslStart", "saslContinue", "authenticate", "logout"} {
		raw := mongoRuleTestMessage(77, []mongosignin.E{{Key: name, Value: int32(1)}, {Key: "payload", Value: []byte("a262-auth-value-canary")}})
		var upstream, client bytes.Buffer
		m := &mongoRelay{client: &client}
		err := forwardMongoRuleCommand(context.Background(), &upstream, m, &commandConnection{}, mongoRuleFrame{raw: raw})
		if err != nil || upstream.Len() != 0 || client.Len() < 16 || binary.LittleEndian.Uint32(client.Bytes()[8:]) != 77 || bytes.Contains(client.Bytes(), []byte("a262-auth-value-canary")) {
			t.Fatal("sign-in bytes entered policy, forwarding or refusal")
		}
	}
	raw := mongoRuleTestMessage(78, []mongosignin.E{{Key: "hello", Value: int32(1)}, {Key: "speculativeAuthenticate", Value: []mongosignin.E{{Key: "payload", Value: []byte("a262-auth-value-canary")}}}, {Key: "compression", Value: mongosignin.A{{Key: "0", Value: "zlib"}}}})
	var upstream, client bytes.Buffer
	if err := forwardMongoRuleCommand(context.Background(), &upstream, &mongoRelay{client: &client}, &commandConnection{}, mongoRuleFrame{raw: raw}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(upstream.Bytes(), []byte("a262-auth-value-canary")) || bytes.Contains(upstream.Bytes(), []byte("speculativeAuthenticate")) || bytes.Contains(upstream.Bytes(), []byte("compression")) {
		t.Fatal("handshake forwarded sign-in material")
	}
	if client.Len() != 0 {
		t.Fatal("sanitized handshake was locally refused")
	}
}

func FuzzMongoRuleFrame(f *testing.F) {
	f.Add(mongoRuleTestMessage(1, []mongosignin.E{{Key: "delete", Value: "notes"}, {Key: "$db", Value: "orders"}}))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		reserved := 0
		frame, err := readMongoRuleFrame(bytes.NewReader(raw), func(n int) (func(), bool) { reserved += n; return func() { reserved -= n }, true })
		if !bytes.Equal(before, raw) {
			t.Fatal("frame parser changed traffic")
		}
		if err == nil {
			if len(frame.raw) > mongoRuleMaxMessage || len(frame.raw) < 21 || !bytes.Equal(frame.raw, raw[:len(frame.raw)]) {
				t.Fatal("unbounded or invented frame")
			}
			if binary.LittleEndian.Uint32(frame.raw[12:]) == uint32(mongosignin.OpMsg) {
				if _, doc, rest, err := opMsgSections(frame.raw[16:]); err == nil {
					_, _, _ = commandName(doc)
					clear(rest)
				}
			}
			frame.done()
		}
		if reserved != 0 {
			t.Fatal("Mongo frame leaked reservation")
		}
	})
}

func TestMongoUnacknowledgedCleanupUsesGuardedCommandPath(t *testing.T) {
	raw := mongoRuleTestMessage(79, []mongosignin.E{{Key: "endSessions", Value: mongosignin.A{}}, {Key: "$db", Value: "admin"}})
	binary.LittleEndian.PutUint32(raw[16:], mongosignin.FlagMoreToCome)
	var upstream, client bytes.Buffer
	// An unmatched command needs no source call; no reviewer or credential is set.
	err := forwardMongoRuleCommand(context.Background(), &upstream, &mongoRelay{client: &client}, &commandConnection{}, mongoRuleFrame{raw: raw})
	if err != nil || !bytes.Equal(upstream.Bytes(), raw) || client.Len() != 0 {
		t.Fatal("normal unacknowledged cleanup lost its command path")
	}
}
