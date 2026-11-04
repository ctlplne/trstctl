// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mongosignin"
)

type mE = mongosignin.E

func opMsg(requestID int32, flags uint32, doc []mE, sequences ...[]byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, flags)
	body = append(append(body, 0), mongosignin.Encode(doc)...)
	for _, s := range sequences {
		body = append(body, s...)
	}
	if flags&mongosignin.FlagChecksumPresent != 0 {
		body = append(body, 1, 2, 3, 4)
	}
	return mongoMessage(requestID, 0, mongosignin.OpMsg, body)
}

func opQuery(requestID int32, collection string, doc []mE) []byte {
	body := []byte{0, 0, 0, 0}
	body = append(append(body, collection...), 0)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = append(body, mongosignin.Encode(doc)...)
	return mongoMessage(requestID, 0, mongosignin.OpQuery, body)
}

// readMessages splits a stream into messages: request id, response to, op
// code and body.
func readMessages(t *testing.T, b []byte) [][4]any {
	t.Helper()
	var out [][4]any
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		id, to, op, body, err := readMongoMessage(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, [4]any{id, to, op, body})
	}
	return out
}

func TestMongoRelayRefusesSignInsAndStripsHandshakes(t *testing.T) {
	find := opMsg(1, 0, []mE{{Key: "find", Value: "notes"}, {Key: "$db", Value: "orders"}})
	saslStart := opMsg(2, 0, []mE{{Key: "saslStart", Value: int32(1)}, {Key: "mechanism", Value: "SCRAM-SHA-256"}, {Key: "payload", Value: []byte("n,,n=root,r=x")}, {Key: "$db", Value: "admin"}})
	quietLogout := opMsg(3, mongosignin.FlagMoreToCome, []mE{{Key: "logout", Value: int32(1)}, {Key: "$db", Value: "admin"}})
	hello := opMsg(4, mongosignin.FlagChecksumPresent, []mE{{Key: "hello", Value: int32(1)}, {Key: "speculativeAuthenticate", Value: []mE{{Key: "saslStart", Value: int32(1)}}},
		{Key: "compression", Value: []mE{{Key: "0", Value: "zstd"}}}, {Key: "client", Value: []mE{{Key: "application", Value: []mE{{Key: "name", Value: "mongosh"}}}}}, {Key: "$db", Value: "admin"}})
	legacy := opQuery(5, "admin.$cmd", []mE{{Key: "isMaster", Value: int32(1)}, {Key: "speculativeAuthenticate", Value: []mE{{Key: "authenticate", Value: int32(1)}}}})
	var server, client bytes.Buffer
	rec, frames := testConnRecorder(t)
	m := &mongoRelay{client: &client, rec: rec}
	in := bytes.Join([][]byte{find, saslStart, quietLogout, hello, legacy}, nil)
	if err := m.requests(&server, bytes.NewReader(in)); err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	forwarded := readMessages(t, server.Bytes())
	if len(forwarded) != 3 {
		t.Fatalf("forwarded %d messages, want find, hello and the legacy handshake", len(forwarded))
	}
	if !bytes.Equal(server.Bytes()[:len(find)], find) {
		t.Fatal("find was not forwarded byte for byte")
	}
	helloBody := forwarded[1][3].([]byte)
	if binary.LittleEndian.Uint32(helloBody)&mongosignin.FlagChecksumPresent != 0 {
		t.Fatal("a rewritten hello kept its checksum flag")
	}
	for _, msg := range forwarded[1:] {
		body := string(msg[3].([]byte))
		if strings.Contains(body, "speculativeAuthenticate") || strings.Contains(body, "compression") || strings.Contains(body, "saslStart") {
			t.Fatalf("a handshake kept a removed field: %q", body)
		}
	}
	if !strings.Contains(string(helloBody), "mongosh") {
		t.Fatal("the hello lost its client metadata")
	}
	replies := readMessages(t, client.Bytes())
	if len(replies) != 1 || replies[0][1].(int32) != 2 {
		t.Fatalf("refusal replies = %v, want one answering request 2", replies)
	}
	_, doc, _, err := opMsgSections(replies[0][3].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := mongosignin.Lookup(doc, "code"); code.Type != mongosignin.TypeInt32 || !strings.Contains(string(doc), "saslStart is refused") {
		t.Fatalf("refusal = %q", doc)
	}
	text := frames()
	for _, want := range []string{`command: {find: "notes", $db: "orders"}`, "refused: saslStart", "refused: logout", `command: {hello: 1, client: {application: {name: "mongosh"}}, $db: "admin"}`} {
		if !strings.Contains(text, want) {
			t.Fatalf("recording lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "n=root") {
		t.Fatalf("a refused command's payload was recorded:\n%s", text)
	}
}

func TestMongoRelayEndsOnMessagesItDoesNotRelay(t *testing.T) {
	for name, msg := range map[string][]byte{
		"compressed":         mongoMessage(1, 0, mongosignin.OpCompressed, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}),
		"legacy insert":      mongoMessage(1, 0, 2002, []byte{0, 0, 0, 0}),
		"query on documents": opQuery(1, "orders.notes", []mE{{Key: "x", Value: int32(1)}}),
		"legacy saslStart":   opQuery(1, "admin.$cmd", []mE{{Key: "saslStart", Value: int32(1)}}),
	} {
		var server, client bytes.Buffer
		m := &mongoRelay{client: &client}
		if err := m.requests(&server, bytes.NewReader(msg)); !errors.Is(err, errMongoMessage) || server.Len() != 0 {
			t.Errorf("%s: err %v, forwarded %d bytes", name, err, server.Len())
		}
	}
}

func TestMongoReplyRelayForwardsAndRecords(t *testing.T) {
	reply := opMsg(9, 0, []mE{{Key: "cursor", Value: []mE{{Key: "firstBatch", Value: mongosignin.A{{Key: "0", Value: []mE{{Key: "note", Value: "ghp_" + strings.Repeat("Q", 36)}}}}},
		{Key: "id", Value: int64(0)}, {Key: "ns", Value: "orders.notes"}}}, {Key: "ok", Value: float64(1)}})
	var client bytes.Buffer
	rec, frames := testConnRecorder(t)
	m := &mongoRelay{client: &client, rec: rec}
	if err := m.replies(bytes.NewReader(reply)); err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	if !bytes.Equal(client.Bytes(), reply) {
		t.Fatal("the reply was not forwarded byte for byte")
	}
	text := frames()
	if !strings.Contains(text, `reply: {cursor: {firstBatch: [{note: "[masked:github-token]"}], id: 0, ns: "orders.notes"}, ok: 1.0}`) {
		t.Fatalf("recording:\n%s", text)
	}
}

// FuzzMongoRequestRelay: no client bytes panic the relay, and nothing it
// forwards signs the connection in again.
func FuzzMongoRequestRelay(f *testing.F) {
	f.Add(opMsg(1, 0, []mE{{Key: "find", Value: "notes"}}))
	f.Add(opMsg(2, 0, []mE{{Key: "saslStart", Value: int32(1)}}))
	f.Add(opMsg(3, 1, []mE{{Key: "hello", Value: int32(1)}, {Key: "speculativeAuthenticate", Value: []mE{}}}))
	f.Add(opQuery(4, "admin.$cmd", []mE{{Key: "isMaster", Value: int32(1)}}))
	f.Fuzz(func(t *testing.T, in []byte) {
		var server, client bytes.Buffer
		m := &mongoRelay{client: &client}
		_ = m.requests(&server, bytes.NewReader(in))
		r := bytes.NewReader(server.Bytes())
		for r.Len() > 0 {
			_, _, op, body, err := readMongoMessage(r)
			if err != nil {
				t.Fatalf("forwarded a malformed message from %q", in)
			}
			var doc []byte
			switch op {
			case mongosignin.OpMsg:
				_, doc, _, err = opMsgSections(body)
				if err != nil {
					t.Fatalf("forwarded an unreadable OP_MSG from %q", in)
				}
			case mongosignin.OpQuery:
				continue
			default:
				t.Fatalf("forwarded op %d from %q", op, in)
			}
			name, elems, err := commandName(doc)
			if err != nil || mongoRefused[strings.ToLower(name)] {
				t.Fatalf("forwarded %q from %q", name, in)
			}
			if isHandshake(name) {
				for _, e := range elems {
					if mongoHandshakeStrip[e.Key] {
						t.Fatalf("forwarded a handshake with %s from %q", e.Key, in)
					}
				}
			}
		}
	})
}
