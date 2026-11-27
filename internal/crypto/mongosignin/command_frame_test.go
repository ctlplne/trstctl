// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type commandFrameConn struct {
	net.Conn
	reply *bytes.Reader
}

func (c *commandFrameConn) Read(p []byte) (int, error) { return c.reply.Read(p) }
func (*commandFrameConn) Write(p []byte) (int, error)  { return len(p), nil }

func commandFrame(payload []byte) []byte {
	return append(MessageHeader(16+len(payload), 1, 0, OpMsg), payload...)
}

func commandPayload(flags uint32, doc []byte) []byte {
	payload := binary.LittleEndian.AppendUint32(nil, flags)
	payload = append(payload, 0)
	return append(payload, doc...)
}

func TestCommandRequiresCompleteReplyDocument(t *testing.T) {
	valid := Encode([]E{{"ok", float64(1)}})
	for _, tc := range []struct {
		name    string
		payload []byte
		valid   bool
	}{
		{name: "empty document", payload: commandPayload(0, nil)},
		{name: "partial document", payload: commandPayload(0, []byte{1, 2, 3})},
		{name: "short checksum", payload: commandPayload(FlagChecksumPresent, []byte{1, 2, 3})},
		{name: "checksum without document", payload: commandPayload(FlagChecksumPresent, []byte{1, 2, 3, 4})},
		{name: "declared length below minimum", payload: commandPayload(0, []byte{4, 0, 0, 0, 0})},
		{name: "declared length beyond frame", payload: commandPayload(0, []byte{6, 0, 0, 0, 0})},
		{name: "complete document", payload: commandPayload(0, valid), valid: true},
		{name: "complete document with checksum", payload: commandPayload(FlagChecksumPresent, append(append([]byte(nil), valid...), 1, 2, 3, 4)), valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &commandFrameConn{reply: bytes.NewReader(commandFrame(tc.payload))}
			reply, err := command(conn, []E{{"hello", int32(1)}})
			if tc.valid {
				if err != nil || !bytes.Equal(reply, valid) {
					t.Fatalf("complete reply = %x, %v", reply, err)
				}
			} else if err == nil {
				t.Fatalf("incomplete reply accepted: %x", reply)
			}
		})
	}
}
