// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// wsFrame encodes one WebSocket frame, masked as a client's are when mask is
// set.
func wsFrame(opcode byte, payload []byte, mask bool) []byte {
	b := []byte{0x80 | opcode}
	n := len(payload)
	maskBit := byte(0)
	if mask {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		b = append(b, maskBit|byte(n)) // #nosec G115 -- a 7-bit length below 126 (CWE-190)
	case n < 1<<16:
		b = append(b, maskBit|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n)) // #nosec G115 -- under 1<<16 (CWE-190)
	default:
		b = append(b, maskBit|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n)) // #nosec G115 -- a payload length, never negative (CWE-190)
	}
	if !mask {
		return append(b, payload...)
	}
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	b = append(b, key[:]...)
	for i, c := range payload {
		b = append(b, c^key[i%4])
	}
	return b
}

func TestWebSocketReaderDecodesChannelsInAnyPieces(t *testing.T) {
	var got []string
	r := &wsReader{emit: func(ch byte, data []byte) { got = append(got, string(rune('0'+ch))+":"+string(data)) }}
	long := strings.Repeat("x", 300)
	stream := bytes.Join([][]byte{
		wsFrame(2, append([]byte{0}, "ls -la\n"...), true),
		wsFrame(9, []byte("ping"), true), // a control frame between messages
		wsFrame(2, append([]byte{1}, long...), true),
		wsFrame(2, append([]byte{2}, "denied\n"...), false),
	}, nil)
	// Fed a byte at a time, then all at once: the same messages.
	for i := range stream {
		r.feed(stream[i : i+1])
	}
	byteWise := strings.Join(got, "|")
	got = nil
	r2 := &wsReader{emit: func(ch byte, data []byte) { got = append(got, string(rune('0'+ch))+":"+string(data)) }}
	r2.feed(stream)
	whole := strings.Join(got, "|")
	want := "0:ls -la\n|1:" + long + "|2:denied\n"
	if whole != want || strings.ReplaceAll(byteWise, "|1:x", "") == "" {
		t.Fatalf("whole = %q", whole)
	}
	// A byte at a time hands the payload on in pieces; joined per channel
	// it is the same.
	var channels [3]strings.Builder
	for _, piece := range strings.Split(byteWise, "|") {
		_, _ = channels[piece[0]-'0'].WriteString(piece[2:])
	}
	if channels[0].String() != "ls -la\n" || channels[1].String() != long || channels[2].String() != "denied\n" {
		t.Fatalf("byte-wise channels = %q %q %q", channels[0].String(), channels[1].String(), channels[2].String())
	}
}

func TestWebSocketReaderDecodesTheBase64Channel(t *testing.T) {
	var out strings.Builder
	r := &wsReader{base64: true, emit: func(ch byte, data []byte) {
		if ch == 1 {
			out.Write(data)
		}
	}}
	r.feed(wsFrame(1, []byte("1"+base64.StdEncoding.EncodeToString([]byte("hello from the pod\n"))), false))
	if out.String() != "hello from the pod\n" {
		t.Fatalf("decoded %q", out.String())
	}
}

// FuzzWebSocketReader: no stream panics the reader.
func FuzzWebSocketReader(f *testing.F) {
	f.Add(wsFrame(2, []byte{1, 'a'}, true))
	f.Add(wsFrame(2, bytes.Repeat([]byte{1}, 70000), false))
	f.Add([]byte{0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := &wsReader{emit: func(byte, []byte) {}, base64: len(in)%2 == 0}
		r.feed(in)
	})
}
