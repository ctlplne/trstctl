package kmip

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestKMIPTTLVInterop(t *testing.T) {
	frame := kmipLocateRequestTTLV()

	root, err := ParseTTLV(frame)
	if err != nil {
		t.Fatalf("ParseTTLV: %v", err)
	}
	if root.Tag != TagRequestMessage || root.Type != TTLVStructure {
		t.Fatalf("root = tag %#06x type %#02x, want RequestMessage structure", root.Tag, root.Type)
	}

	msg, err := DecodeRequestMessage(frame)
	if err != nil {
		t.Fatalf("DecodeRequestMessage: %v", err)
	}
	if msg.ProtocolMajor != 1 || msg.ProtocolMinor != 4 {
		t.Fatalf("protocol = %d.%d, want 1.4", msg.ProtocolMajor, msg.ProtocolMinor)
	}
	if msg.BatchCount != 1 {
		t.Fatalf("batch count = %d, want 1", msg.BatchCount)
	}
	if len(msg.Operations) != 1 || msg.Operations[0] != OperationLocate {
		t.Fatalf("operations = %v, want Locate", msg.Operations)
	}

	s := New("tenant-a", certAuth{}, &auditsink.Recorder{})
	if _, err := s.DecodeTTLVRequest(context.Background(), []byte("good-client"), frame); err != nil {
		t.Fatalf("authenticated DecodeTTLVRequest: %v", err)
	}
	if _, err := s.DecodeTTLVRequest(context.Background(), []byte("anonymous"), frame); err == nil {
		t.Fatal("DecodeTTLVRequest allowed unauthenticated client cert")
	}
}

func TestParseTTLVRejectsResourceExhaustion(t *testing.T) {
	valid := kmipLocateRequestTTLV()
	if _, err := ParseTTLVWithLimits(valid, TTLVLimits{MaxFrameSize: len(valid) - 1, MaxFields: 64, MaxDepth: 16}); err == nil {
		t.Fatal("ParseTTLVWithLimits accepted an over-cap frame")
	}

	deep := ttlvStructure(0x420100,
		ttlvStructure(0x420101,
			ttlvStructure(0x420102,
				ttlvInteger(0x420103, 1),
			),
		),
	)
	if _, err := ParseTTLVWithLimits(deep, TTLVLimits{MaxFrameSize: len(deep), MaxFields: 64, MaxDepth: 2}); err == nil {
		t.Fatal("ParseTTLVWithLimits accepted an over-depth frame")
	}

	wide := ttlvStructure(0x420200,
		ttlvInteger(0x420201, 1),
		ttlvInteger(0x420202, 2),
	)
	if _, err := ParseTTLVWithLimits(wide, TTLVLimits{MaxFrameSize: len(wide), MaxFields: 2, MaxDepth: 8}); err == nil {
		t.Fatal("ParseTTLVWithLimits accepted an over-field-count frame")
	}
}

func kmipLocateRequestTTLV() []byte {
	return ttlvStructure(TagRequestMessage,
		ttlvStructure(TagRequestHeader,
			ttlvStructure(TagProtocolVersion,
				ttlvInteger(TagProtocolVersionMajor, 1),
				ttlvInteger(TagProtocolVersionMinor, 4),
			),
			ttlvInteger(TagBatchCount, 1),
		),
		ttlvStructure(TagBatchItem,
			ttlvEnumeration(TagOperation, int32(OperationLocate)),
		),
	)
}

func ttlvStructure(tag uint32, children ...[]byte) []byte {
	return ttlvEncode(tag, TTLVStructure, bytes.Join(children, nil))
}

func ttlvInteger(tag uint32, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return ttlvEncode(tag, TTLVInteger, buf[:])
}

func ttlvEnumeration(tag uint32, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return ttlvEncode(tag, TTLVEnumeration, buf[:])
}

func ttlvEncode(tag uint32, typ TTLVType, value []byte) []byte {
	out := make([]byte, 8+len(value)+ttlvPadding(len(value)))
	out[0] = byte(tag >> 16)
	out[1] = byte(tag >> 8)
	out[2] = byte(tag)
	out[3] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}
