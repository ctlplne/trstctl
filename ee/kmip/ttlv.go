package kmip

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TTLVType is the one-byte KMIP type code in the tag/type/length/value header.
type TTLVType byte

const (
	TTLVStructure   TTLVType = 0x01
	TTLVInteger     TTLVType = 0x02
	TTLVLongInteger TTLVType = 0x03
	TTLVBigInteger  TTLVType = 0x04
	TTLVEnumeration TTLVType = 0x05
	TTLVBoolean     TTLVType = 0x06
	TTLVTextString  TTLVType = 0x07
	TTLVByteString  TTLVType = 0x08
	TTLVDateTime    TTLVType = 0x09
	TTLVInterval    TTLVType = 0x0a
)

const (
	TagAttribute              uint32 = 0x420008
	TagAttributeName          uint32 = 0x42000a
	TagAttributeValue         uint32 = 0x42000b
	TagBatchCount             uint32 = 0x42000d
	TagBatchItem              uint32 = 0x42000f
	TagCryptographicAlgorithm uint32 = 0x420028
	TagCryptographicLength    uint32 = 0x42002a
	TagKeyBlock               uint32 = 0x420040
	TagKeyFormatType          uint32 = 0x420042
	TagKeyMaterial            uint32 = 0x420043
	TagKeyValue               uint32 = 0x420045
	TagOperation              uint32 = 0x42005c
	TagObjectType             uint32 = 0x420057
	TagProtocolVersion        uint32 = 0x420069
	TagProtocolVersionMajor   uint32 = 0x42006a
	TagProtocolVersionMinor   uint32 = 0x42006b
	TagRequestHeader          uint32 = 0x420077
	TagRequestMessage         uint32 = 0x420078
	TagRequestPayload         uint32 = 0x420079
	TagResponseHeader         uint32 = 0x42007a
	TagResponseMessage        uint32 = 0x42007b
	TagResponsePayload        uint32 = 0x42007c
	TagResultMessage          uint32 = 0x42007d
	TagResultReason           uint32 = 0x42007e
	TagResultStatus           uint32 = 0x42007f
	TagSymmetricKey           uint32 = 0x42008f
	TagTemplateAttribute      uint32 = 0x420091
	TagTimeStamp              uint32 = 0x420092
	TagUniqueIdentifier       uint32 = 0x420094
)

// Operation is the KMIP operation enumeration.
type Operation int32

const (
	OperationCreate  Operation = 0x00000001
	OperationLocate  Operation = 0x00000008
	OperationGet     Operation = 0x0000000a
	OperationRevoke  Operation = 0x00000013
	OperationDestroy Operation = 0x00000014
)

const (
	objectTypeSymmetricKey      int32 = 0x00000002
	cryptographicAlgorithmAES   int32 = 0x00000003
	keyFormatTypeRaw            int32 = 0x00000001
	resultStatusSuccess         int32 = 0x00000000
	resultStatusOperationFailed int32 = 0x00000001
	resultReasonItemNotFound    int32 = 0x00000001
	resultReasonAuthFailed      int32 = 0x00000003
	resultReasonInvalidMessage  int32 = 0x00000004
	resultReasonUnsupported     int32 = 0x00000005
	resultReasonInvalidField    int32 = 0x00000007
	resultReasonGeneralFailure  int32 = 0x00000100
)

// TTLV is one parsed KMIP tag/type/length/value node. Primitive Value bytes are
// copied out of the input frame so callers can discard the attacker-owned buffer.
type TTLV struct {
	Tag      uint32
	Type     TTLVType
	Length   uint32
	Value    []byte
	Children []TTLV
}

// TTLVLimits bounds parser work before any operation-level logic runs.
type TTLVLimits struct {
	MaxFrameSize int
	MaxFields    int
	MaxDepth     int
}

// DefaultTTLVLimits are deliberately small for a control-plane key-management
// ingress: enough for normal KMIP request envelopes, not enough for memory abuse.
var DefaultTTLVLimits = TTLVLimits{
	MaxFrameSize: 1 << 20,
	MaxFields:    4096,
	MaxDepth:     16,
}

// RequestMessage is the operation-level subset needed to route a KMIP request.
type RequestMessage struct {
	ProtocolMajor int
	ProtocolMinor int
	BatchCount    int
	Operations    []Operation
	BatchItems    []RequestBatchItem
}

// RequestBatchItem is the parsed operation and payload for one KMIP batch item.
type RequestBatchItem struct {
	Operation Operation
	Payload   TTLV
}

// ParseTTLV parses one complete KMIP TTLV frame with production defaults.
func ParseTTLV(frame []byte) (TTLV, error) {
	return ParseTTLVWithLimits(frame, DefaultTTLVLimits)
}

// ParseTTLVWithLimits parses one complete KMIP TTLV frame while enforcing frame,
// field-count, and nesting-depth caps.
func ParseTTLVWithLimits(frame []byte, limits TTLVLimits) (TTLV, error) {
	limits = normalizeTTLVLimits(limits)
	if len(frame) == 0 {
		return TTLV{}, errors.New("kmip ttlv: empty frame")
	}
	if len(frame) > limits.MaxFrameSize {
		return TTLV{}, fmt.Errorf("kmip ttlv: frame size %d exceeds cap %d", len(frame), limits.MaxFrameSize)
	}

	p := ttlvParser{limits: limits}
	root, n, err := p.parseItem(frame, 1)
	if err != nil {
		return TTLV{}, err
	}
	if n != len(frame) {
		return TTLV{}, fmt.Errorf("kmip ttlv: trailing bytes after top-level item: %d", len(frame)-n)
	}
	return root, nil
}

// DecodeRequestMessage parses a KMIP RequestMessage and returns the protocol
// version, declared batch count, and batch operations.
func DecodeRequestMessage(frame []byte) (RequestMessage, error) {
	root, err := ParseTTLV(frame)
	if err != nil {
		return RequestMessage{}, err
	}
	if root.Tag != TagRequestMessage || root.Type != TTLVStructure {
		return RequestMessage{}, fmt.Errorf("kmip ttlv: root tag/type = %#06x/%#02x, want RequestMessage structure", root.Tag, root.Type)
	}

	header, ok := root.FirstChild(TagRequestHeader)
	if !ok || header.Type != TTLVStructure {
		return RequestMessage{}, errors.New("kmip ttlv: request header missing")
	}
	version, ok := header.FirstChild(TagProtocolVersion)
	if !ok || version.Type != TTLVStructure {
		return RequestMessage{}, errors.New("kmip ttlv: protocol version missing")
	}
	major, err := integerChild(version, TagProtocolVersionMajor)
	if err != nil {
		return RequestMessage{}, err
	}
	minor, err := integerChild(version, TagProtocolVersionMinor)
	if err != nil {
		return RequestMessage{}, err
	}
	batchCount, err := integerChild(header, TagBatchCount)
	if err != nil {
		return RequestMessage{}, err
	}

	var ops []Operation
	var batchItems []RequestBatchItem
	for _, item := range root.ChildrenByTag(TagBatchItem) {
		if item.Type != TTLVStructure {
			return RequestMessage{}, errors.New("kmip ttlv: batch item is not a structure")
		}
		op, err := enumChild(item, TagOperation)
		if err != nil {
			return RequestMessage{}, err
		}
		operation := Operation(op)
		ops = append(ops, operation)
		payload, _ := item.FirstChild(TagRequestPayload)
		batchItems = append(batchItems, RequestBatchItem{Operation: operation, Payload: payload})
	}
	if batchCount != len(ops) {
		return RequestMessage{}, fmt.Errorf("kmip ttlv: batch count %d does not match %d batch items", batchCount, len(ops))
	}

	return RequestMessage{
		ProtocolMajor: major,
		ProtocolMinor: minor,
		BatchCount:    batchCount,
		Operations:    ops,
		BatchItems:    batchItems,
	}, nil
}

// FirstChild returns the first direct child matching tag.
func (n TTLV) FirstChild(tag uint32) (TTLV, bool) {
	for _, child := range n.Children {
		if child.Tag == tag {
			return child, true
		}
	}
	return TTLV{}, false
}

// ChildrenByTag returns all direct children matching tag.
func (n TTLV) ChildrenByTag(tag uint32) []TTLV {
	var out []TTLV
	for _, child := range n.Children {
		if child.Tag == tag {
			out = append(out, child)
		}
	}
	return out
}

type ttlvParser struct {
	limits TTLVLimits
	fields int
}

func (p *ttlvParser) parseItem(frame []byte, depth int) (TTLV, int, error) {
	if depth > p.limits.MaxDepth {
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: nesting depth %d exceeds cap %d", depth, p.limits.MaxDepth)
	}
	if len(frame) < 8 {
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: truncated item header: %d bytes", len(frame))
	}
	p.fields++
	if p.fields > p.limits.MaxFields {
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: field count exceeds cap %d", p.limits.MaxFields)
	}

	tag := uint32(frame[0])<<16 | uint32(frame[1])<<8 | uint32(frame[2])
	typ := TTLVType(frame[3])
	rawLength := binary.BigEndian.Uint32(frame[4:8])
	if rawLength > uint32(p.limits.MaxFrameSize) {
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: value length %d exceeds frame cap %d", rawLength, p.limits.MaxFrameSize)
	}
	length := int(rawLength)
	padding := ttlvPadding(length)
	total := 8 + length + padding
	if total < 8 || total > len(frame) {
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: value length %d exceeds remaining frame %d", length, len(frame)-8)
	}

	node := TTLV{Tag: tag, Type: typ, Length: uint32(length)}
	value := frame[8 : 8+length]
	switch typ {
	case TTLVStructure:
		for off := 0; off < len(value); {
			child, n, err := p.parseItem(value[off:], depth+1)
			if err != nil {
				return TTLV{}, 0, err
			}
			off += n
			node.Children = append(node.Children, child)
		}
	case TTLVInteger, TTLVEnumeration, TTLVInterval:
		if length != 4 {
			return TTLV{}, 0, fmt.Errorf("kmip ttlv: type %#02x length %d, want 4", typ, length)
		}
		node.Value = append([]byte(nil), value...)
	case TTLVLongInteger, TTLVBoolean, TTLVDateTime:
		if length != 8 {
			return TTLV{}, 0, fmt.Errorf("kmip ttlv: type %#02x length %d, want 8", typ, length)
		}
		node.Value = append([]byte(nil), value...)
	case TTLVBigInteger, TTLVTextString, TTLVByteString:
		node.Value = append([]byte(nil), value...)
	default:
		return TTLV{}, 0, fmt.Errorf("kmip ttlv: unsupported type %#02x", typ)
	}
	return node, total, nil
}

func normalizeTTLVLimits(limits TTLVLimits) TTLVLimits {
	if limits.MaxFrameSize <= 0 {
		limits.MaxFrameSize = DefaultTTLVLimits.MaxFrameSize
	}
	if limits.MaxFields <= 0 {
		limits.MaxFields = DefaultTTLVLimits.MaxFields
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = DefaultTTLVLimits.MaxDepth
	}
	return limits
}

func integerChild(parent TTLV, tag uint32) (int, error) {
	child, ok := parent.FirstChild(tag)
	if !ok || child.Type != TTLVInteger || len(child.Value) != 4 {
		return 0, fmt.Errorf("kmip ttlv: integer child %#06x missing", tag)
	}
	return int(int32(binary.BigEndian.Uint32(child.Value))), nil
}

func enumChild(parent TTLV, tag uint32) (int32, error) {
	child, ok := parent.FirstChild(tag)
	if !ok || child.Type != TTLVEnumeration || len(child.Value) != 4 {
		return 0, fmt.Errorf("kmip ttlv: enumeration child %#06x missing", tag)
	}
	return int32(binary.BigEndian.Uint32(child.Value)), nil
}

func ttlvPadding(length int) int {
	if rem := length % 8; rem != 0 {
		return 8 - rem
	}
	return 0
}
