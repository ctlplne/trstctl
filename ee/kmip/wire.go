package kmip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const defaultWireFrameCap = 1 << 20

// ReadFrame reads one complete KMIP TTLV frame from r. KMIP frames are length-
// prefixed by the standard 8-byte TTLV item header; this helper reads exactly one
// top-level item and enforces the same bounded frame cap as the parser.
func ReadFrame(r io.Reader, maxFrameSize int) ([]byte, error) {
	if maxFrameSize <= 0 {
		maxFrameSize = defaultWireFrameCap
	}
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[4:8]))
	total := 8 + length + ttlvPadding(length)
	if total < 8 || total > maxFrameSize {
		return nil, fmt.Errorf("kmip ttlv: frame size %d exceeds cap %d", total, maxFrameSize)
	}
	frame := make([]byte, total)
	copy(frame, header[:])
	if _, err := io.ReadFull(r, frame[8:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// HandleFrame authenticates the verified client certificate, dispatches the
// single-request KMIP frame, and returns a KMIP ResponseMessage. The first served
// listener intentionally supports the stock-client path KMS-02 requires: AES
// SymmetricKey Create and Get. Unsupported operations receive a parseable KMIP
// failure instead of an unframed TCP close.
func (s *Server) HandleFrame(ctx context.Context, clientCertDER []byte, frame []byte) ([]byte, error) {
	msg, err := DecodeRequestMessage(frame)
	if err != nil {
		return encodeResponse(1, 2, []wireResponseItem{failureItem(0, resultReasonInvalidMessage, err.Error())}), nil
	}
	if msg.BatchCount == 0 || len(msg.BatchItems) == 0 {
		return encodeResponse(msg.ProtocolMajor, msg.ProtocolMinor, []wireResponseItem{failureItem(0, resultReasonInvalidMessage, "empty KMIP batch")}), nil
	}

	items := make([]wireResponseItem, 0, len(msg.BatchItems))
	for _, item := range msg.BatchItems {
		switch item.Operation {
		case OperationCreate:
			resp, err := s.handleCreate(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		case OperationGet:
			resp, err := s.handleGet(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		default:
			items = append(items, failureItem(item.Operation, resultReasonUnsupported, "KMIP operation is not served yet"))
		}
	}
	return encodeResponse(msg.ProtocolMajor, msg.ProtocolMinor, items), nil
}

func (s *Server) handleCreate(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	spec, err := parseCreatePayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	if spec.objectType != objectTypeSymmetricKey {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "only SymmetricKey creation is served"}
	}
	if spec.algorithm != cryptographicAlgorithmAES || spec.length != 256 {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "only AES-256 SymmetricKey creation is served"}
	}
	id, err := s.Create(ctx, clientCertDER, "AES")
	if err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationCreate,
		payload: encodeStructure(TagResponsePayload,
			encodeEnumeration(TagObjectType, objectTypeSymmetricKey),
			encodeText(TagUniqueIdentifier, id),
		),
	}, nil
}

func (s *Server) handleGet(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	obj, err := s.GetObject(ctx, clientCertDER, id)
	if err != nil {
		return wireResponseItem{}, err
	}
	defer secret.Wipe(obj.Key)
	return wireResponseItem{
		operation: OperationGet,
		payload: encodeStructure(TagResponsePayload,
			encodeEnumeration(TagObjectType, objectTypeSymmetricKey),
			encodeText(TagUniqueIdentifier, obj.ID),
			encodeStructure(TagSymmetricKey,
				encodeStructure(TagKeyBlock,
					encodeEnumeration(TagKeyFormatType, keyFormatTypeRaw),
					encodeStructure(TagKeyValue,
						encodeBytes(TagKeyMaterial, obj.Key),
					),
					encodeEnumeration(TagCryptographicAlgorithm, cryptographicAlgorithmAES),
					encodeInteger(TagCryptographicLength, int32(len(obj.Key)*8)),
				),
			),
		),
	}, nil
}

type createPayloadSpec struct {
	objectType int32
	algorithm  int32
	length     int
}

func parseCreatePayload(payload TTLV) (createPayloadSpec, error) {
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return createPayloadSpec{}, wireError{reason: resultReasonInvalidMessage, message: "Create request payload missing"}
	}
	objectType, err := enumChild(payload, TagObjectType)
	if err != nil {
		return createPayloadSpec{}, wireError{reason: resultReasonInvalidField, message: err.Error()}
	}
	spec := createPayloadSpec{objectType: int32(objectType), algorithm: cryptographicAlgorithmAES, length: 256}
	if tmpl, ok := payload.FirstChild(TagTemplateAttribute); ok && tmpl.Type == TTLVStructure {
		for _, attr := range tmpl.Children {
			if attr.Tag != TagAttribute || attr.Type != TTLVStructure {
				continue
			}
			name, value, ok := parseAttribute(attr)
			if !ok {
				continue
			}
			switch normalizedAttributeName(name) {
			case "cryptographic_algorithm":
				if value.Type == TTLVEnumeration && len(value.Value) == 4 {
					spec.algorithm = int32(binary.BigEndian.Uint32(value.Value))
				}
			case "cryptographic_length":
				if value.Type == TTLVInteger && len(value.Value) == 4 {
					spec.length = int(binary.BigEndian.Uint32(value.Value))
				}
			}
		}
	}
	return spec, nil
}

func parseAttribute(attr TTLV) (string, TTLV, bool) {
	nameNode, ok := attr.FirstChild(TagAttributeName)
	if !ok || nameNode.Type != TTLVTextString {
		return "", TTLV{}, false
	}
	valueNode, ok := attr.FirstChild(TagAttributeValue)
	if !ok {
		return "", TTLV{}, false
	}
	return string(nameNode.Value), valueNode, true
}

func normalizedAttributeName(name string) string {
	return strings.ToLower(strings.NewReplacer(" ", "_", ".", "_", "-", "_").Replace(name))
}

func parseUniqueIdentifierPayload(payload TTLV) (string, error) {
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return "", wireError{reason: resultReasonInvalidMessage, message: "Get request payload missing"}
	}
	uid, ok := payload.FirstChild(TagUniqueIdentifier)
	if !ok || uid.Type != TTLVTextString {
		return "", wireError{reason: resultReasonInvalidField, message: "UniqueIdentifier is required"}
	}
	id := strings.TrimSpace(string(uid.Value))
	if id == "" {
		return "", wireError{reason: resultReasonInvalidField, message: "UniqueIdentifier is empty"}
	}
	return id, nil
}

type wireError struct {
	reason  int32
	message string
}

func (e wireError) Error() string { return e.message }

func errorItem(op Operation, err error) wireResponseItem {
	var werr wireError
	switch {
	case errors.As(err, &werr):
		return failureItem(op, werr.reason, werr.message)
	case strings.Contains(err.Error(), "not available"), strings.Contains(err.Error(), "not active"), strings.Contains(err.Error(), "not found"):
		return failureItem(op, resultReasonItemNotFound, err.Error())
	case strings.Contains(err.Error(), "not authenticated"):
		return failureItem(op, resultReasonAuthFailed, err.Error())
	default:
		return failureItem(op, resultReasonGeneralFailure, err.Error())
	}
}

type wireResponseItem struct {
	operation Operation
	status    int32
	reason    int32
	message   string
	payload   []byte
}

func failureItem(op Operation, reason int32, message string) wireResponseItem {
	return wireResponseItem{
		operation: op,
		status:    resultStatusOperationFailed,
		reason:    reason,
		message:   message,
	}
}

func encodeResponse(major, minor int, items []wireResponseItem) []byte {
	if major <= 0 {
		major = 1
	}
	if minor < 0 {
		minor = 2
	}
	children := [][]byte{
		encodeStructure(TagResponseHeader,
			encodeStructure(TagProtocolVersion,
				encodeInteger(TagProtocolVersionMajor, int32(major)),
				encodeInteger(TagProtocolVersionMinor, int32(minor)),
			),
			encodeDateTime(TagTimeStamp, time.Now()),
			encodeInteger(TagBatchCount, int32(len(items))),
		),
	}
	for _, item := range items {
		children = append(children, encodeResponseBatchItem(item))
	}
	return encodeStructure(TagResponseMessage, children...)
}

func encodeResponseBatchItem(item wireResponseItem) []byte {
	status := item.status
	if status == 0 && item.reason == 0 && item.message == "" {
		status = resultStatusSuccess
	}
	children := [][]byte{}
	if item.operation != 0 {
		children = append(children, encodeEnumeration(TagOperation, int32(item.operation)))
	}
	children = append(children, encodeEnumeration(TagResultStatus, status))
	if status != resultStatusSuccess {
		children = append(children, encodeEnumeration(TagResultReason, item.reason))
		children = append(children, encodeText(TagResultMessage, item.message))
	}
	if len(item.payload) > 0 {
		children = append(children, item.payload)
	}
	return encodeStructure(TagBatchItem, children...)
}

func encodeStructure(tag uint32, children ...[]byte) []byte {
	return encodeItem(tag, TTLVStructure, bytes.Join(children, nil))
}

func encodeInteger(tag uint32, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return encodeItem(tag, TTLVInteger, buf[:])
}

func encodeEnumeration(tag uint32, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return encodeItem(tag, TTLVEnumeration, buf[:])
}

func encodeDateTime(tag uint32, value time.Time) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value.Unix()))
	return encodeItem(tag, TTLVDateTime, buf[:])
}

func encodeText(tag uint32, value string) []byte {
	return encodeItem(tag, TTLVTextString, []byte(value))
}

func encodeBytes(tag uint32, value []byte) []byte {
	return encodeItem(tag, TTLVByteString, value)
}

func encodeItem(tag uint32, typ TTLVType, value []byte) []byte {
	out := make([]byte, 8+len(value)+ttlvPadding(len(value)))
	out[0] = byte(tag >> 16)
	out[1] = byte(tag >> 8)
	out[2] = byte(tag)
	out[3] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}
