// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Client-side codec (A124). A KMIP observation client builds its requests and
// reads its responses with the same bounded encoder and parser the served
// listener uses, so trstctl keeps one TTLV implementation.

// Client operations and tags beyond the served listener's own set.
const (
	OperationGetAttributes Operation = 0x0000000b

	TagCertificate      uint32 = 0x420013
	TagCertificateType  uint32 = 0x42001d
	TagCertificateValue uint32 = 0x42001e
	TagMaximumItems     uint32 = 0x42004f
	TagOffsetItems      uint32 = 0x4200d4
)

// ResultStatusSuccess is the KMIP Result Status of a successful batch item.
const ResultStatusSuccess int32 = resultStatusSuccess

// ClientRequestItem is one batch item of a client request: the operation and
// its encoded Request Payload structure.
type ClientRequestItem struct {
	Operation Operation
	Payload   []byte
}

// ClientResponseItem is one decoded batch item of a response.
type ClientResponseItem struct {
	Operation     Operation
	ResultStatus  int32
	ResultReason  int32
	ResultMessage string
	// Payload is the Response Payload structure; HasPayload is false when the
	// item carried none.
	Payload    TTLV
	HasPayload bool
}

// EncodeStructure, EncodeText, EncodeInteger, EncodeEnumeration, EncodeBytes
// and EncodeDateTime encode one TTLV item for a client payload.
func EncodeStructure(tag uint32, children ...[]byte) []byte { return encodeStructure(tag, children...) }
func EncodeText(tag uint32, value string) []byte            { return encodeText(tag, value) }
func EncodeInteger(tag uint32, value int32) []byte          { return encodeInteger(tag, value) }
func EncodeEnumeration(tag uint32, value int32) []byte      { return encodeEnumeration(tag, value) }
func EncodeBytes(tag uint32, value []byte) []byte           { return encodeBytes(tag, value) }
func EncodeDateTime(tag uint32, value time.Time) []byte     { return encodeDateTime(tag, value) }

// EncodeClientRequest builds a Request Message for protocol major.minor with
// one batch item per entry.
func EncodeClientRequest(major, minor int32, items ...ClientRequestItem) ([]byte, error) {
	if len(items) == 0 {
		return nil, errors.New("kmip client: a request needs at least one batch item")
	}
	count, err := wireInt32From(len(items))
	if err != nil {
		return nil, fmt.Errorf("kmip client: batch count: %w", err)
	}
	children := [][]byte{
		encodeStructure(TagRequestHeader,
			encodeStructure(TagProtocolVersion,
				encodeInteger(TagProtocolVersionMajor, major),
				encodeInteger(TagProtocolVersionMinor, minor),
			),
			encodeInteger(TagBatchCount, count),
		),
	}
	for _, item := range items {
		if item.Operation == 0 {
			return nil, errors.New("kmip client: a batch item needs an operation")
		}
		payload := item.Payload
		if len(payload) == 0 {
			payload = encodeStructure(TagRequestPayload)
		}
		children = append(children, encodeStructure(TagBatchItem,
			encodeEnumeration(TagOperation, int32(item.Operation)),
			payload,
		))
	}
	return encodeStructure(TagRequestMessage, children...), nil
}

// DecodeClientResponse parses one Response Message frame with the default
// limits and returns its batch items in order.
func DecodeClientResponse(frame []byte) ([]ClientResponseItem, error) {
	root, err := ParseTTLV(frame)
	if err != nil {
		return nil, err
	}
	if root.Tag != TagResponseMessage || root.Type != TTLVStructure {
		return nil, errors.New("kmip client: the frame is not a Response Message")
	}
	var out []ClientResponseItem
	for _, node := range root.ChildrenByTag(TagBatchItem) {
		if node.Type != TTLVStructure {
			return nil, errors.New("kmip client: a batch item is not a structure")
		}
		item := ClientResponseItem{ResultStatus: -1}
		for _, child := range node.Children {
			switch child.Tag {
			case TagOperation:
				value, err := clientEnum(child)
				if err != nil {
					return nil, err
				}
				item.Operation = Operation(value)
			case TagResultStatus:
				value, err := clientEnum(child)
				if err != nil {
					return nil, err
				}
				item.ResultStatus = value
			case TagResultReason:
				value, err := clientEnum(child)
				if err != nil {
					return nil, err
				}
				item.ResultReason = value
			case TagResultMessage:
				if child.Type == TTLVTextString {
					item.ResultMessage = string(child.Value)
				}
			case TagResponsePayload:
				if child.Type != TTLVStructure {
					return nil, errors.New("kmip client: a response payload is not a structure")
				}
				item.Payload, item.HasPayload = child, true
			}
		}
		if item.ResultStatus < 0 {
			return nil, errors.New("kmip client: a batch item carries no result status")
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, errors.New("kmip client: the response carries no batch item")
	}
	return out, nil
}

func clientEnum(node TTLV) (int32, error) {
	if (node.Type != TTLVEnumeration && node.Type != TTLVInteger) || len(node.Value) != 4 {
		return 0, fmt.Errorf("kmip client: tag %06x is not a 32-bit enumeration", node.Tag)
	}
	return wireInt32(binary.BigEndian.Uint32(node.Value)), nil
}
