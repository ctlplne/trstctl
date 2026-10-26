// SPDX-License-Identifier: BUSL-1.1

// Package kmiptest is an in-process KMIP server double for the XREC KMIP
// observation client (A124). It answers Locate (paged with Maximum Items and
// Offset Items), Get Attributes and Get of certificate values over any
// connection, decoding every request with the served KMIP parser, and refuses
// a Get of anything that is not a certificate: a client that keeps key values
// out of reconciliation never asks for one, and KeyValueReads counts the
// attempts.
package kmiptest

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	servedkmip "trstctl.com/trstctl/internal/kmip"
)

// KMIP enumerations a test uses to describe objects.
const (
	ObjectTypeCertificate  int32 = 0x01
	ObjectTypeSymmetricKey int32 = 0x02
	ObjectTypeTemplate     int32 = 0x06
	AlgorithmAES           int32 = 0x03
	AlgorithmECDSA         int32 = 0x06
	StatePreActive         int32 = 0x01
	StateActive            int32 = 0x02
)

// Object is one managed object the double holds.
type Object struct {
	ObjectType     int32
	Algorithm      int32
	Length         int32
	State          int32
	Initial        time.Time
	CertificateDER []byte
}

// Server is the KMIP double. Configure it before serving.
type Server struct {
	// IgnoreOffset makes Locate disregard Offset Items, as a server that does
	// not page answers the first page again.
	IgnoreOffset bool
	// Refuse makes the named operation fail.
	Refuse servedkmip.Operation
	// WrongOperation makes every successful answer name another operation.
	WrongOperation bool

	mu            sync.Mutex
	ids           []string
	objects       map[string]Object
	offsets       []int64
	keyValueReads int
	errs          []error
}

// New returns an empty double.
func New() *Server { return &Server{objects: map[string]Object{}} }

// Add holds obj under id; Locate lists identifiers in the order they were added.
func (s *Server) Add(id string, obj Object) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[id]; !exists {
		s.ids = append(s.ids, id)
	}
	s.objects[id] = obj
}

// Offsets lists the Offset Items of every Locate served.
func (s *Server) Offsets() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.offsets...)
}

// KeyValueReads counts Gets of objects that are not certificates.
func (s *Server) KeyValueReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyValueReads
}

// Errors lists requests the served parser refused.
func (s *Server) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// Serve answers requests on conn until it closes.
func (s *Server) Serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		frame, err := servedkmip.ReadFrame(conn, 1<<20)
		if err != nil {
			return
		}
		req, err := servedkmip.DecodeRequestMessage(frame)
		if err == nil && len(req.BatchItems) != 1 {
			err = fmt.Errorf("a request carried %d batch items", len(req.BatchItems))
		}
		if err != nil {
			s.mu.Lock()
			s.errs = append(s.errs, err)
			s.mu.Unlock()
			return
		}
		if _, err := conn.Write(s.answer(req.BatchItems[0])); err != nil {
			return
		}
	}
}

func (s *Server) answer(item servedkmip.RequestBatchItem) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	op := item.Operation
	if s.Refuse == op {
		return failure(op, 0x0100, "refused by the test server")
	}
	var payload [][]byte
	switch op {
	case servedkmip.OperationLocate:
		maxItems, offset := int64(len(s.ids)), int64(0)
		if node, ok := item.Payload.FirstChild(servedkmip.TagMaximumItems); ok && len(node.Value) == 4 {
			maxItems = int64(binary.BigEndian.Uint32(node.Value))
		}
		if node, ok := item.Payload.FirstChild(servedkmip.TagOffsetItems); ok && len(node.Value) == 4 && !s.IgnoreOffset {
			offset = int64(binary.BigEndian.Uint32(node.Value))
		}
		s.offsets = append(s.offsets, offset)
		for i := offset; i < int64(len(s.ids)) && i < offset+maxItems; i++ {
			payload = append(payload, servedkmip.EncodeText(servedkmip.TagUniqueIdentifier, s.ids[i]))
		}
	case servedkmip.OperationGetAttributes:
		uid, _ := item.Payload.FirstChild(servedkmip.TagUniqueIdentifier)
		obj, ok := s.objects[string(uid.Value)]
		if !ok {
			return failure(op, 0x0001, "item not found")
		}
		payload = append(payload, servedkmip.EncodeText(servedkmip.TagUniqueIdentifier, string(uid.Value)))
		for _, name := range item.Payload.ChildrenByTag(servedkmip.TagAttributeName) {
			if value := attributeValue(string(name.Value), obj); value != nil {
				payload = append(payload, servedkmip.EncodeStructure(servedkmip.TagAttribute,
					servedkmip.EncodeText(servedkmip.TagAttributeName, string(name.Value)), value))
			}
		}
	case servedkmip.OperationGet:
		uid, _ := item.Payload.FirstChild(servedkmip.TagUniqueIdentifier)
		obj, ok := s.objects[string(uid.Value)]
		if !ok || obj.ObjectType != ObjectTypeCertificate {
			s.keyValueReads++
			return failure(op, 0x0100, "the test server serves only certificate values")
		}
		payload = append(payload,
			servedkmip.EncodeEnumeration(servedkmip.TagObjectType, ObjectTypeCertificate),
			servedkmip.EncodeText(servedkmip.TagUniqueIdentifier, string(uid.Value)),
			servedkmip.EncodeStructure(servedkmip.TagCertificate,
				servedkmip.EncodeEnumeration(servedkmip.TagCertificateType, 0x01),
				servedkmip.EncodeBytes(servedkmip.TagCertificateValue, obj.CertificateDER)))
	default:
		return failure(op, 0x0005, "operation not supported by the test server")
	}
	if s.WrongOperation {
		op = servedkmip.OperationDestroy
	}
	return message(servedkmip.EncodeStructure(servedkmip.TagBatchItem,
		servedkmip.EncodeEnumeration(servedkmip.TagOperation, int32(op)),
		servedkmip.EncodeEnumeration(servedkmip.TagResultStatus, servedkmip.ResultStatusSuccess),
		servedkmip.EncodeStructure(servedkmip.TagResponsePayload, payload...)))
}

func attributeValue(name string, obj Object) []byte {
	switch name {
	case "Object Type":
		return servedkmip.EncodeEnumeration(servedkmip.TagAttributeValue, obj.ObjectType)
	case "Cryptographic Algorithm":
		if obj.Algorithm != 0 {
			return servedkmip.EncodeEnumeration(servedkmip.TagAttributeValue, obj.Algorithm)
		}
	case "Cryptographic Length":
		if obj.Length != 0 {
			return servedkmip.EncodeInteger(servedkmip.TagAttributeValue, obj.Length)
		}
	case "State":
		return servedkmip.EncodeEnumeration(servedkmip.TagAttributeValue, obj.State)
	case "Initial Date":
		if !obj.Initial.IsZero() {
			return servedkmip.EncodeDateTime(servedkmip.TagAttributeValue, obj.Initial)
		}
	}
	return nil
}

func failure(op servedkmip.Operation, reason int32, text string) []byte {
	return message(servedkmip.EncodeStructure(servedkmip.TagBatchItem,
		servedkmip.EncodeEnumeration(servedkmip.TagOperation, int32(op)),
		servedkmip.EncodeEnumeration(servedkmip.TagResultStatus, 0x01),
		servedkmip.EncodeEnumeration(servedkmip.TagResultReason, reason),
		servedkmip.EncodeText(servedkmip.TagResultMessage, text)))
}

func message(batchItem []byte) []byte {
	return servedkmip.EncodeStructure(servedkmip.TagResponseMessage,
		servedkmip.EncodeStructure(servedkmip.TagResponseHeader,
			servedkmip.EncodeStructure(servedkmip.TagProtocolVersion,
				servedkmip.EncodeInteger(servedkmip.TagProtocolVersionMajor, 1),
				servedkmip.EncodeInteger(servedkmip.TagProtocolVersionMinor, 4)),
			servedkmip.EncodeDateTime(servedkmip.TagTimeStamp, time.Now()),
			servedkmip.EncodeInteger(servedkmip.TagBatchCount, 1)),
		batchItem)
}
