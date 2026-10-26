// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	servedkmip "trstctl.com/trstctl/internal/kmip"
)

// Wire observation (A124). A WireEndpoint speaks KMIP 1.4 over one connection
// the source opened (TLS with a client certificate): Locate, paged with Maximum
// Items and Offset Items, and Get Attributes for the metadata the reducer maps.
// A certificate's issuer and serial come from a Get of the certificate object,
// whose value is public; keys and secret objects are never fetched.

const (
	wireProtocolMajor = 1
	wireProtocolMinor = 4
	// wireLocatePage is how many identifiers one Locate asks for.
	wireLocatePage = 500
	// wireMaxFrame bounds one response frame, as the served parser does.
	wireMaxFrame = 1 << 20
	// DefaultMaxObjects bounds one observation. A server holding more fails
	// the observation rather than yield a partial inventory, which would read
	// as objects missing from the authority.
	DefaultMaxObjects = 10000
)

var (
	// ErrTooManyObjects is returned when a server holds more objects than one
	// observation may read.
	ErrTooManyObjects = errors.New("xrec kmip: the server holds more objects than one observation reads")
	// ErrUnmappedObjectType is returned for an object whose type the canon
	// vocabulary has no record for (a template, split key or PGP key); a
	// source skips it, since no other authority asserts it either.
	ErrUnmappedObjectType = errors.New("xrec kmip: object type outside the reconciliation vocabulary")
)

// wireAttributeNames are the attributes Get Attributes asks for.
var wireAttributeNames = []string{
	"Object Type", "Cryptographic Algorithm", "Cryptographic Length", "State",
	"Initial Date", "Activation Date", "Deactivation Date",
}

// KMIP 1.4 enumerations the reducer maps.
var (
	wireObjectTypes = map[int32]ObjectType{
		0x01: ObjectTypeCertificate, 0x02: ObjectTypeSymmetricKey, 0x03: ObjectTypePublicKey,
		0x04: ObjectTypePrivateKey, 0x07: ObjectTypeSecretData, 0x08: ObjectTypeOpaqueObject,
	}
	wireStates = map[int32]State{
		0x01: StatePreActive, 0x02: StateActive, 0x03: StateDeactivated,
		0x04: StateCompromised, 0x05: StateDestroyed, 0x06: "Destroyed Compromised",
	}
	wireAlgorithms = map[int32]string{
		0x01: "DES", 0x02: "3DES", 0x03: "AES", 0x04: "RSA", 0x05: "DSA", 0x06: "ECDSA",
		0x07: "HMAC-SHA1", 0x08: "HMAC-SHA224", 0x09: "HMAC-SHA256", 0x0a: "HMAC-SHA384",
		0x0b: "HMAC-SHA512", 0x0c: "HMAC-MD5", 0x0d: "DH", 0x0e: "ECDH", 0x0f: "ECMQV",
		0x10: "Blowfish", 0x11: "Camellia", 0x12: "CAST5", 0x13: "IDEA", 0x14: "MARS",
		0x15: "RC2", 0x16: "RC4", 0x17: "RC5", 0x18: "SKIPJACK", 0x19: "Twofish",
		0x1a: "EC", 0x1c: "ChaCha20",
	}
)

// WireEndpoint observes one KMIP server over one connection. Calls are
// serialized; a KMIP connection carries one request at a time.
type WireEndpoint struct {
	mu         sync.Mutex
	conn       io.ReadWriter
	maxObjects int
}

var _ Endpoint = (*WireEndpoint)(nil)

// NewWireEndpoint observes the server at the other end of conn. maxObjects
// <= 0 means DefaultMaxObjects.
func NewWireEndpoint(conn io.ReadWriter, maxObjects int) *WireEndpoint {
	if maxObjects <= 0 {
		maxObjects = DefaultMaxObjects
	}
	return &WireEndpoint{conn: conn, maxObjects: maxObjects}
}

// Locate lists every object the server shows this client, a page at a time.
// The tenant scopes the round, not the server: one KMIP authority is one
// server account.
func (e *WireEndpoint) Locate(ctx context.Context, _ string) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for offset := int32(0); ; offset += wireLocatePage {
		payload := servedkmip.EncodeStructure(servedkmip.TagRequestPayload,
			servedkmip.EncodeInteger(servedkmip.TagMaximumItems, wireLocatePage),
			servedkmip.EncodeInteger(servedkmip.TagOffsetItems, offset),
		)
		item, err := e.call(ctx, servedkmip.OperationLocate, payload)
		if err != nil {
			return nil, fmt.Errorf("xrec kmip: locate: %w", err)
		}
		page := 0
		for _, node := range item.Payload.ChildrenByTag(servedkmip.TagUniqueIdentifier) {
			if node.Type != servedkmip.TTLVTextString || len(node.Value) == 0 {
				return nil, errors.New("xrec kmip: locate returned an identifier that is not text")
			}
			id := string(node.Value)
			if seen[id] {
				// A server that ignores Offset Items answers the first page
				// again; reading on would count it twice.
				return nil, fmt.Errorf("xrec kmip: locate returned %q on two pages; the server does not page with Offset Items", id)
			}
			seen[id] = true
			ids = append(ids, id)
			page++
		}
		if len(ids) > e.maxObjects {
			return nil, fmt.Errorf("%w (more than %d)", ErrTooManyObjects, e.maxObjects)
		}
		if page < wireLocatePage {
			return ids, nil
		}
	}
}

// GetAttributes reads one object's metadata. A certificate's issuer, serial
// and subject come from a Get of the certificate, whose value is public.
func (e *WireEndpoint) GetAttributes(ctx context.Context, uniqueIdentifier string) (ManagedObject, error) {
	children := [][]byte{servedkmip.EncodeText(servedkmip.TagUniqueIdentifier, uniqueIdentifier)}
	for _, name := range wireAttributeNames {
		children = append(children, servedkmip.EncodeText(servedkmip.TagAttributeName, name))
	}
	item, err := e.call(ctx, servedkmip.OperationGetAttributes, servedkmip.EncodeStructure(servedkmip.TagRequestPayload, children...))
	if err != nil {
		return ManagedObject{}, fmt.Errorf("xrec kmip: get attributes %q: %w", uniqueIdentifier, err)
	}
	obj := ManagedObject{UniqueIdentifier: uniqueIdentifier}
	for _, attr := range item.Payload.ChildrenByTag(servedkmip.TagAttribute) {
		name, value, ok := parseAttribute(attr)
		if !ok {
			continue
		}
		switch name {
		case "Object Type":
			obj.ObjectType = wireObjectTypes[wireEnum(value)]
		case "Cryptographic Algorithm":
			code := wireEnum(value)
			if alg, known := wireAlgorithms[code]; known {
				obj.Algorithm = alg
			} else {
				obj.Algorithm = fmt.Sprintf("KMIP_ALGORITHM_%d", code)
			}
		case "Cryptographic Length":
			obj.LengthBits = valueInt(value)
		case "State":
			obj.State = wireStates[wireEnum(value)]
		case "Initial Date":
			obj.InitialDate = valueTime(value)
		case "Activation Date":
			obj.ActivationDate = valueTime(value)
		case "Deactivation Date":
			obj.DeactivationDate = valueTime(value)
		}
	}
	if obj.ObjectType == "" {
		return ManagedObject{}, fmt.Errorf("%w: %q", ErrUnmappedObjectType, uniqueIdentifier)
	}
	if obj.ObjectType == ObjectTypeCertificate {
		if err := e.certificateIdentity(ctx, &obj); err != nil {
			return ManagedObject{}, err
		}
	}
	return obj, nil
}

// certificateIdentity fills a certificate object's issuer, serial and subject
// from its value.
func (e *WireEndpoint) certificateIdentity(ctx context.Context, obj *ManagedObject) error {
	item, err := e.call(ctx, servedkmip.OperationGet, servedkmip.EncodeStructure(servedkmip.TagRequestPayload,
		servedkmip.EncodeText(servedkmip.TagUniqueIdentifier, obj.UniqueIdentifier)))
	if err != nil {
		return fmt.Errorf("xrec kmip: get certificate %q: %w", obj.UniqueIdentifier, err)
	}
	cert, ok := item.Payload.FirstChild(servedkmip.TagCertificate)
	if !ok {
		return fmt.Errorf("xrec kmip: object %q returned no certificate", obj.UniqueIdentifier)
	}
	value, ok := cert.FirstChild(servedkmip.TagCertificateValue)
	if !ok || value.Type != servedkmip.TTLVByteString || len(value.Value) == 0 {
		return fmt.Errorf("xrec kmip: certificate %q carries no value", obj.UniqueIdentifier)
	}
	issuer, serial, err := crypto.CertificateIssuerAndSerial(value.Value)
	if err != nil {
		return fmt.Errorf("xrec kmip: certificate %q does not parse", obj.UniqueIdentifier)
	}
	obj.IssuerNameDER, obj.SerialHex = issuer, serial
	if info, err := certinfo.Inspect(value.Value); err == nil {
		obj.SubjectDN = info.Subject
	}
	return nil
}

// call sends one single-item request and returns its successful response item.
func (e *WireEndpoint) call(ctx context.Context, op servedkmip.Operation, payload []byte) (servedkmip.ClientResponseItem, error) {
	if err := ctx.Err(); err != nil {
		return servedkmip.ClientResponseItem{}, err
	}
	frame, err := servedkmip.EncodeClientRequest(wireProtocolMajor, wireProtocolMinor,
		servedkmip.ClientRequestItem{Operation: op, Payload: payload})
	if err != nil {
		return servedkmip.ClientResponseItem{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if conn, ok := e.conn.(net.Conn); ok {
		deadline, set := ctx.Deadline()
		if !set {
			deadline = time.Time{}
		}
		_ = conn.SetDeadline(deadline)
	}
	if _, err := e.conn.Write(frame); err != nil {
		return servedkmip.ClientResponseItem{}, err
	}
	response, err := servedkmip.ReadFrame(e.conn, wireMaxFrame)
	if err != nil {
		return servedkmip.ClientResponseItem{}, err
	}
	items, err := servedkmip.DecodeClientResponse(response)
	if err != nil {
		return servedkmip.ClientResponseItem{}, err
	}
	if len(items) != 1 {
		return servedkmip.ClientResponseItem{}, fmt.Errorf("the server answered %d batch items to one request", len(items))
	}
	item := items[0]
	if item.ResultStatus != servedkmip.ResultStatusSuccess {
		// The server's message names the failure; it carries no key material.
		return servedkmip.ClientResponseItem{}, fmt.Errorf("the server refused the operation (status %d, reason %d): %s",
			item.ResultStatus, item.ResultReason, item.ResultMessage)
	}
	if item.Operation != 0 && item.Operation != op {
		return servedkmip.ClientResponseItem{}, fmt.Errorf("the server answered operation %d to operation %d", item.Operation, op)
	}
	if !item.HasPayload {
		return servedkmip.ClientResponseItem{}, errors.New("the server answered without a response payload")
	}
	return item, nil
}

func wireEnum(v servedkmip.TTLV) int32 {
	if (v.Type != servedkmip.TTLVEnumeration && v.Type != servedkmip.TTLVInteger) || len(v.Value) != 4 {
		return 0
	}
	return asInt32(binary.BigEndian.Uint32(v.Value))
}
