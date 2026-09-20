// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
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
// single-request KMIP frame, and returns a KMIP ResponseMessage. The served
// listener supports the bounded appliance lifecycle path KMS-02 requires: AES
// SymmetricKey Create/Register/Get (including AES-GCM wrapping), Locate,
// Revoke/Destroy, Query, and DiscoverVersions. Unsupported operations receive a
// parseable KMIP failure instead of an unframed TCP close.
func (s *Server) HandleFrame(ctx context.Context, clientCertDER []byte, frame []byte) ([]byte, error) {
	if s.log == nil {
		return s.handleFrame(ctx, clientCertDER, frame)
	}
	var response []byte
	err := s.withTenantCipher(ctx, func(scoped context.Context, _ tenantseal.Cipher) (err error) {
		response, err = s.handleFrame(scoped, clientCertDER, frame)
		return err
	})
	return response, err
}

func (s *Server) handleFrame(ctx context.Context, clientCertDER []byte, frame []byte) ([]byte, error) {
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
		case OperationRegister:
			resp, err := s.handleRegister(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		case OperationLocate:
			resp, err := s.handleLocate(ctx, clientCertDER, item.Payload)
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
		case OperationRevoke:
			resp, err := s.handleRevoke(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		case OperationDestroy:
			resp, err := s.handleDestroy(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		case OperationQuery:
			resp, err := s.handleQuery(ctx, clientCertDER, item.Payload)
			if err != nil {
				items = append(items, errorItem(item.Operation, err))
				continue
			}
			items = append(items, resp)
		case OperationDiscoverVersions:
			resp, err := s.handleDiscoverVersions(ctx, clientCertDER, item.Payload)
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

func (s *Server) handleRegister(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	key, err := s.registeredKeyMaterial(ctx, clientCertDER, payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	defer secret.Wipe(key)
	id, err := s.Register(ctx, clientCertDER, "AES", key)
	if err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationRegister,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id)),
	}, nil
}

func (s *Server) handleQuery(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	if _, err := s.authClient(ctx, "query", clientCertDER); err != nil {
		return wireResponseItem{}, err
	}
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidMessage, message: "Query request payload missing"}
	}
	functions := payload.ChildrenByTag(TagQueryFunction)
	if len(functions) == 0 {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "QueryFunction is required"}
	}
	children := make([][]byte, 0, 16)
	seen := map[int32]bool{}
	for _, function := range functions {
		if function.Type != TTLVEnumeration || len(function.Value) != 4 {
			return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "QueryFunction must be an enumeration"}
		}
		value := wireInt32(binary.BigEndian.Uint32(function.Value))
		if seen[value] {
			continue
		}
		seen[value] = true
		switch value {
		case queryFunctionOperations:
			for _, operation := range []Operation{
				OperationCreate, OperationRegister, OperationLocate, OperationGet,
				OperationRevoke, OperationDestroy, OperationQuery, OperationDiscoverVersions,
			} {
				children = append(children, encodeEnumeration(TagOperation, int32(operation)))
			}
		case queryFunctionObjects:
			children = append(children, encodeEnumeration(TagObjectType, objectTypeSymmetricKey))
		case queryFunctionServerInformation:
			children = append(children,
				encodeText(TagVendorIdentification, "trstctl"),
				encodeStructure(TagServerInformation),
			)
		case queryFunctionProfiles:
			children = append(children,
				encodeStructure(TagProfileInformation, encodeEnumeration(TagProfileName, profileSymmetricKeyLifecycleServer14)),
				encodeStructure(TagProfileInformation, encodeEnumeration(TagProfileName, profileSymmetricKeyFoundryServer14)),
			)
		default:
			return wireResponseItem{}, wireError{reason: resultReasonUnsupported, message: "QueryFunction is not supported by the served KMIP profile"}
		}
	}
	return wireResponseItem{
		operation: OperationQuery,
		payload:   encodeStructure(TagResponsePayload, children...),
	}, nil
}

type protocolVersion struct {
	major int32
	minor int32
}

var supportedProtocolVersions = []protocolVersion{{major: 1, minor: 4}}

func (s *Server) handleDiscoverVersions(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	if _, err := s.authClient(ctx, "discover_versions", clientCertDER); err != nil {
		return wireResponseItem{}, err
	}
	requested, err := parseProtocolVersions(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	negotiated := supportedProtocolVersions
	if len(requested) > 0 {
		negotiated = negotiated[:0]
		for _, supported := range supportedProtocolVersions {
			for _, offered := range requested {
				if offered == supported {
					negotiated = append(negotiated, supported)
					break
				}
			}
		}
	}
	children := make([][]byte, 0, len(negotiated))
	for _, version := range negotiated {
		children = append(children, encodeProtocolVersion(version))
	}
	return wireResponseItem{
		operation: OperationDiscoverVersions,
		payload:   encodeStructure(TagResponsePayload, children...),
	}, nil
}

func parseProtocolVersions(payload TTLV) ([]protocolVersion, error) {
	if payload.Tag == 0 {
		return nil, nil
	}
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidMessage, message: "DiscoverVersions request payload malformed"}
	}
	versions := payload.ChildrenByTag(TagProtocolVersion)
	out := make([]protocolVersion, 0, len(versions))
	for _, node := range versions {
		major, majorErr := integerChild(node, TagProtocolVersionMajor)
		minor, minorErr := integerChild(node, TagProtocolVersionMinor)
		if node.Type != TTLVStructure || majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
			return nil, wireError{reason: resultReasonInvalidField, message: "ProtocolVersion is malformed"}
		}
		out = append(out, protocolVersion{major: major, minor: minor})
	}
	return out, nil
}

func protocolVersionsIn(root TTLV) []protocolVersion {
	versions := root.ChildrenByTag(TagProtocolVersion)
	out := make([]protocolVersion, 0, len(versions))
	for _, node := range versions {
		major, majorErr := integerChild(node, TagProtocolVersionMajor)
		minor, minorErr := integerChild(node, TagProtocolVersionMinor)
		if node.Type != TTLVStructure || majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
			continue
		}
		out = append(out, protocolVersion{major: major, minor: minor})
	}
	return out
}

func encodeProtocolVersion(version protocolVersion) []byte {
	return encodeStructure(TagProtocolVersion,
		encodeInteger(TagProtocolVersionMajor, version.major),
		encodeInteger(TagProtocolVersionMinor, version.minor),
	)
}

func (s *Server) handleLocate(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	algorithm, err := parseLocateAlgorithm(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	ids, err := s.Locate(ctx, clientCertDER, algorithm)
	if err != nil {
		return wireResponseItem{}, err
	}
	children := make([][]byte, 0, len(ids))
	for _, id := range ids {
		children = append(children, encodeText(TagUniqueIdentifier, id))
	}
	return wireResponseItem{
		operation: OperationLocate,
		payload:   encodeStructure(TagResponsePayload, children...),
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

	keyValue := encodeStructure(TagKeyValue, encodeBytes(TagKeyMaterial, obj.Key))
	wrappingData := []byte(nil)
	if specNode, ok := payload.FirstChild(TagKeyWrappingSpecification); ok {
		spec, err := parseKeyWrappingSpecification(specNode)
		if err != nil {
			return wireResponseItem{}, err
		}
		wrappingKey, err := s.GetObject(ctx, clientCertDER, spec.keyID)
		if err != nil {
			return wireResponseItem{}, err
		}
		defer secret.Wipe(wrappingKey.Key)

		plaintext := obj.Key
		var encoded []byte
		if spec.encoding == encodingOptionTTLVEncoding {
			encoded = encodeStructure(TagKeyValue, encodeBytes(TagKeyMaterial, obj.Key))
			plaintext = encoded
			defer secret.Wipe(encoded)
		}
		sealed, err := crypto.AESGCMSeal(wrappingKey.Key, plaintext, nil)
		if err != nil {
			return wireResponseItem{}, fmt.Errorf("kmip: wrap key material: %w", err)
		}
		defer secret.Wipe(sealed)
		const nonceSize, tagSize = 12, 16
		if len(sealed) < nonceSize+tagSize {
			return wireResponseItem{}, errors.New("kmip: cryptographic boundary returned a truncated AES-GCM value")
		}
		nonce := sealed[:nonceSize]
		ciphertext := sealed[nonceSize : len(sealed)-tagSize]
		tag := sealed[len(sealed)-tagSize:]
		keyValue = encodeBytes(TagKeyValue, ciphertext)
		wrappingData = encodeStructure(TagKeyWrappingData,
			encodeEnumeration(TagWrappingMethod, wrappingMethodEncrypt),
			encodeStructure(TagEncryptionKeyInformation,
				encodeText(TagUniqueIdentifier, spec.keyID),
				encodeStructure(TagCryptographicParameters,
					encodeEnumeration(TagBlockCipherMode, blockCipherModeGCM),
				),
			),
			encodeBytes(TagMACSignature, tag),
			encodeBytes(TagIVCounterNonce, nonce),
			encodeEnumeration(TagEncodingOption, spec.encoding),
		)
	}
	// A key whose bit length overflows an int32 is not representable in KMIP and is
	// not something this server can hold; refuse rather than encode a wrong length.
	keyBits, err := wireInt32From(len(obj.Key) * 8)
	if err != nil {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "key length is not representable in KMIP"}
	}
	keyBlockChildren := [][]byte{
		encodeEnumeration(TagKeyFormatType, keyFormatTypeRaw),
		keyValue,
		encodeEnumeration(TagCryptographicAlgorithm, cryptographicAlgorithmAES),
		encodeInteger(TagCryptographicLength, keyBits),
	}
	if len(wrappingData) > 0 {
		keyBlockChildren = append(keyBlockChildren, wrappingData)
	}
	return wireResponseItem{
		operation: OperationGet,
		payload: encodeStructure(TagResponsePayload,
			encodeEnumeration(TagObjectType, objectTypeSymmetricKey),
			encodeText(TagUniqueIdentifier, obj.ID),
			encodeStructure(TagSymmetricKey,
				encodeStructure(TagKeyBlock, keyBlockChildren...),
			),
		),
	}, nil
}

type keyWrappingSpec struct {
	keyID    string
	encoding int32
}

func parseKeyWrappingSpecification(node TTLV) (keyWrappingSpec, error) {
	if node.Type != TTLVStructure {
		return keyWrappingSpec{}, wireError{reason: resultReasonInvalidField, message: "KeyWrappingSpecification must be a structure"}
	}
	method, err := enumChild(node, TagWrappingMethod)
	if err != nil || method != wrappingMethodEncrypt {
		return keyWrappingSpec{}, wireError{reason: resultReasonUnsupported, message: "only Encrypt key wrapping is served"}
	}
	info, ok := node.FirstChild(TagEncryptionKeyInformation)
	if !ok || info.Type != TTLVStructure {
		return keyWrappingSpec{}, wireError{reason: resultReasonInvalidField, message: "EncryptionKeyInformation is required"}
	}
	keyIDNode, ok := info.FirstChild(TagUniqueIdentifier)
	if !ok || keyIDNode.Type != TTLVTextString || strings.TrimSpace(string(keyIDNode.Value)) == "" {
		return keyWrappingSpec{}, wireError{reason: resultReasonInvalidField, message: "wrapping-key UniqueIdentifier is required"}
	}
	parameters, ok := info.FirstChild(TagCryptographicParameters)
	if !ok || parameters.Type != TTLVStructure {
		return keyWrappingSpec{}, wireError{reason: resultReasonInvalidField, message: "CryptographicParameters are required"}
	}
	mode, err := enumChild(parameters, TagBlockCipherMode)
	if err != nil || mode != blockCipherModeGCM {
		return keyWrappingSpec{}, wireError{reason: resultReasonUnsupported, message: "only AES-GCM key wrapping is served"}
	}
	encoding, err := enumChild(node, TagEncodingOption)
	if err != nil {
		encoding = encodingOptionNoEncoding
	}
	if encoding != encodingOptionNoEncoding && encoding != encodingOptionTTLVEncoding {
		return keyWrappingSpec{}, wireError{reason: resultReasonUnsupported, message: "unsupported key-wrapping EncodingOption"}
	}
	return keyWrappingSpec{keyID: strings.TrimSpace(string(keyIDNode.Value)), encoding: encoding}, nil
}

func (s *Server) registeredKeyMaterial(ctx context.Context, clientCertDER []byte, payload TTLV) ([]byte, error) {
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidMessage, message: "Register request payload missing"}
	}
	objectType, err := enumChild(payload, TagObjectType)
	if err != nil || objectType != objectTypeSymmetricKey {
		return nil, wireError{reason: resultReasonInvalidField, message: "Register serves only SymmetricKey objects"}
	}
	if template, ok := payload.FirstChild(TagTemplateAttribute); !ok || template.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidField, message: "TemplateAttribute is required"}
	}
	symmetricKey, ok := payload.FirstChild(TagSymmetricKey)
	if !ok || symmetricKey.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidField, message: "SymmetricKey object is required"}
	}
	keyBlock, ok := symmetricKey.FirstChild(TagKeyBlock)
	if !ok || keyBlock.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidField, message: "KeyBlock is required"}
	}
	format, err := enumChild(keyBlock, TagKeyFormatType)
	if err != nil || format != keyFormatTypeRaw {
		return nil, wireError{reason: resultReasonUnsupported, message: "Register serves only Raw key format"}
	}
	algorithm, err := enumChild(keyBlock, TagCryptographicAlgorithm)
	if err != nil || algorithm != cryptographicAlgorithmAES {
		return nil, wireError{reason: resultReasonInvalidField, message: "Register serves only AES keys"}
	}
	length, err := integerChild(keyBlock, TagCryptographicLength)
	if err != nil || length != 256 {
		return nil, wireError{reason: resultReasonInvalidField, message: "Register serves only AES-256 keys"}
	}
	keyValue, ok := keyBlock.FirstChild(TagKeyValue)
	if !ok {
		return nil, wireError{reason: resultReasonInvalidField, message: "KeyValue is required"}
	}
	wrappingData, wrapped := keyBlock.FirstChild(TagKeyWrappingData)
	if !wrapped {
		if keyValue.Type != TTLVStructure {
			return nil, wireError{reason: resultReasonInvalidField, message: "unwrapped KeyValue must be a structure"}
		}
		material, ok := keyValue.FirstChild(TagKeyMaterial)
		if !ok || material.Type != TTLVByteString || len(material.Value) != 32 {
			return nil, wireError{reason: resultReasonInvalidField, message: "KeyMaterial must contain 32 bytes"}
		}
		return append([]byte(nil), material.Value...), nil
	}
	if keyValue.Type != TTLVByteString {
		return nil, wireError{reason: resultReasonInvalidField, message: "wrapped KeyValue must be a byte string"}
	}
	spec, nonce, tag, err := parseKeyWrappingData(wrappingData)
	if err != nil {
		return nil, err
	}
	wrappingKey, err := s.GetObject(ctx, clientCertDER, spec.keyID)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(wrappingKey.Key)
	sealed := make([]byte, 0, len(nonce)+len(keyValue.Value)+len(tag))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, keyValue.Value...)
	sealed = append(sealed, tag...)
	defer secret.Wipe(sealed)
	plaintext, err := crypto.AESGCMOpen(wrappingKey.Key, sealed, nil)
	if err != nil {
		return nil, wireError{reason: resultReasonInvalidField, message: "wrapped KeyValue authentication failed"}
	}
	if spec.encoding == encodingOptionNoEncoding {
		if len(plaintext) != 32 {
			secret.Wipe(plaintext)
			return nil, wireError{reason: resultReasonInvalidField, message: "unwrapped KeyMaterial must contain 32 bytes"}
		}
		return plaintext, nil
	}
	decoded, err := ParseTTLV(plaintext)
	secret.Wipe(plaintext)
	if err != nil || decoded.Tag != TagKeyValue || decoded.Type != TTLVStructure {
		return nil, wireError{reason: resultReasonInvalidField, message: "wrapped TTLV KeyValue is malformed"}
	}
	material, ok := decoded.FirstChild(TagKeyMaterial)
	if !ok || material.Type != TTLVByteString || len(material.Value) != 32 {
		return nil, wireError{reason: resultReasonInvalidField, message: "wrapped TTLV KeyMaterial must contain 32 bytes"}
	}
	return append([]byte(nil), material.Value...), nil
}

func parseKeyWrappingData(node TTLV) (keyWrappingSpec, []byte, []byte, error) {
	if node.Type != TTLVStructure {
		return keyWrappingSpec{}, nil, nil, wireError{reason: resultReasonInvalidField, message: "KeyWrappingData must be a structure"}
	}
	spec, err := parseKeyWrappingSpecification(node)
	if err != nil {
		return keyWrappingSpec{}, nil, nil, err
	}
	nonce, ok := node.FirstChild(TagIVCounterNonce)
	if !ok || nonce.Type != TTLVByteString || len(nonce.Value) != 12 {
		return keyWrappingSpec{}, nil, nil, wireError{reason: resultReasonInvalidField, message: "AES-GCM IV/Counter/Nonce must contain 12 bytes"}
	}
	tag, ok := node.FirstChild(TagMACSignature)
	if !ok || tag.Type != TTLVByteString || len(tag.Value) != 16 {
		return keyWrappingSpec{}, nil, nil, wireError{reason: resultReasonInvalidField, message: "AES-GCM authentication tag must contain 16 bytes"}
	}
	return spec, nonce.Value, tag.Value, nil
}

func (s *Server) handleRevoke(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	if err := s.Revoke(ctx, clientCertDER, id); err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationRevoke,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id)),
	}, nil
}

func (s *Server) handleDestroy(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	if err := s.Destroy(ctx, clientCertDER, id); err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationDestroy,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id)),
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
					spec.algorithm = wireInt32(binary.BigEndian.Uint32(value.Value))
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

func parseLocateAlgorithm(payload TTLV) (string, error) {
	if payload.Tag == 0 {
		return "", nil
	}
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return "", wireError{reason: resultReasonInvalidMessage, message: "Locate request payload malformed"}
	}
	if tmpl, ok := payload.FirstChild(TagTemplateAttribute); ok && tmpl.Type == TTLVStructure {
		for _, attr := range tmpl.Children {
			if attr.Tag != TagAttribute || attr.Type != TTLVStructure {
				continue
			}
			name, value, ok := parseAttribute(attr)
			if !ok || normalizedAttributeName(name) != "cryptographic_algorithm" {
				continue
			}
			if value.Type != TTLVEnumeration || len(value.Value) != 4 {
				return "", wireError{reason: resultReasonInvalidField, message: "Cryptographic Algorithm must be an enumeration"}
			}
			if wireInt32(binary.BigEndian.Uint32(value.Value)) != cryptographicAlgorithmAES {
				return "", wireError{reason: resultReasonInvalidField, message: "only AES SymmetricKey Locate is served"}
			}
			return "AES", nil
		}
	}
	return "", nil
}

func parseUniqueIdentifierPayload(payload TTLV) (string, error) {
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return "", wireError{reason: resultReasonInvalidMessage, message: "UniqueIdentifier request payload missing"}
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

func encodeResponse(major, minor int32, items []wireResponseItem) []byte {
	if major <= 0 {
		major = 1
	}
	if minor < 0 {
		minor = 2
	}
	// A batch larger than an int32 has no KMIP encoding. It cannot arise here --
	// the request parser caps the batch long before a response is built -- but
	// emitting a truncated count would misdescribe the frame to the peer, so the
	// count is clamped to the maximum rather than wrapped to a small number.
	batchCount, err := wireInt32From(len(items))
	if err != nil {
		batchCount = math.MaxInt32
	}
	children := [][]byte{
		encodeStructure(TagResponseHeader,
			encodeStructure(TagProtocolVersion,
				encodeInteger(TagProtocolVersionMajor, major),
				encodeInteger(TagProtocolVersionMinor, minor),
			),
			encodeDateTime(TagTimeStamp, time.Now()),
			encodeInteger(TagBatchCount, batchCount),
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
	putInt32(buf[:], value)
	return encodeItem(tag, TTLVInteger, buf[:])
}

func encodeEnumeration(tag uint32, value int32) []byte {
	var buf [4]byte
	putInt32(buf[:], value)
	return encodeItem(tag, TTLVEnumeration, buf[:])
}

func encodeDateTime(tag uint32, value time.Time) []byte {
	var buf [8]byte
	// POSIX seconds are signed: KMIP DateTime legitimately encodes pre-1970.
	putInt64(buf[:], value.Unix())
	return encodeItem(tag, TTLVDateTime, buf[:])
}

func encodeText(tag uint32, value string) []byte {
	return encodeItem(tag, TTLVTextString, []byte(value))
}

func encodeBytes(tag uint32, value []byte) []byte {
	return encodeItem(tag, TTLVByteString, value)
}

func encodeItem(tag uint32, typ TTLVType, value []byte) []byte {
	padding := ttlvPadding(len(value))
	if len(value) > DefaultTTLVLimits.MaxFrameSize-8-padding {
		panic(fmt.Errorf("kmip: encoded value length %d exceeds frame cap %d", len(value), DefaultTTLVLimits.MaxFrameSize))
	}
	length, err := frameLen32(len(value))
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8+len(value)+padding)
	out[0] = byte(tag >> 16 & 0xFF)
	out[1] = byte(tag >> 8 & 0xFF)
	out[2] = byte(tag & 0xFF)
	out[3] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], length)
	copy(out[8:], value)
	return out
}
