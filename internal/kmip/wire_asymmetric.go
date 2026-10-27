// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"encoding/binary"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Wire handlers for the asymmetric profile (A197).

// keyPairTemplate is what one Template-Attribute of a Create Key Pair carries.
type keyPairTemplate struct {
	algorithm, length, mask *int32
	names                   []string
	extractable             *bool
}

func readKeyPairTemplate(node TTLV) (keyPairTemplate, error) {
	var t keyPairTemplate
	if node.Type != TTLVStructure {
		return t, wireError{reason: resultReasonInvalidField, message: "a Template-Attribute must be a structure"}
	}
	for _, child := range node.Children {
		if child.Tag == TagName {
			// A Name directly inside a Template-Attribute names a Template
			// object, deprecated since KMIP 1.3.
			return t, wireError{reason: resultReasonFeatureNotSupported, message: "Template objects are not served; send individual attributes"}
		}
		if child.Tag != TagAttribute {
			continue
		}
		name, value, ok := parseAttribute(child)
		if !ok {
			return t, wireError{reason: resultReasonInvalidField, message: "an Attribute needs a name and a value"}
		}
		attr := requestedAttribute{name: name, value: value}
		switch normalizedAttributeName(name) {
		case "cryptographic_algorithm", "cryptographic_length", "cryptographic_usage_mask":
			n, err := int32Value(value)
			if err != nil {
				return t, wireError{reason: resultReasonInvalidField, message: name + " is malformed"}
			}
			switch normalizedAttributeName(name) {
			case "cryptographic_algorithm":
				t.algorithm = &n
			case "cryptographic_length":
				t.length = &n
			default:
				t.mask = &n
			}
		case "name":
			v, err := nameValue(attr)
			if err != nil {
				return t, err
			}
			t.names = append(t.names, v)
		case "extractable":
			v, err := booleanValue(attr)
			if err != nil {
				return t, err
			}
			t.extractable = &v
		case "operation_policy_name":
			// The server applies its own policy: the tenant's clients share the
			// tenant's objects.
		case "activation_date":
			return t, wireError{reason: resultReasonFeatureNotSupported, message: "activate the key pair with Activate after creating it"}
		default:
			return t, wireError{reason: resultReasonFeatureNotSupported, message: "attribute " + name + " is not served on Create Key Pair"}
		}
	}
	return t, nil
}

func int32Value(node TTLV) (int32, error) {
	if (node.Type != TTLVEnumeration && node.Type != TTLVInteger) || len(node.Value) != 4 {
		return 0, wireError{reason: resultReasonInvalidField, message: "expected a 32-bit value"}
	}
	return wireInt32(binary.BigEndian.Uint32(node.Value)), nil
}

func parseKeyPairSpec(payload TTLV) (KeyPairSpec, error) {
	if payload.Tag != TagRequestPayload || payload.Type != TTLVStructure {
		return KeyPairSpec{}, wireError{reason: resultReasonInvalidMessage, message: "Create Key Pair request payload missing"}
	}
	var common, private, public keyPairTemplate
	for _, part := range []struct {
		tag uint32
		out *keyPairTemplate
	}{{TagCommonTemplateAttribute, &common}, {TagPrivateKeyTemplateAttribute, &private}, {TagPublicKeyTemplateAttribute, &public}} {
		if node, ok := payload.FirstChild(part.tag); ok {
			t, err := readKeyPairTemplate(node)
			if err != nil {
				return KeyPairSpec{}, err
			}
			*part.out = t
		}
	}
	pick := func(specific, shared *int32) *int32 {
		if specific != nil {
			return specific
		}
		return shared
	}
	privAlg, pubAlg := pick(private.algorithm, common.algorithm), pick(public.algorithm, common.algorithm)
	privLen, pubLen := pick(private.length, common.length), pick(public.length, common.length)
	if privAlg == nil || pubAlg == nil {
		return KeyPairSpec{}, wireError{reason: resultReasonInvalidField, message: "Cryptographic Algorithm is required"}
	}
	if *privAlg != *pubAlg || (privLen == nil) != (pubLen == nil) || (privLen != nil && *privLen != *pubLen) {
		return KeyPairSpec{}, wireError{reason: resultReasonInvalidField, message: "the private and public keys must share Cryptographic Algorithm and Length"}
	}
	spec := KeyPairSpec{}
	switch *privAlg {
	case cryptographicAlgorithmRSA:
		spec.Algorithm, spec.Length = "RSA", 2048
	case cryptographicAlgorithmECDSA:
		spec.Algorithm, spec.Length = "ECDSA", 256
	default:
		return KeyPairSpec{}, wireError{reason: resultReasonInvalidField, message: "key pairs are RSA or ECDSA"}
	}
	if privLen != nil {
		spec.Length = int(*privLen)
	}
	if mask := pick(private.mask, common.mask); mask != nil {
		spec.PrivateMask = *mask
	}
	if mask := pick(public.mask, common.mask); mask != nil {
		spec.PublicMask = *mask
	}
	spec.PrivateNames = append(append([]string(nil), common.names...), private.names...)
	spec.PublicNames = append(append([]string(nil), common.names...), public.names...)
	if len(spec.PrivateNames) > maxObjectNames || len(spec.PublicNames) > maxObjectNames {
		return KeyPairSpec{}, wireError{reason: resultReasonInvalidField, message: "too many names"}
	}
	if private.extractable != nil {
		spec.PrivateExtractable = private.extractable
	} else {
		spec.PrivateExtractable = common.extractable
	}
	return spec, nil
}

func (s *Server) handleCreateKeyPair(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	spec, err := parseKeyPairSpec(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	privateID, publicID, err := s.CreateKeyPair(ctx, clientCertDER, spec)
	if err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationCreateKeyPair,
		payload: encodeStructure(TagResponsePayload,
			encodeText(TagPrivateKeyUniqueIdentifier, privateID),
			encodeText(TagPublicKeyUniqueIdentifier, publicID),
		),
	}, nil
}

func (s *Server) handleActivate(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	if err := s.Activate(ctx, clientCertDER, id); err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationActivate,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id)),
	}, nil
}

func (s *Server) handleGetAttributes(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	var names []string
	for _, node := range payload.ChildrenByTag(TagAttributeName) {
		if node.Type != TTLVTextString {
			return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "Attribute Name must be text"}
		}
		names = append(names, string(node.Value))
	}
	attrs, err := s.GetAttributes(ctx, clientCertDER, id, names)
	if err != nil {
		return wireResponseItem{}, err
	}
	children := [][]byte{encodeText(TagUniqueIdentifier, id)}
	for _, attr := range attrs {
		children = append(children, attr.encode())
	}
	return wireResponseItem{operation: OperationGetAttributes, payload: encodeStructure(TagResponsePayload, children...)}, nil
}

func (s *Server) handleGetAttributeList(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	names, err := s.GetAttributeList(ctx, clientCertDER, id)
	if err != nil {
		return wireResponseItem{}, err
	}
	children := [][]byte{encodeText(TagUniqueIdentifier, id)}
	for _, name := range names {
		children = append(children, encodeText(TagAttributeName, name))
	}
	return wireResponseItem{operation: OperationGetAttributeList, payload: encodeStructure(TagResponsePayload, children...)}, nil
}

func (s *Server) handleAddAttribute(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	return s.handleAttributeChange(ctx, clientCertDER, OperationAddAttribute, payload)
}

func (s *Server) handleModifyAttribute(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	return s.handleAttributeChange(ctx, clientCertDER, OperationModifyAttribute, payload)
}

func (s *Server) handleDeleteAttribute(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	return s.handleAttributeChange(ctx, clientCertDER, OperationDeleteAttribute, payload)
}

func (s *Server) handleAttributeChange(ctx context.Context, clientCertDER []byte, op Operation, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	attr, err := parseRequestedAttribute(op, payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	instance, err := s.ChangeAttribute(ctx, clientCertDER, op, id, attr)
	if err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: op,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id), instance.encode()),
	}, nil
}

// parseRequestedAttribute reads the attribute an Add or Modify Attribute
// carries, or the name and index a Delete Attribute names.
func parseRequestedAttribute(op Operation, payload TTLV) (requestedAttribute, error) {
	node := payload
	if op != OperationDeleteAttribute {
		attrNode, ok := payload.FirstChild(TagAttribute)
		if !ok || attrNode.Type != TTLVStructure {
			return requestedAttribute{}, wireError{reason: resultReasonInvalidField, message: "an Attribute is required"}
		}
		node = attrNode
	}
	nameNode, ok := node.FirstChild(TagAttributeName)
	if !ok || nameNode.Type != TTLVTextString || strings.TrimSpace(string(nameNode.Value)) == "" {
		return requestedAttribute{}, wireError{reason: resultReasonInvalidField, message: "Attribute Name is required"}
	}
	attr := requestedAttribute{name: string(nameNode.Value)}
	if indexNode, ok := node.FirstChild(TagAttributeIndex); ok {
		if op == OperationAddAttribute {
			return requestedAttribute{}, wireError{reason: resultReasonInvalidField, message: "Add Attribute takes no Attribute Index"}
		}
		index, err := int32Value(indexNode)
		if err != nil || index < 0 {
			return requestedAttribute{}, wireError{reason: resultReasonInvalidField, message: "Attribute Index is malformed"}
		}
		attr.index = index
	}
	if op != OperationDeleteAttribute {
		value, ok := node.FirstChild(TagAttributeValue)
		if !ok {
			return requestedAttribute{}, wireError{reason: resultReasonInvalidField, message: "Attribute Value is required"}
		}
		attr.value = value
	}
	return attr, nil
}

// parseSignatureParams reads a request's Cryptographic Parameters: a Digital
// Signature Algorithm, or a Cryptographic Algorithm with a Hashing Algorithm
// and, for RSA, a Padding Method. SHA-256, -384 and -512 are served.
func parseSignatureParams(payload TTLV) (SignatureParams, error) {
	node, ok := payload.FirstChild(TagCryptographicParameters)
	if !ok {
		return SignatureParams{}, nil
	}
	if node.Type != TTLVStructure {
		return SignatureParams{}, wireError{reason: resultReasonInvalidField, message: "Cryptographic Parameters must be a structure"}
	}
	var params SignatureParams
	if v, err := enumChild(node, TagCryptographicAlgorithm); err == nil {
		switch v {
		case cryptographicAlgorithmRSA:
			params.Algorithm = "RSA"
		case cryptographicAlgorithmECDSA:
			params.Algorithm = "ECDSA"
		default:
			return SignatureParams{}, wireError{reason: resultReasonInvalidField, message: "signatures are RSA or ECDSA"}
		}
	}
	if v, err := enumChild(node, TagHashingAlgorithm); err == nil {
		hash, ok := map[int32]crypto.Hash{hashingAlgorithmSHA256: crypto.SHA256, hashingAlgorithmSHA384: crypto.SHA384, hashingAlgorithmSHA512: crypto.SHA512}[v]
		if !ok {
			return SignatureParams{}, wireError{reason: resultReasonFeatureNotSupported, message: "signatures use SHA-256, SHA-384 or SHA-512"}
		}
		params.Hash = hash
	}
	if v, err := enumChild(node, TagPaddingMethod); err == nil {
		switch v {
		case paddingMethodPKCS1v15:
			params.Padding = crypto.RSAPKCS1v15
		case paddingMethodPSS:
			params.Padding = crypto.RSAPSS
		default:
			return SignatureParams{}, wireError{reason: resultReasonFeatureNotSupported, message: "RSA signatures use PKCS#1 v1.5 or PSS padding"}
		}
	}
	if v, err := enumChild(node, TagDigitalSignatureAlgorithm); err == nil {
		scheme, ok := map[int32]SignatureParams{
			signatureSHA256WithRSA:   {Algorithm: "RSA", Hash: crypto.SHA256, Padding: crypto.RSAPKCS1v15},
			signatureSHA384WithRSA:   {Algorithm: "RSA", Hash: crypto.SHA384, Padding: crypto.RSAPKCS1v15},
			signatureSHA512WithRSA:   {Algorithm: "RSA", Hash: crypto.SHA512, Padding: crypto.RSAPKCS1v15},
			signatureRSASSAPSS:       {Algorithm: "RSA", Hash: params.Hash, Padding: crypto.RSAPSS},
			signatureECDSAWithSHA256: {Algorithm: "ECDSA", Hash: crypto.SHA256},
			signatureECDSAWithSHA384: {Algorithm: "ECDSA", Hash: crypto.SHA384},
			signatureECDSAWithSHA512: {Algorithm: "ECDSA", Hash: crypto.SHA512},
		}[v]
		if !ok {
			return SignatureParams{}, wireError{reason: resultReasonFeatureNotSupported, message: "the Digital Signature Algorithm is not served"}
		}
		if (params.Algorithm != "" && params.Algorithm != scheme.Algorithm) || (params.Hash != "" && params.Hash != scheme.Hash) ||
			(params.Padding != "" && params.Padding != scheme.Padding) {
			return SignatureParams{}, wireError{reason: resultReasonInvalidField, message: "the Digital Signature Algorithm contradicts the other Cryptographic Parameters"}
		}
		params = scheme
	}
	return params, nil
}

// singlePartData reads a Sign or Signature Verify request's Data; digested
// data and streamed operations are not served.
func singlePartData(payload TTLV) ([]byte, error) {
	for _, tag := range []uint32{TagDigestedData, TagCorrelationValue, TagInitIndicator, TagFinalIndicator} {
		if _, ok := payload.FirstChild(tag); ok {
			return nil, wireError{reason: resultReasonFeatureNotSupported, message: "single-part signatures over Data are served; digested and streamed data are not"}
		}
	}
	data, ok := payload.FirstChild(TagData)
	if !ok || data.Type != TTLVByteString {
		return nil, wireError{reason: resultReasonInvalidField, message: "Data is required"}
	}
	return data.Value, nil
}

func (s *Server) handleSign(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	params, err := parseSignatureParams(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	data, err := singlePartData(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	signature, err := s.Sign(ctx, clientCertDER, id, params, data)
	if err != nil {
		return wireResponseItem{}, err
	}
	return wireResponseItem{
		operation: OperationSign,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id), encodeBytes(TagSignatureData, signature)),
	}, nil
}

func (s *Server) handleSignatureVerify(ctx context.Context, clientCertDER []byte, payload TTLV) (wireResponseItem, error) {
	id, err := parseUniqueIdentifierPayload(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	params, err := parseSignatureParams(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	data, err := singlePartData(payload)
	if err != nil {
		return wireResponseItem{}, err
	}
	signature, ok := payload.FirstChild(TagSignatureData)
	if !ok || signature.Type != TTLVByteString {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "Signature Data is required"}
	}
	valid, err := s.SignatureVerify(ctx, clientCertDER, id, params, data, signature.Value)
	if err != nil {
		return wireResponseItem{}, err
	}
	indicator := validityIndicatorInvalid
	if valid {
		indicator = validityIndicatorValid
	}
	return wireResponseItem{
		operation: OperationSignatureVerify,
		payload:   encodeStructure(TagResponsePayload, encodeText(TagUniqueIdentifier, id), encodeEnumeration(TagValidityIndicator, indicator)),
	}, nil
}

// handleGetKey answers Get for a key pair half: a public key as an X.509
// SubjectPublicKeyInfo, an extractable private key as PKCS#8. Wrapping is
// served for symmetric keys only.
func (s *Server) handleGetKey(ctx context.Context, clientCertDER []byte, id string, payload TTLV) (wireResponseItem, error) {
	if _, ok := payload.FirstChild(TagKeyWrappingSpecification); ok {
		return wireResponseItem{}, wireError{reason: resultReasonFeatureNotSupported, message: "key wrapping is served for symmetric keys"}
	}
	key, err := s.GetKey(ctx, clientCertDER, id)
	if err != nil {
		return wireResponseItem{}, err
	}
	defer secret.Wipe(key.Material)
	length, err := wireInt32From(key.Length)
	if err != nil {
		return wireResponseItem{}, wireError{reason: resultReasonInvalidField, message: "key length is not representable in KMIP"}
	}
	format, objectType, objectTag := keyFormatTypeX509, objectTypePublicKey, TagPublicKey
	if key.Type == ObjectPrivateKey {
		format, objectType, objectTag = keyFormatTypePKCS8, objectTypePrivateKey, TagPrivateKey
	}
	return wireResponseItem{
		operation: OperationGet,
		payload: encodeStructure(TagResponsePayload,
			encodeEnumeration(TagObjectType, objectType),
			encodeText(TagUniqueIdentifier, key.ID),
			encodeStructure(objectTag, encodeStructure(TagKeyBlock,
				encodeEnumeration(TagKeyFormatType, format),
				encodeStructure(TagKeyValue, encodeBytes(TagKeyMaterial, key.Material)),
				encodeEnumeration(TagCryptographicAlgorithm, algorithmEnum(key.Algorithm)),
				encodeInteger(TagCryptographicLength, length),
			)),
		),
	}, nil
}
