// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// These frames follow the OASIS KMIP 1.4 Query, Discover Versions, Register,
// Get, Key Wrapping Specification, and Key Wrapping Data structures. Keeping
// them at the wire boundary prevents an in-process lifecycle method from being
// mistaken for appliance interoperability.
func TestKMIPOASIS14QueryAndDiscoverVersions(t *testing.T) {
	s := New("tenant-a", certAuth{}, &auditsink.Recorder{})
	good := []byte("good-client")

	query := ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagQueryFunction, queryFunctionOperations),
		ttlvEnumeration(TagQueryFunction, queryFunctionObjects),
		ttlvEnumeration(TagQueryFunction, queryFunctionServerInformation),
		ttlvEnumeration(TagQueryFunction, queryFunctionProfiles),
	)
	queryResponse, err := s.HandleFrame(context.Background(), good, kmipRequestFrame(OperationQuery, query))
	if err != nil {
		t.Fatalf("Query HandleFrame: %v", err)
	}
	queryRoot := mustKMIPSuccess(t, queryResponse, OperationQuery)
	operations := allEnumerationValues(queryRoot, TagOperation)
	for _, want := range []int32{
		int32(OperationCreate), int32(OperationRegister), int32(OperationLocate),
		int32(OperationGet), int32(OperationRevoke), int32(OperationDestroy),
		int32(OperationQuery), int32(OperationDiscoverVersions),
	} {
		if !containsEnumeration(operations, want) {
			t.Fatalf("Query Operations = %v, missing %#x", operations, want)
		}
	}
	if got := allEnumerationValues(queryRoot, TagObjectType); !containsEnumeration(got, objectTypeSymmetricKey) {
		t.Fatalf("Query Objects = %v, want SymmetricKey", got)
	}
	if got := allTextValues(queryRoot, TagVendorIdentification); len(got) != 1 || got[0] != "trstctl" {
		t.Fatalf("Query vendor identification = %v, want trstctl", got)
	}
	profiles := allEnumerationValues(queryRoot, TagProfileName)
	if !containsEnumeration(profiles, profileSymmetricKeyLifecycleServer14) ||
		!containsEnumeration(profiles, profileSymmetricKeyFoundryServer14) {
		t.Fatalf("Query Profiles = %v, want lifecycle and foundry server v1.4", profiles)
	}

	discover := ttlvStructure(TagRequestPayload,
		protocolVersionTTLV(1, 4),
		protocolVersionTTLV(1, 3),
	)
	discoverResponse, err := s.HandleFrame(context.Background(), good, kmipRequestFrame(OperationDiscoverVersions, discover))
	if err != nil {
		t.Fatalf("DiscoverVersions HandleFrame: %v", err)
	}
	discoverRoot := mustKMIPSuccess(t, discoverResponse, OperationDiscoverVersions)
	versions := protocolVersionsIn(mustFindNode(t, discoverRoot, TagResponsePayload))
	if len(versions) != 1 || versions[0] != (protocolVersion{major: 1, minor: 4}) {
		t.Fatalf("DiscoverVersions = %+v, want only negotiated 1.4", versions)
	}
}

func TestKMIPOASIS14RegisterWrapAndUnwrap(t *testing.T) {
	ctx := context.Background()
	recorder := &auditsink.Recorder{}
	s := New("tenant-a", certAuth{}, recorder)
	t.Cleanup(s.Close)
	good := []byte("good-client")

	wrappingResponse, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationCreate, kmipCreateAES256Payload()))
	if err != nil {
		t.Fatalf("create wrapping key: %v", err)
	}
	wrappingID := mustFindText(t, mustKMIPSuccess(t, wrappingResponse, OperationCreate), TagUniqueIdentifier)

	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	registerResponse, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationRegister, kmipRegisterRawAES256Payload(keyMaterial)))
	if err != nil {
		t.Fatalf("Register raw key: %v", err)
	}
	targetID := mustFindText(t, mustKMIPSuccess(t, registerResponse, OperationRegister), TagUniqueIdentifier)

	wrappedResponse, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationGet, kmipGetWrappedPayload(targetID, wrappingID, encodingOptionNoEncoding)))
	if err != nil {
		t.Fatalf("Get wrapped key: %v", err)
	}
	wrappedRoot := mustKMIPSuccess(t, wrappedResponse, OperationGet)
	wrappedObject := mustFindNode(t, wrappedRoot, TagSymmetricKey)
	keyBlock := mustFindNode(t, wrappedObject, TagKeyBlock)
	keyValue := mustFindNode(t, keyBlock, TagKeyValue)
	if keyValue.Type != TTLVByteString || len(keyValue.Value) != len(keyMaterial) {
		t.Fatalf("wrapped KeyValue type=%#x bytes=%d, want 32-byte GCM ciphertext", keyValue.Type, len(keyValue.Value))
	}
	wrappingData := mustFindNode(t, keyBlock, TagKeyWrappingData)
	if got, err := enumChild(wrappingData, TagWrappingMethod); err != nil || got != wrappingMethodEncrypt {
		t.Fatalf("WrappingMethod = %d err=%v, want Encrypt", got, err)
	}
	if got, err := enumChild(wrappingData, TagEncodingOption); err != nil || got != encodingOptionNoEncoding {
		t.Fatalf("EncodingOption = %d err=%v, want NoEncoding", got, err)
	}
	if nonce := mustFindNode(t, wrappingData, TagIVCounterNonce); nonce.Type != TTLVByteString || len(nonce.Value) != 12 {
		t.Fatalf("IV/Counter/Nonce type=%#x bytes=%d, want 12-byte GCM nonce", nonce.Type, len(nonce.Value))
	}
	if tag := mustFindNode(t, wrappingData, TagMACSignature); tag.Type != TTLVByteString || len(tag.Value) != 16 {
		t.Fatalf("MAC/Signature type=%#x bytes=%d, want 16-byte GCM authentication tag", tag.Type, len(tag.Value))
	}

	cloneResponse, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationRegister,
		ttlvStructure(TagRequestPayload,
			ttlvEnumeration(TagObjectType, objectTypeSymmetricKey),
			ttlvStructure(TagTemplateAttribute),
			encodeParsedTTLV(wrappedObject),
		),
	))
	if err != nil {
		t.Fatalf("Register wrapped key: %v", err)
	}
	cloneID := mustFindText(t, mustKMIPSuccess(t, cloneResponse, OperationRegister), TagUniqueIdentifier)
	cloneGetResponse, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(cloneID)))
	if err != nil {
		t.Fatalf("Get unwrapped clone: %v", err)
	}
	cloneRoot := mustKMIPSuccess(t, cloneGetResponse, OperationGet)
	cloneMaterial := mustFindNode(t, cloneRoot, TagKeyMaterial).Value
	defer secret.Wipe(cloneMaterial)
	if !bytes.Equal(cloneMaterial, keyMaterial) {
		t.Fatalf("unwrapped clone differs: got %x want %x", cloneMaterial, keyMaterial)
	}
	if recorder.Count("kmip.object.registered") != 2 {
		t.Fatalf("registered audit events = %d, want raw + wrapped Register", recorder.Count("kmip.object.registered"))
	}
}

func kmipRegisterRawAES256Payload(key []byte) []byte {
	return ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagObjectType, objectTypeSymmetricKey),
		ttlvStructure(TagTemplateAttribute),
		ttlvStructure(TagSymmetricKey,
			ttlvStructure(TagKeyBlock,
				ttlvEnumeration(TagKeyFormatType, keyFormatTypeRaw),
				ttlvStructure(TagKeyValue, ttlvEncode(TagKeyMaterial, TTLVByteString, key)),
				ttlvEnumeration(TagCryptographicAlgorithm, cryptographicAlgorithmAES),
				ttlvInteger(TagCryptographicLength, 256),
			),
		),
	)
}

func kmipGetWrappedPayload(targetID, wrappingID string, encoding int32) []byte {
	return ttlvStructure(TagRequestPayload,
		ttlvText(TagUniqueIdentifier, targetID),
		ttlvStructure(TagKeyWrappingSpecification,
			ttlvEnumeration(TagWrappingMethod, wrappingMethodEncrypt),
			ttlvStructure(TagEncryptionKeyInformation,
				ttlvText(TagUniqueIdentifier, wrappingID),
				ttlvStructure(TagCryptographicParameters,
					ttlvEnumeration(TagBlockCipherMode, blockCipherModeGCM),
				),
			),
			ttlvEnumeration(TagEncodingOption, encoding),
		),
	)
}

func protocolVersionTTLV(major, minor int32) []byte {
	return ttlvStructure(TagProtocolVersion,
		ttlvInteger(TagProtocolVersionMajor, major),
		ttlvInteger(TagProtocolVersionMinor, minor),
	)
}

func mustFindNode(t *testing.T, root TTLV, tag uint32) TTLV {
	t.Helper()
	if root.Tag == tag {
		return root
	}
	for _, child := range root.Children {
		if found, ok := findNode(child, tag); ok {
			return found
		}
	}
	t.Fatalf("response missing tag %#06x", tag)
	return TTLV{}
}

func findNode(root TTLV, tag uint32) (TTLV, bool) {
	if root.Tag == tag {
		return root, true
	}
	for _, child := range root.Children {
		if found, ok := findNode(child, tag); ok {
			return found, true
		}
	}
	return TTLV{}, false
}

func allEnumerationValues(root TTLV, tag uint32) []int32 {
	var out []int32
	var walk func(TTLV)
	walk = func(node TTLV) {
		if node.Tag == tag && node.Type == TTLVEnumeration && len(node.Value) == 4 {
			out = append(out, wireInt32(binary.BigEndian.Uint32(node.Value)))
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(root)
	return out
}

func containsEnumeration(values []int32, want int32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func encodeParsedTTLV(node TTLV) []byte {
	if node.Type == TTLVStructure {
		children := make([][]byte, 0, len(node.Children))
		for _, child := range node.Children {
			children = append(children, encodeParsedTTLV(child))
		}
		return encodeStructure(node.Tag, children...)
	}
	return encodeItem(node.Tag, node.Type, node.Value)
}
