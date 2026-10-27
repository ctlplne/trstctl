// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

// A197: a client creates an RSA and an ECDSA key pair over the wire. Each
// half starts Pre-Active and signs nothing until activated; once active, the
// private key signs and the public key verifies, and the public key a client
// reads back verifies the same signature on its own. The private key never
// leaves the server, a compromise revocation stops it signing, Locate finds
// pairs by type and name, and Query lists the wider profile.
func TestKMIPKeyPairSignsOnlyOnceActivated(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("tenant-a", certAuth{}, rec)
	good := []byte("good-client")
	call := func(op Operation, payload []byte) []byte {
		t.Helper()
		resp, err := s.HandleFrame(ctx, good, kmipRequestFrame(op, payload))
		if err != nil {
			t.Fatalf("%s: %v", operationName(op), err)
		}
		return resp
	}
	createPair := func(algorithm, length int32, name string) (string, string) {
		t.Helper()
		root := mustKMIPSuccess(t, call(OperationCreateKeyPair, kmipCreateKeyPairPayload(algorithm, length, name)), OperationCreateKeyPair)
		return mustFindText(t, root, TagPrivateKeyUniqueIdentifier), mustFindText(t, root, TagPublicKeyUniqueIdentifier)
	}
	state := func(id string) int32 {
		t.Helper()
		root := mustKMIPSuccess(t, call(OperationGetAttributes, kmipGetAttributesPayload(id, attrState)), OperationGetAttributes)
		values := allEnumerationValues(root, TagAttributeValue)
		if len(values) != 1 {
			t.Fatalf("State of %s = %v", id, values)
		}
		return values[0]
	}
	data := []byte("the release manifest")
	pss := ttlvStructure(TagCryptographicParameters,
		ttlvEnumeration(TagCryptographicAlgorithm, cryptographicAlgorithmRSA),
		ttlvEnumeration(TagHashingAlgorithm, hashingAlgorithmSHA256),
		ttlvEnumeration(TagPaddingMethod, paddingMethodPSS),
	)

	rsaPrivate, rsaPublic := createPair(cryptographicAlgorithmRSA, 2048, "release-signing")
	if state(rsaPrivate) != stateEnumPreActive || state(rsaPublic) != stateEnumPreActive {
		t.Fatal("a new key pair is not Pre-Active")
	}
	if reason := failureReason(t, call(OperationSign, kmipSignPayload(rsaPrivate, pss, data)), OperationSign); reason != resultReasonPermissionDenied {
		t.Fatalf("Sign with a Pre-Active key = reason %#x, want Permission Denied", reason)
	}
	for _, id := range []string{rsaPrivate, rsaPublic} {
		mustKMIPSuccess(t, call(OperationActivate, kmipUniqueIDPayload(id)), OperationActivate)
	}
	if reason := failureReason(t, call(OperationActivate, kmipUniqueIDPayload(rsaPrivate)), OperationActivate); reason != resultReasonPermissionDenied {
		t.Fatalf("activating an active key = reason %#x", reason)
	}
	if state(rsaPrivate) != stateEnumActive {
		t.Fatal("Activate did not make the key Active")
	}

	signed := mustKMIPSuccess(t, call(OperationSign, kmipSignPayload(rsaPrivate, pss, data)), OperationSign)
	signature := mustFindNode(t, signed, TagSignatureData).Value
	verify := func(id string, params, message, sig []byte) int32 {
		t.Helper()
		root := mustKMIPSuccess(t, call(OperationSignatureVerify, kmipVerifyPayload(id, params, message, sig)), OperationSignatureVerify)
		values := allEnumerationValues(root, TagValidityIndicator)
		if len(values) != 1 {
			t.Fatalf("Validity Indicator = %v", values)
		}
		return values[0]
	}
	if verify(rsaPublic, pss, data, signature) != validityIndicatorValid || verify(rsaPublic, pss, []byte("tampered"), signature) != validityIndicatorInvalid {
		t.Fatal("the public key did not verify its own signature and refuse a tampered message")
	}
	got := mustKMIPSuccess(t, call(OperationGet, kmipUniqueIDPayload(rsaPublic)), OperationGet)
	if formats := allEnumerationValues(got, TagKeyFormatType); len(formats) != 1 || formats[0] != keyFormatTypeX509 {
		t.Fatalf("public key format = %v, want X.509", formats)
	}
	spki := mustFindNode(t, got, TagKeyMaterial).Value
	if err := crypto.Verify(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: spki}, data, signature, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPSS}); err != nil {
		t.Fatalf("the public key read back does not verify the signature: %v", err)
	}
	if reason := failureReason(t, call(OperationGet, kmipUniqueIDPayload(rsaPrivate)), OperationGet); reason != resultReasonNotExtractable {
		t.Fatalf("Get of the private key = reason %#x, want Not Extractable", reason)
	}

	ecPrivate, ecPublic := createPair(cryptographicAlgorithmECDSA, 256, "")
	for _, id := range []string{ecPrivate, ecPublic} {
		mustKMIPSuccess(t, call(OperationActivate, kmipUniqueIDPayload(id)), OperationActivate)
	}
	ecdsa := ttlvStructure(TagCryptographicParameters, ttlvEnumeration(TagDigitalSignatureAlgorithm, signatureECDSAWithSHA256))
	ecSigned := mustKMIPSuccess(t, call(OperationSign, kmipSignPayload(ecPrivate, ecdsa, data)), OperationSign)
	if verify(ecPublic, ecdsa, data, mustFindNode(t, ecSigned, TagSignatureData).Value) != validityIndicatorValid {
		t.Fatal("the ECDSA signature did not verify")
	}
	if reason := failureReason(t, call(OperationSign, kmipSignPayload(ecPrivate, pss, data)), OperationSign); reason != resultReasonInvalidField {
		t.Fatalf("RSA parameters on an ECDSA key = reason %#x", reason)
	}

	privateKeys := locateIDs(t, call(OperationLocate, ttlvStructure(TagRequestPayload, kmipAttribute(attrObjectType, ttlvEnumeration(TagAttributeValue, objectTypePrivateKey)))))
	if len(privateKeys) != 2 || !contains(privateKeys, rsaPrivate) || !contains(privateKeys, ecPrivate) {
		t.Fatalf("Locate private keys = %v", privateKeys)
	}
	named := locateIDs(t, call(OperationLocate, ttlvStructure(TagRequestPayload, kmipAttribute(attrName, kmipNameValue("release-signing")))))
	if len(named) != 2 || !contains(named, rsaPrivate) || !contains(named, rsaPublic) {
		t.Fatalf("Locate by name = %v", named)
	}

	revoke := ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, rsaPrivate),
		ttlvStructure(TagRevocationReason, ttlvEnumeration(TagRevocationReasonCode, revocationReasonKeyCompromise)))
	mustKMIPSuccess(t, call(OperationRevoke, revoke), OperationRevoke)
	if state(rsaPrivate) != stateEnumCompromised {
		t.Fatal("a compromise revocation did not leave the key Compromised")
	}
	if reason := failureReason(t, call(OperationSign, kmipSignPayload(rsaPrivate, pss, data)), OperationSign); reason != resultReasonPermissionDenied {
		t.Fatalf("Sign with a compromised key = reason %#x", reason)
	}

	query := mustKMIPSuccess(t, call(OperationQuery, ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagQueryFunction, queryFunctionOperations), ttlvEnumeration(TagQueryFunction, queryFunctionObjects))), OperationQuery)
	ops := allEnumerationValues(query, TagOperation)
	for _, want := range []Operation{OperationCreateKeyPair, OperationActivate, OperationGetAttributes, OperationSign, OperationSignatureVerify} {
		if !containsEnumeration(ops, int32(want)) {
			t.Fatalf("Query does not list operation %#x", want)
		}
	}
	if objects := allEnumerationValues(query, TagObjectType); !containsEnumeration(objects, objectTypePrivateKey) || !containsEnumeration(objects, objectTypePublicKey) {
		t.Fatalf("Query objects = %v", objects)
	}
	if rec.Count("kmip.object.created") != 4 || rec.Count("kmip.object.activated") != 4 {
		t.Fatalf("audit created=%d activated=%d", rec.Count("kmip.object.created"), rec.Count("kmip.object.activated"))
	}
}

// A197: a client names an object, sets contact information and its own x-
// attributes, modifies and deletes them, and reads them back; the server's
// attributes are read-only, and a key a client made unextractable stays so.
func TestKMIPAttributeOperations(t *testing.T) {
	ctx := context.Background()
	s := New("tenant-a", certAuth{}, &auditsink.Recorder{})
	good := []byte("good-client")
	call := func(op Operation, payload []byte) []byte {
		t.Helper()
		resp, err := s.HandleFrame(ctx, good, kmipRequestFrame(op, payload))
		if err != nil {
			t.Fatalf("%s: %v", operationName(op), err)
		}
		return resp
	}
	id := mustFindText(t, mustKMIPSuccess(t, call(OperationCreate, kmipCreateAES256Payload()), OperationCreate), TagUniqueIdentifier)
	change := func(op Operation, attr []byte) []byte {
		return call(op, ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, id), attr))
	}
	mustKMIPSuccess(t, change(OperationAddAttribute, kmipAttribute(attrName, kmipNameValue("db-tde"))), OperationAddAttribute)
	mustKMIPSuccess(t, change(OperationAddAttribute, kmipAttribute(attrName, kmipNameValue("db-tde-2026"))), OperationAddAttribute)
	mustKMIPSuccess(t, change(OperationAddAttribute, kmipAttribute("x-owner", ttlvText(TagAttributeValue, "storage team"))), OperationAddAttribute)
	mustKMIPSuccess(t, change(OperationAddAttribute, kmipAttribute(attrContactInformation, ttlvText(TagAttributeValue, "storage-oncall"))), OperationAddAttribute)

	list := mustKMIPSuccess(t, call(OperationGetAttributeList, kmipUniqueIDPayload(id)), OperationGetAttributeList)
	names := allTextValues(list, TagAttributeName)
	for _, want := range []string{attrUniqueIdentifier, attrState, attrName, attrContactInformation, attrExtractable, "x-owner"} {
		if !contains(names, want) {
			t.Fatalf("Get Attribute List = %v, missing %q", names, want)
		}
	}
	mustKMIPSuccess(t, change(OperationModifyAttribute, kmipIndexedAttribute(attrName, 1, kmipNameValue("db-tde-2027"))), OperationModifyAttribute)
	mustKMIPSuccess(t, change(OperationModifyAttribute, kmipAttribute("x-owner", ttlvText(TagAttributeValue, "platform team"))), OperationModifyAttribute)
	mustKMIPSuccess(t, call(OperationDeleteAttribute, ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, id), ttlvText(TagAttributeName, attrName))), OperationDeleteAttribute)
	got := mustKMIPSuccess(t, call(OperationGetAttributes, kmipGetAttributesPayload(id, attrName, "x-owner")), OperationGetAttributes)
	if values := allTextValues(got, TagNameValue); len(values) != 1 || values[0] != "db-tde-2027" {
		t.Fatalf("names after modify and delete = %v", values)
	}
	if values := allTextValues(got, TagAttributeValue); !contains(values, "platform team") {
		t.Fatalf("x-owner after modify = %v", values)
	}

	for _, refused := range []struct {
		attr   []byte
		reason int32
	}{
		{kmipAttribute(attrState, ttlvEnumeration(TagAttributeValue, stateEnumActive)), resultReasonPermissionDenied},
		{kmipAttribute("y-server", ttlvText(TagAttributeValue, "x")), resultReasonPermissionDenied},
		{kmipAttribute("x-owner", ttlvText(TagAttributeValue, "again")), resultReasonIllegalOperation},
	} {
		if reason := failureReason(t, change(OperationAddAttribute, refused.attr), OperationAddAttribute); reason != refused.reason {
			t.Fatalf("refused Add Attribute = reason %#x, want %#x", reason, refused.reason)
		}
	}
	if reason := failureReason(t, change(OperationModifyAttribute, kmipIndexedAttribute(attrName, 5, kmipNameValue("x"))), OperationModifyAttribute); reason != resultReasonIndexOutOfBounds {
		t.Fatalf("Modify of a missing Name index = reason %#x", reason)
	}

	mustKMIPSuccess(t, change(OperationModifyAttribute, kmipAttribute(attrExtractable, kmipBoolean(TagAttributeValue, false))), OperationModifyAttribute)
	if reason := failureReason(t, call(OperationGet, kmipUniqueIDPayload(id)), OperationGet); reason != resultReasonNotExtractable {
		t.Fatalf("Get of an unextractable key = reason %#x", reason)
	}
	if reason := failureReason(t, change(OperationModifyAttribute, kmipAttribute(attrExtractable, kmipBoolean(TagAttributeValue, true))), OperationModifyAttribute); reason != resultReasonPermissionDenied {
		t.Fatalf("making an unextractable key extractable = reason %#x", reason)
	}
}

// A197: a key pair, its activation and its client attributes survive a
// restart: the private key is replayed from its sealed event and still signs,
// and no event carries it in the clear.
func TestKMIPDurableKeyPairReplays(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	good := []byte("good-client")
	first, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	privateID, publicID, err := first.CreateKeyPair(ctx, good, KeyPairSpec{Algorithm: "ECDSA", Length: 384, PrivateNames: []string{"edge-signer"}})
	if err != nil {
		t.Fatalf("create key pair: %v", err)
	}
	for _, id := range []string{privateID, publicID} {
		if err := first.Activate(ctx, good, id); err != nil {
			t.Fatalf("activate %s: %v", id, err)
		}
	}
	if _, err := first.ChangeAttribute(ctx, good, OperationAddAttribute, privateID,
		requestedAttribute{name: "x-rotation", value: TTLV{Tag: TagAttributeValue, Type: TTLVTextString, Value: []byte("quarterly")}}); err != nil {
		t.Fatalf("add custom attribute: %v", err)
	}
	first.Close()

	second, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	defer second.Close()
	attrs, err := second.GetAttributes(ctx, good, privateID, []string{attrState, attrName, "x-rotation", attrLink, attrNeverExtractable})
	if err != nil || len(attrs) != 5 {
		t.Fatalf("replayed attributes = %d, %v", len(attrs), err)
	}
	data := []byte("edge config")
	signature, err := second.Sign(ctx, good, privateID, SignatureParams{Hash: crypto.SHA384}, data)
	if err != nil {
		t.Fatalf("the replayed private key does not sign: %v", err)
	}
	if ok, err := second.SignatureVerify(ctx, good, publicID, SignatureParams{Hash: crypto.SHA384}, data, signature); err != nil || !ok {
		t.Fatalf("the replayed public key does not verify: %v %v", ok, err)
	}
	if ids, err := second.LocateMatching(ctx, good, LocateFilter{Name: "edge-signer"}); err != nil || len(ids) != 1 || ids[0] != privateID {
		t.Fatalf("Locate by the replayed name = %v %v", ids, err)
	}
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if bytes.Contains(ev.Data, []byte("PRIVATE KEY")) {
			t.Fatalf("event %q carries a private key in the clear", ev.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func kmipCreateKeyPairPayload(algorithm, length int32, name string) []byte {
	common := ttlvStructure(TagCommonTemplateAttribute,
		kmipAttribute(attrCryptographicAlgorithm, ttlvEnumeration(TagAttributeValue, algorithm)),
		kmipAttribute(attrCryptographicLength, ttlvInteger(TagAttributeValue, length)),
	)
	private := []byte(nil)
	public := []byte(nil)
	if name != "" {
		private = ttlvStructure(TagPrivateKeyTemplateAttribute, kmipAttribute(attrName, kmipNameValue(name)))
		public = ttlvStructure(TagPublicKeyTemplateAttribute, kmipAttribute(attrName, kmipNameValue(name)))
	}
	return ttlvStructure(TagRequestPayload, common, private, public)
}

func kmipAttribute(name string, value []byte) []byte {
	return ttlvStructure(TagAttribute, ttlvText(TagAttributeName, name), value)
}

func kmipIndexedAttribute(name string, index int32, value []byte) []byte {
	return ttlvStructure(TagAttribute, ttlvText(TagAttributeName, name), ttlvInteger(TagAttributeIndex, index), value)
}

func kmipNameValue(name string) []byte {
	return ttlvStructure(TagAttributeValue, ttlvText(TagNameValue, name), ttlvEnumeration(TagNameType, nameTypeUninterpretedText))
}

func kmipBoolean(tag uint32, value bool) []byte {
	var buf [8]byte
	if value {
		buf[7] = 1
	}
	return ttlvEncode(tag, TTLVBoolean, buf[:])
}

func kmipGetAttributesPayload(id string, names ...string) []byte {
	children := [][]byte{ttlvText(TagUniqueIdentifier, id)}
	for _, name := range names {
		children = append(children, ttlvText(TagAttributeName, name))
	}
	return ttlvStructure(TagRequestPayload, children...)
}

func kmipSignPayload(id string, params, data []byte) []byte {
	return ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, id), params, ttlvEncode(TagData, TTLVByteString, data))
}

func kmipVerifyPayload(id string, params, data, signature []byte) []byte {
	return ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, id), params,
		ttlvEncode(TagData, TTLVByteString, data), ttlvEncode(TagSignatureData, TTLVByteString, signature))
}

func locateIDs(t *testing.T, frame []byte) []string {
	t.Helper()
	return allTextValues(mustKMIPSuccess(t, frame, OperationLocate), TagUniqueIdentifier)
}

// failureReason returns the Result Reason of a failed batch item for op.
func failureReason(t *testing.T, frame []byte, op Operation) int32 {
	t.Helper()
	if status := responseStatus(t, frame, op); status != resultStatusOperationFailed {
		t.Fatalf("%s succeeded; want a failure", operationName(op))
	}
	root, err := ParseTTLV(frame)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range root.ChildrenByTag(TagBatchItem) {
		reason, err := enumChild(item, TagResultReason)
		if err == nil {
			return reason
		}
	}
	t.Fatalf("%s failure carries no Result Reason", operationName(op))
	return 0
}
