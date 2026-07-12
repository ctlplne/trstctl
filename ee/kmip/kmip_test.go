// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// certAuth authenticates client certs whose bytes contain "good".
type certAuth struct{}

func (certAuth) Authenticate(cert []byte) (string, bool) {
	if len(cert) > 0 && string(cert) == "good-client" {
		return "client-a", true
	}
	return "", false
}

func TestKMIPLifecycleAuthenticated(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", certAuth{}, rec)
	good := []byte("good-client")

	id, err := s.Create(ctx, good, "AES")
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.Get(ctx, good, id)
	if err != nil || len(key) != 32 {
		t.Fatalf("get = %d bytes (err %v), want 32", len(key), err)
	}
	ids, _ := s.Locate(ctx, good, "AES")
	if len(ids) != 1 {
		t.Errorf("locate = %v, want 1", ids)
	}
	v, err := s.ReKey(ctx, good, id)
	if err != nil || v != 2 {
		t.Fatalf("rekey = v%d (err %v)", v, err)
	}
	if err := s.Revoke(ctx, good, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, good, id); err == nil {
		t.Error("got a revoked object")
	}
	if err := s.Destroy(ctx, good, id); err != nil {
		t.Fatal(err)
	}
}

func TestKMIPUnauthenticatedRefused(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", certAuth{}, rec)
	bad := []byte("anonymous")
	if _, err := s.Create(ctx, bad, "AES"); err == nil {
		t.Error("Create allowed without client-cert auth")
	}
	if _, err := s.Get(ctx, bad, "kmip-1"); err == nil {
		t.Error("Get allowed without client-cert auth")
	}
	if rec.Count("kmip.unauthenticated") < 2 {
		t.Error("unauthenticated attempts not audited")
	}
}

func TestKMIPWireLifecycleOperationsServed(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("tenant-a", certAuth{}, rec)
	good := []byte("good-client")

	createResp, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationCreate, kmipCreateAES256Payload()))
	if err != nil {
		t.Fatalf("Create HandleFrame: %v", err)
	}
	createRoot := mustKMIPSuccess(t, createResp, OperationCreate)
	id := mustFindText(t, createRoot, TagUniqueIdentifier)

	locateResp, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationLocate, nil))
	if err != nil {
		t.Fatalf("Locate HandleFrame: %v", err)
	}
	locateRoot := mustKMIPSuccess(t, locateResp, OperationLocate)
	if got := allTextValues(locateRoot, TagUniqueIdentifier); !contains(got, id) {
		t.Fatalf("Locate response ids = %v, want %q", got, id)
	}

	revokeResp, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationRevoke, kmipUniqueIDPayload(id)))
	if err != nil {
		t.Fatalf("Revoke HandleFrame: %v", err)
	}
	mustKMIPSuccess(t, revokeResp, OperationRevoke)

	destroyResp, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationDestroy, kmipUniqueIDPayload(id)))
	if err != nil {
		t.Fatalf("Destroy HandleFrame: %v", err)
	}
	mustKMIPSuccess(t, destroyResp, OperationDestroy)

	if rec.Count("kmip.object.created") != 1 || rec.Count("kmip.object.revoke") != 1 || rec.Count("kmip.object.destroyed") != 1 {
		t.Fatalf("audit counts created=%d revoke=%d destroyed=%d", rec.Count("kmip.object.created"), rec.Count("kmip.object.revoke"), rec.Count("kmip.object.destroyed"))
	}

	getResp, err := s.HandleFrame(ctx, good, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(id)))
	if err != nil {
		t.Fatalf("Get HandleFrame after destroy: %v", err)
	}
	if status := responseStatus(t, getResp, OperationGet); status != resultStatusOperationFailed {
		t.Fatalf("Get after Destroy status = %d, want failure", status)
	}
}

func kmipRequestFrame(op Operation, payload []byte) []byte {
	batchChildren := [][]byte{ttlvEnumeration(TagOperation, int32(op))}
	if len(payload) > 0 {
		batchChildren = append(batchChildren, payload)
	}
	return ttlvStructure(TagRequestMessage,
		ttlvStructure(TagRequestHeader,
			ttlvStructure(TagProtocolVersion,
				ttlvInteger(TagProtocolVersionMajor, 1),
				ttlvInteger(TagProtocolVersionMinor, 4),
			),
			ttlvInteger(TagBatchCount, 1),
		),
		ttlvStructure(TagBatchItem, batchChildren...),
	)
}

func kmipCreateAES256Payload() []byte {
	return ttlvStructure(TagRequestPayload,
		ttlvEnumeration(TagObjectType, objectTypeSymmetricKey),
		ttlvStructure(TagTemplateAttribute,
			ttlvStructure(TagAttribute,
				ttlvText(TagAttributeName, "Cryptographic Algorithm"),
				ttlvEnumeration(TagAttributeValue, cryptographicAlgorithmAES),
			),
			ttlvStructure(TagAttribute,
				ttlvText(TagAttributeName, "Cryptographic Length"),
				ttlvInteger(TagAttributeValue, 256),
			),
		),
	)
}

func kmipUniqueIDPayload(id string) []byte {
	return ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, id))
}

func ttlvText(tag uint32, value string) []byte {
	return ttlvEncode(tag, TTLVTextString, []byte(value))
}

func mustKMIPSuccess(t *testing.T, frame []byte, op Operation) TTLV {
	t.Helper()
	status := responseStatus(t, frame, op)
	if status != resultStatusSuccess {
		t.Fatalf("%s response status = %d, want success", operationName(op), status)
	}
	root, err := ParseTTLV(frame)
	if err != nil {
		t.Fatalf("parse %s response: %v", operationName(op), err)
	}
	return root
}

func responseStatus(t *testing.T, frame []byte, op Operation) int32 {
	t.Helper()
	root, err := ParseTTLV(frame)
	if err != nil {
		t.Fatalf("parse %s response: %v", operationName(op), err)
	}
	for _, item := range root.ChildrenByTag(TagBatchItem) {
		gotOp, _ := enumChild(item, TagOperation)
		if Operation(gotOp) != op {
			continue
		}
		status, err := enumChild(item, TagResultStatus)
		if err != nil {
			t.Fatalf("%s response missing ResultStatus: %v", operationName(op), err)
		}
		return status
	}
	t.Fatalf("response missing batch item for %s", operationName(op))
	return resultStatusOperationFailed
}

func mustFindText(t *testing.T, root TTLV, tag uint32) string {
	t.Helper()
	values := allTextValues(root, tag)
	if len(values) == 0 {
		t.Fatalf("response missing text tag %#06x", tag)
	}
	return values[0]
}

func allTextValues(root TTLV, tag uint32) []string {
	var out []string
	var walk func(TTLV)
	walk = func(node TTLV) {
		if node.Tag == tag && node.Type == TTLVTextString {
			out = append(out, string(node.Value))
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(root)
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func operationName(op Operation) string {
	switch op {
	case OperationCreate:
		return "Create"
	case OperationRegister:
		return "Register"
	case OperationLocate:
		return "Locate"
	case OperationGet:
		return "Get"
	case OperationRevoke:
		return "Revoke"
	case OperationDestroy:
		return "Destroy"
	case OperationQuery:
		return "Query"
	case OperationDiscoverVersions:
		return "DiscoverVersions"
	default:
		return "Operation"
	}
}
