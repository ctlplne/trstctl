// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	servedkmip "trstctl.com/trstctl/ee/kmip"
	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/connector"
)

func TestReducer_KMIPShape(t *testing.T) {
	ctx := context.Background()
	nb := mustTime("2026-07-08T12:02:04Z")
	na := mustTime("2026-07-08T13:02:04Z")
	issuer := []byte{0x30, 0x03, 0x31, 0x01, 0x61}
	serial := "00:AA:10"
	certStable, err := canon.X509StableID(issuer, serial)
	if err != nil {
		t.Fatalf("x509 stable id: %v", err)
	}

	snapshot, err := DecodeSnapshotTTLV(kmipFixtureTTLV(nb, na, issuer, serial))
	if err != nil {
		t.Fatalf("DecodeSnapshotTTLV: %v", err)
	}
	snapshot.Watermark = reducers.Watermark{Mode: reducers.ModePoll, Position: "kmip-batch-17", ObservedAt: nb}
	source := &staticSource{snapshot: snapshot}
	reducer := NewReducer(reducers.ReducerConfig{AuthorityID: "kmip-prod", Scope: "kmip-prod"}, source)
	obs, err := reducer.Observe(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	assertRecord(t, obs.Set, canon.RecordTypeKey, "kmip-key-1", "rsa-2048", canon.StatusActive)
	assertRecord(t, obs.Set, canon.RecordTypeX509Certificate, certStable, "ecdsa-p256", canon.StatusActive)
	assertRecord(t, obs.Set, canon.RecordTypeSecretRef, "kmip:/secrets/opaque-1", canon.NormalizeAlgorithm("unknown"), canon.StatusDisabled)
	if rec := mustRecordByStableID(t, obs.Set, "kmip-key-1"); rec.Validity.CreatedAt == nil || *rec.Validity.CreatedAt != mustUnix("2026-07-08T12:00:00Z") {
		t.Fatalf("created_at bucket = %v, want 2026-07-08T12:00:00Z", rec.Validity.CreatedAt)
	}
	for _, rec := range obs.Set.Records {
		b, err := rec.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		for _, bad := range [][]byte{
			[]byte("KeyMaterial"),
			[]byte("secret-value"),
			[]byte("BEGIN PRIVATE KEY"),
			[]byte("password"),
		} {
			if bytes.Contains(bytes.ToLower(b), bytes.ToLower(bad)) {
				t.Fatalf("KMIP secret marker %q leaked into canonical record: %s", bad, b)
			}
		}
	}
	assertInternalKMIPEmpty(t)
}

func TestConnector_ReadOnlyNoMutation(t *testing.T) {
	ctx := context.Background()
	recorder := &recordingTransport{}
	source := &clientSource{
		client: NewClient("kmip-prod", fakeEndpoint{
			ids: []string{"kmip-key-1"},
			objects: map[string]ManagedObject{
				"kmip-key-1": {
					UniqueIdentifier: "kmip-key-1",
					ObjectType:       ObjectTypePublicKey,
					Algorithm:        "RSA",
					LengthBits:       2048,
					State:            StateActive,
				},
			},
		}),
		watermark: reducers.Watermark{Mode: reducers.ModePoll, Position: "cursor-1", ObservedAt: mustTime("2026-07-08T12:00:00Z")},
	}
	reducer := NewReducer(reducers.ReducerConfig{AuthorityID: "kmip-prod", Scope: "kmip-prod", Transport: recorder}, source)
	if _, err := reducer.Observe(ctx, "tenant-a"); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if recorder.has(reducers.OpMutate) {
		t.Fatalf("KMIP observation issued a mutation: %#v", recorder.calls)
	}
	if !recorder.has(reducers.OpList) || !recorder.has(reducers.OpDescribe) {
		t.Fatalf("KMIP observation calls = %#v, want Locate/list and Get-Attributes/describe", recorder.calls)
	}
}

func TestConnector_CapabilityGrantDenied(t *testing.T) {
	ctx := context.Background()
	sb := reducers.NewObservationSandbox(ReadOnlyKMIPObservationGrant("kmip-prod"), &recordingTransport{})
	client := NewClient("kmip-prod", fakeEndpoint{})
	if _, err := client.Locate(ctx, sb, "tenant-a"); err != nil {
		t.Fatalf("allowed Locate denied: %v", err)
	}
	if _, err := client.GetAttributes(ctx, sb, "kmip-key-1"); err != nil {
		t.Fatalf("allowed Get-Attributes denied: %v", err)
	}
	if _, err := sb.Describe(ctx, "other-kmip/GetAttributes/kmip-key-1"); !errors.Is(err, connector.ErrDenied) {
		t.Fatalf("out-of-scope Get-Attributes error = %v, want connector.ErrDenied", err)
	}
	if err := sb.Mutate(ctx, "kmip-prod/Destroy/kmip-key-1", nil); !errors.Is(err, connector.ErrDenied) {
		t.Fatalf("KMIP mutation error = %v, want connector.ErrDenied", err)
	}
}

func FuzzDecodeSnapshotTTLV(f *testing.F) {
	f.Add(kmipFixtureTTLV(mustTime("2026-07-08T12:00:00Z"), mustTime("2026-07-08T13:00:00Z"), []byte{0x30, 0x00}, "01"))
	f.Add([]byte{})
	f.Add([]byte{0x42, 0x00, 0x7c, byte(servedkmip.TTLVStructure), 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeSnapshotTTLV(data)
	})
}

type staticSource struct {
	snapshot Snapshot
}

func (s *staticSource) KMIPSnapshot(context.Context, string, *reducers.ObservationSandbox) (Snapshot, error) {
	return s.snapshot, nil
}

type clientSource struct {
	client    Client
	watermark reducers.Watermark
}

func (s *clientSource) KMIPSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (Snapshot, error) {
	ids, err := s.client.Locate(ctx, sb, tenantID)
	if err != nil {
		return Snapshot{}, err
	}
	objects := make([]ManagedObject, 0, len(ids))
	for _, id := range ids {
		obj, err := s.client.GetAttributes(ctx, sb, id)
		if err != nil {
			return Snapshot{}, err
		}
		objects = append(objects, obj)
	}
	return Snapshot{Watermark: s.watermark, Objects: objects}, nil
}

type fakeEndpoint struct {
	ids     []string
	objects map[string]ManagedObject
}

func (f fakeEndpoint) Locate(context.Context, string) ([]string, error) {
	return append([]string(nil), f.ids...), nil
}

func (f fakeEndpoint) GetAttributes(_ context.Context, id string) (ManagedObject, error) {
	if f.objects == nil {
		return ManagedObject{UniqueIdentifier: id, ObjectType: ObjectTypePublicKey, Algorithm: "RSA", LengthBits: 2048, State: StateActive}, nil
	}
	return f.objects[id], nil
}

type recordingTransport struct {
	calls []reducers.AuthorityOperation
}

func (r *recordingTransport) DoObservation(_ context.Context, op reducers.AuthorityOperation) ([]byte, error) {
	r.calls = append(r.calls, op)
	return nil, nil
}

func (r *recordingTransport) has(kind reducers.OperationKind) bool {
	for _, call := range r.calls {
		if call.Kind == kind {
			return true
		}
	}
	return false
}

func kmipFixtureTTLV(nb, na time.Time, issuer []byte, serial string) []byte {
	return ttlvStructure(servedkmip.TagResponsePayload,
		kmipObjectTTLV(ObjectTypePublicKey, "kmip-key-1",
			kmipAttrText("Cryptographic Algorithm", "RSA"),
			kmipAttrInt("Cryptographic Length", 2048),
			kmipAttrText("State", "Active"),
			kmipAttrTime("Initial Date", nb),
		),
		kmipObjectTTLV(ObjectTypeCertificate, "kmip-cert-1",
			kmipAttrText("Cryptographic Algorithm", "ECDSA"),
			kmipAttrInt("Cryptographic Length", 256),
			kmipAttrText("State", "Active"),
			kmipAttrBytes("Issuer DER", issuer),
			kmipAttrText("Serial Number", serial),
			kmipAttrText("Subject DN", " CN=api , O=Example "),
			kmipAttrTime("Activation Date", nb),
			kmipAttrTime("Deactivation Date", na),
		),
		kmipObjectTTLV(ObjectTypeSecretData, "/secrets/opaque-1",
			kmipAttrText("State", "Deactivated"),
		),
	)
}

func kmipObjectTTLV(objectType ObjectType, uniqueID string, attrs ...[]byte) []byte {
	children := [][]byte{
		ttlvText(servedkmip.TagUniqueIdentifier, uniqueID),
		ttlvText(servedkmip.TagObjectType, string(objectType)),
	}
	children = append(children, attrs...)
	return ttlvStructure(TagManagedObject, children...)
}

func kmipAttrText(name, value string) []byte {
	return ttlvStructure(servedkmip.TagAttribute, ttlvText(servedkmip.TagAttributeName, name), ttlvText(servedkmip.TagAttributeValue, value))
}

func kmipAttrInt(name string, value int32) []byte {
	return ttlvStructure(servedkmip.TagAttribute, ttlvText(servedkmip.TagAttributeName, name), ttlvInteger(servedkmip.TagAttributeValue, value))
}

func kmipAttrBytes(name string, value []byte) []byte {
	return ttlvStructure(servedkmip.TagAttribute, ttlvText(servedkmip.TagAttributeName, name), ttlvBytes(servedkmip.TagAttributeValue, value))
}

func kmipAttrTime(name string, value time.Time) []byte {
	return ttlvStructure(servedkmip.TagAttribute, ttlvText(servedkmip.TagAttributeName, name), ttlvDateTime(servedkmip.TagAttributeValue, value))
}

func ttlvStructure(tag uint32, children ...[]byte) []byte {
	return ttlvEncode(tag, servedkmip.TTLVStructure, bytes.Join(children, nil))
}

func ttlvText(tag uint32, value string) []byte {
	return ttlvEncode(tag, servedkmip.TTLVTextString, []byte(value))
}

func ttlvInteger(tag uint32, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return ttlvEncode(tag, servedkmip.TTLVInteger, buf[:])
}

func ttlvBytes(tag uint32, value []byte) []byte {
	return ttlvEncode(tag, servedkmip.TTLVByteString, value)
}

func ttlvDateTime(tag uint32, value time.Time) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value.Unix()))
	return ttlvEncode(tag, servedkmip.TTLVDateTime, buf[:])
}

func ttlvEncode(tag uint32, typ servedkmip.TTLVType, value []byte) []byte {
	out := make([]byte, 8+len(value)+ttlvPadding(len(value)))
	out[0] = byte(tag >> 16)
	out[1] = byte(tag >> 8)
	out[2] = byte(tag)
	out[3] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}

func ttlvPadding(length int) int {
	if rem := length % 8; rem != 0 {
		return 8 - rem
	}
	return 0
}

func assertRecord(t *testing.T, set canon.Set, recordType, stableID, algorithm, status string) {
	t.Helper()
	for _, rec := range set.Records {
		if rec.RecordType == recordType && rec.RecordKey.StableID == stableID {
			if rec.Algorithm != algorithm {
				t.Fatalf("%s/%s algorithm = %q, want %q", recordType, stableID, rec.Algorithm, algorithm)
			}
			if rec.Status != status {
				t.Fatalf("%s/%s status = %q, want %q", recordType, stableID, rec.Status, status)
			}
			return
		}
	}
	t.Fatalf("record %s/%s not found in %#v", recordType, stableID, set.Records)
}

func mustRecordByStableID(t *testing.T, set canon.Set, stableID string) canon.CanonicalRecord {
	t.Helper()
	for _, rec := range set.Records {
		if rec.RecordKey.StableID == stableID {
			return rec
		}
	}
	t.Fatalf("stable id %s not found", stableID)
	return canon.CanonicalRecord{}
}

func assertInternalKMIPEmpty(t *testing.T) {
	t.Helper()
	root := filepath.Clean("../../../../../internal/kmip")
	entries, err := os.ReadDir(root)
	if err != nil {
		// B-6a332fa9: an absent directory is the clean-checkout
		// representation of the required empty core KMIP boundary.
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read internal/kmip: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("internal/kmip must stay empty, found %d entries", len(entries))
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func mustUnix(s string) int64 { return mustTime(s).Unix() }
