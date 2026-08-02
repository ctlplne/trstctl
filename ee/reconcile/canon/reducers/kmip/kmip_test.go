// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"errors"
	"math"
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
	// KMIP Integer is a big-endian two's-complement 32-bit field. Masking the
	// bytes out directly is bit-identical to reinterpreting through uint32 and
	// keeps negative values intact.
	var buf [4]byte
	buf[0] = byte(value >> 24 & 0xFF)
	buf[1] = byte(value >> 16 & 0xFF)
	buf[2] = byte(value >> 8 & 0xFF)
	buf[3] = byte(value & 0xFF)
	return ttlvEncode(tag, servedkmip.TTLVInteger, buf[:])
}

func ttlvBytes(tag uint32, value []byte) []byte {
	return ttlvEncode(tag, servedkmip.TTLVByteString, value)
}

func ttlvDateTime(tag uint32, value time.Time) []byte {
	// KMIP DateTime is a big-endian two's-complement 64-bit POSIX timestamp.
	secs := value.Unix()
	var buf [8]byte
	buf[0] = byte(secs >> 56 & 0xFF)
	buf[1] = byte(secs >> 48 & 0xFF)
	buf[2] = byte(secs >> 40 & 0xFF)
	buf[3] = byte(secs >> 32 & 0xFF)
	buf[4] = byte(secs >> 24 & 0xFF)
	buf[5] = byte(secs >> 16 & 0xFF)
	buf[6] = byte(secs >> 8 & 0xFF)
	buf[7] = byte(secs & 0xFF)
	return ttlvEncode(tag, servedkmip.TTLVDateTime, buf[:])
}

func ttlvEncode(tag uint32, typ servedkmip.TTLVType, value []byte) []byte {
	n := len(value)
	if n < 0 || n > math.MaxInt32 {
		panic("xrec kmip test: TTLV value length does not fit the 4-byte length field")
	}
	out := make([]byte, 8+n+ttlvPadding(n))
	out[0] = byte(tag >> 16 & 0xFF)
	out[1] = byte(tag >> 8 & 0xFF)
	out[2] = byte(tag & 0xFF)
	out[3] = byte(typ)
	out[4] = byte(n >> 24 & 0xFF)
	out[5] = byte(n >> 16 & 0xFF)
	out[6] = byte(n >> 8 & 0xFF)
	out[7] = byte(n & 0xFF)
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

// TestAsInt32_TwosComplement pins asInt32 to hand-written expected values at
// the sign boundary. The expectations are literals on purpose: the stdlib
// int32(u) conversion is the thing under replacement, so it cannot be the
// oracle.
func TestAsInt32_TwosComplement(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want int32
	}{
		{"zero", 0x00000000, 0},
		{"one", 0x00000001, 1},
		{"max_int32", 0x7FFFFFFF, 2147483647},
		{"min_int32", 0x80000000, -2147483648},
		{"min_int32_plus_one", 0x80000001, -2147483647},
		{"minus_two", 0xFFFFFFFE, -2},
		{"max_uint32_is_minus_one", 0xFFFFFFFF, -1},
		{"rsa_2048", 0x00000800, 2048},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := asInt32(tc.in); got != tc.want {
				t.Fatalf("asInt32(%#08x) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestAsInt64_TwosComplement pins asInt64 the same way asInt32 is pinned.
func TestAsInt64_TwosComplement(t *testing.T) {
	cases := []struct {
		name string
		in   uint64
		want int64
	}{
		{"zero", 0x0000000000000000, 0},
		{"one", 0x0000000000000001, 1},
		{"max_int64", 0x7FFFFFFFFFFFFFFF, 9223372036854775807},
		{"min_int64", 0x8000000000000000, -9223372036854775808},
		{"min_int64_plus_one", 0x8000000000000001, -9223372036854775807},
		{"minus_two", 0xFFFFFFFFFFFFFFFE, -2},
		{"max_uint64_is_minus_one", 0xFFFFFFFFFFFFFFFF, -1},
		{"above_uint32", 0x0000000100000000, 4294967296},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := asInt64(tc.in); got != tc.want {
				t.Fatalf("asInt64(%#016x) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestTTLVEncodeBigEndianBytes pins the masked byte emission in the fixture
// encoders, including negative values, which the previous uint conversion
// path never exercised.
func TestTTLVEncodeBigEndianBytes(t *testing.T) {
	t.Run("integer_negative", func(t *testing.T) {
		got := ttlvInteger(0x420001, -2)
		want := []byte{
			0x42, 0x00, 0x01, byte(servedkmip.TTLVInteger),
			0x00, 0x00, 0x00, 0x04,
			0xFF, 0xFF, 0xFF, 0xFE,
			0x00, 0x00, 0x00, 0x00,
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ttlvInteger(-2) = % x, want % x", got, want)
		}
	})
	t.Run("integer_positive", func(t *testing.T) {
		got := ttlvInteger(0x420001, 2048)
		if !bytes.Equal(got[8:12], []byte{0x00, 0x00, 0x08, 0x00}) {
			t.Fatalf("ttlvInteger(2048) value = % x, want 00 00 08 00", got[8:12])
		}
	})
	t.Run("datetime_pre_epoch", func(t *testing.T) {
		got := ttlvDateTime(0x420002, time.Unix(-2, 0).UTC())
		want := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}
		if !bytes.Equal(got[8:16], want) {
			t.Fatalf("ttlvDateTime(-2) value = % x, want % x", got[8:16], want)
		}
	})
	t.Run("tag_and_length_bytes", func(t *testing.T) {
		got := ttlvEncode(0xABCDEF, servedkmip.TTLVByteString, []byte{0x01, 0x02, 0x03})
		if got[0] != 0xAB || got[1] != 0xCD || got[2] != 0xEF {
			t.Fatalf("tag bytes = % x, want ab cd ef", got[:3])
		}
		if !bytes.Equal(got[4:8], []byte{0x00, 0x00, 0x00, 0x03}) {
			t.Fatalf("length bytes = % x, want 00 00 00 03", got[4:8])
		}
	})
}
