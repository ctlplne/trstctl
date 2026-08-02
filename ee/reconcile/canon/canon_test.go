// SPDX-License-Identifier: LicenseRef-trstctl-EE

package canon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanon_DeterministicByteIdentical(t *testing.T) {
	obs := []ObservedRecord{
		{
			TenantID:   "tenant-a",
			RecordType: RecordTypeX509Certificate,
			X509:       &X509Identity{IssuerNameDER: []byte{0x30, 0x03, 0x31, 0x01, 0x61}, SerialHex: "00:AA:10"},
			Algorithm:  "RSA_2048",
			Validity: ValidityInput{
				NotBefore: mustTime("2026-07-08T12:02:04Z"),
				NotAfter:  mustTime("2026-08-08T12:02:04Z"),
			},
			Status:     "enabled",
			Provenance: Provenance{AuthorityID: "vault-prod", NativeID: "pki/cert/AA10"},
			Attributes: map[string]Value{
				"subject_dn": DN(" CN=Svc , O=Example "),
				"san_uri":    URI("SPIFFE://Example.COM/ns/prod/../prod/sa/api"),
				"critical":   Bool(true),
			},
		},
		{
			TenantID:   "tenant-a",
			RecordType: RecordTypeWorkloadIdentity,
			Workload:   &WorkloadIdentity{SPIFFEID: "SPIFFE://Example.COM/ns/prod/../prod/sa/api"},
			Algorithm:  "EdDSA",
			Validity: ValidityInput{
				NotBefore: mustTime("2026-07-08T12:00:00Z"),
				NotAfter:  mustTime("2026-07-08T12:04:59Z"),
			},
			Status:     "ACTIVE",
			Provenance: Provenance{AuthorityID: "spire-prod", NativeID: "entry/api"},
			Attributes: map[string]Value{
				"selector_count": Int(3),
				"trust_domain":   String("Example.COM"),
			},
		},
	}

	a := mustReduceBytes(t, obs, SpecVersionV1)
	b := mustReduceBytes(t, obs, SpecVersionV1)
	if !equalByteSlices(a, b) {
		t.Fatalf("same observed state reduced to different bytes:\n%q\n%q", a, b)
	}

	x509Bytes := findRecordBytes(t, a, `"record_type":"x509_certificate"`)
	want := mustReadVector(t, "x509-rsa.canonical.json", x509Bytes)
	if !bytes.Equal(x509Bytes, want) {
		t.Fatalf("x509 golden vector drifted\n got: %s\nwant: %s", x509Bytes, want)
	}
}

func TestCanon_GoldenVectors(t *testing.T) {
	for _, name := range []string{"x509-rsa", "key-ed25519", "secret-ref", "workload-spiffe"} {
		t.Run(name, func(t *testing.T) {
			got := mustSingleBytes(t, mustReadFixture(t, name))
			want := mustReadVector(t, name+".canonical.json", got)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s vector drifted\n got: %s\nwant: %s", name, got, want)
			}
		})
	}
}

// Normalized attributes reduce alias forms to one value (XREC-claim-10).
func TestCanon_AliasFormsReduceEqual(t *testing.T) {
	base := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeKey,
		Key:        &KeyIdentity{LogicalID: "kms/prod/signing"},
		Validity:   ValidityInput{NotBefore: mustTime("2026-07-08T12:00:00Z"), NotAfter: mustTime("2026-07-09T12:00:00Z")},
		Status:     "active",
		Provenance: Provenance{AuthorityID: "aws-kms", NativeID: "key/1234"},
		Attributes: map[string]Value{"purpose": String("signing")},
	}

	rsaA := base
	rsaA.Algorithm = "RSA_2048"
	rsaB := base
	rsaB.Algorithm = "rsaEncryption-2048-OID"
	if a, b := mustSingleBytes(t, rsaA), mustSingleBytes(t, rsaB); !bytes.Equal(a, b) {
		t.Fatalf("RSA aliases changed canonical bytes\n a=%s\n b=%s", a, b)
	}

	ecA := base
	ecA.Algorithm = "ECC_NIST_P256"
	ecB := base
	ecB.Algorithm = "prime256v1"
	if a, b := mustSingleBytes(t, ecA), mustSingleBytes(t, ecB); !bytes.Equal(a, b) {
		t.Fatalf("P-256 aliases changed canonical bytes\n a=%s\n b=%s", a, b)
	}

	unknownA := NormalizeAlgorithm("Vendor Weird Alg")
	unknownB := NormalizeAlgorithm("Vendor Weird Alg")
	if unknownA != unknownB || unknownA[:8] != "unknown-" || len(unknownA) != len("unknown-")+64 {
		t.Fatalf("unknown algorithm normalization unstable or malformed: %q vs %q", unknownA, unknownB)
	}
}

func TestCanon_ValidityBucketing_FloorCeil(t *testing.T) {
	base := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeKey,
		Key:        &KeyIdentity{LogicalID: "kms/prod/signing"},
		Algorithm:  "ed25519",
		Status:     "active",
		Provenance: Provenance{AuthorityID: "kms", NativeID: "key/1"},
	}
	base.Validity = ValidityInput{
		CreatedAt: mustTime("2026-07-08T12:02:04Z"),
		NotBefore: mustTime("2026-07-08T12:02:04Z"),
		NotAfter:  mustTime("2026-07-08T12:02:04Z"),
		DeletedAt: mustTime("2026-07-08T12:02:04Z"),
	}
	got := mustRecord(t, base)
	if got.Validity.CreatedAt == nil || *got.Validity.CreatedAt != mustUnix("2026-07-08T12:00:00Z") {
		t.Fatalf("created_at bucket = %v, want 12:00 floor", got.Validity.CreatedAt)
	}
	if got.Validity.NotBefore == nil || *got.Validity.NotBefore != mustUnix("2026-07-08T12:00:00Z") {
		t.Fatalf("not_before bucket = %v, want 12:00 floor", got.Validity.NotBefore)
	}
	if got.Validity.NotAfter == nil || *got.Validity.NotAfter != mustUnix("2026-07-08T12:05:00Z") {
		t.Fatalf("not_after bucket = %v, want 12:05 ceil", got.Validity.NotAfter)
	}
	if got.Validity.DeletedAt == nil || *got.Validity.DeletedAt != mustUnix("2026-07-08T12:05:00Z") {
		t.Fatalf("deleted_at bucket = %v, want 12:05 ceil", got.Validity.DeletedAt)
	}

	skewA := base
	skewA.Validity = ValidityInput{NotBefore: mustTime("2026-07-08T12:00:01Z"), NotAfter: mustTime("2026-07-08T12:04:59Z")}
	skewB := base
	skewB.Validity = ValidityInput{NotBefore: mustTime("2026-07-08T12:04:59Z"), NotAfter: mustTime("2026-07-08T12:00:01Z")}
	if a, b := mustSingleBytes(t, skewA), mustSingleBytes(t, skewB); !bytes.Equal(a, b) {
		t.Fatalf("sub-granularity skew did not collapse\n a=%s\n b=%s", a, b)
	}

	next := base
	next.Validity = ValidityInput{NotBefore: mustTime("2026-07-08T12:05:00Z"), NotAfter: mustTime("2026-07-08T12:05:00Z")}
	if a, b := mustSingleBytes(t, skewA), mustSingleBytes(t, next); bytes.Equal(a, b) {
		t.Fatalf("at-granularity difference collapsed unexpectedly: %s", a)
	}
}

func TestCanon_TenantScoped(t *testing.T) {
	a := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeSecretRef,
		SecretRef:  &SecretRefIdentity{Namespace: "Prod", Path: "/TLS/API"},
		Algorithm:  "unknown",
		Status:     "active",
		Provenance: Provenance{AuthorityID: "vault", NativeID: "secret/data/tls/api"},
	}
	b := a
	b.TenantID = "tenant-b"

	ba := mustSingleBytes(t, a)
	bb := mustSingleBytes(t, b)
	if bytes.Equal(ba, bb) {
		t.Fatalf("tenant id was not bound into canonical bytes: %s", ba)
	}
	if bytes.Contains(ba, []byte("tenant-b")) || bytes.Contains(bb, []byte("tenant-a")) {
		t.Fatalf("canonical bytes committed another tenant\n a=%s\n b=%s", ba, bb)
	}
	if _, err := ReduceTenant(SpecVersionV1, "tenant-a", []ObservedRecord{a, b}); !errors.Is(err, ErrTenantScope) {
		t.Fatalf("mixed-tenant reduction error = %v, want ErrTenantScope", err)
	}
}

func TestCanon_SpecVersionBoundIntoDigest(t *testing.T) {
	obs := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeKey,
		Key:        &KeyIdentity{LogicalID: "kms/prod/signing"},
		Algorithm:  "ed25519",
		Status:     "active",
		Provenance: Provenance{AuthorityID: "kms", NativeID: "key/1"},
	}
	v1 := mustSet(t, []ObservedRecord{obs}, SpecVersionV1)
	v2 := mustSet(t, []ObservedRecord{obs}, "xrec.canon/v2")
	b1 := mustDigestInputs(t, v1)
	b2 := mustDigestInputs(t, v2)
	if equalByteSlices(b1, b2) {
		t.Fatalf("spec_version change did not change digest input: %s", b1[0])
	}
	if !bytes.Contains(b1[0], []byte(`"spec_version":"xrec.canon/v1"`)) {
		t.Fatalf("spec version missing from digest input: %s", b1[0])
	}
}

// Canonical records carry a record key and no secret material (XREC-claim-10).
func TestNoSecrets_CanonicalRecords(t *testing.T) {
	obs := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeSecretRef,
		SecretRef:  &SecretRefIdentity{Namespace: "prod", Path: "/tls/api"},
		Algorithm:  "unknown",
		Status:     "active",
		Provenance: Provenance{AuthorityID: "vault", NativeID: "secret/data/tls/api"},
		Attributes: map[string]Value{
			"password": String("super-secret-password"),
		},
	}
	if _, err := ReduceTenant(SpecVersionV1, "tenant-a", []ObservedRecord{obs}); !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("secret attribute error = %v, want ErrSecretMaterial", err)
	}
	secretValue := obs
	secretValue.Attributes = map[string]Value{"display_name": String("super-secret-password")}
	if _, err := ReduceTenant(SpecVersionV1, "tenant-a", []ObservedRecord{secretValue}); !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("secret string value error = %v, want ErrSecretMaterial", err)
	}
	secretBytes := obs
	secretBytes.Attributes = map[string]Value{"opaque_metadata": Bytes([]byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"))}
	if _, err := ReduceTenant(SpecVersionV1, "tenant-a", []ObservedRecord{secretBytes}); !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("secret byte value error = %v, want ErrSecretMaterial", err)
	}

	clean := obs
	clean.Attributes = map[string]Value{"provider_version_id": String("v42")}
	for _, b := range mustReduceBytes(t, []ObservedRecord{clean}, SpecVersionV1) {
		assertNoEvidenceSecret(t, b)
	}
}

func TestNoSecrets_DigestsAndWitnesses(t *testing.T) {
	obs := ObservedRecord{
		TenantID:   "tenant-a",
		RecordType: RecordTypeSecretRef,
		SecretRef:  &SecretRefIdentity{Namespace: "prod", Path: "/tls/api"},
		Algorithm:  "unknown",
		Status:     "active",
		Provenance: Provenance{AuthorityID: "vault", NativeID: "secret/data/tls/api"},
		Attributes: map[string]Value{
			"provider_version_id": String("v42"),
			"value_sha256":        Bytes([]byte{0x01, 0x02, 0x03}),
		},
	}
	set := mustSet(t, []ObservedRecord{obs}, SpecVersionV1)
	for _, b := range mustDigestInputs(t, set) {
		assertNoEvidenceSecret(t, b)
	}
}

func mustSet(t *testing.T, obs []ObservedRecord, spec string) Set {
	t.Helper()
	tenantID := "tenant-a"
	if len(obs) > 0 {
		tenantID = obs[0].TenantID
	}
	set, err := ReduceTenant(spec, tenantID, obs)
	if err != nil {
		t.Fatalf("ReduceTenant: %v", err)
	}
	return set
}

func mustRecord(t *testing.T, obs ObservedRecord) CanonicalRecord {
	t.Helper()
	set := mustSet(t, []ObservedRecord{obs}, SpecVersionV1)
	if len(set.Records) != 1 {
		t.Fatalf("records len = %d, want 1", len(set.Records))
	}
	return set.Records[0]
}

func mustSingleBytes(t *testing.T, obs ObservedRecord) []byte {
	t.Helper()
	return mustReduceBytes(t, []ObservedRecord{obs}, SpecVersionV1)[0]
}

func mustReduceBytes(t *testing.T, obs []ObservedRecord, spec string) [][]byte {
	t.Helper()
	return mustDigestInputs(t, mustSet(t, obs, spec))
}

func mustDigestInputs(t *testing.T, set Set) [][]byte {
	t.Helper()
	out, err := set.DigestInputs()
	if err != nil {
		t.Fatalf("DigestInputs: %v", err)
	}
	return out
}

func mustTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func mustUnix(s string) int64 { return mustTime(s).Unix() }

func mustReadVector(t *testing.T, name string, seed []byte) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatalf("read vector %s: %v\nseed vector:\n%s", name, err, seed)
	}
	return bytes.TrimSpace(b)
}

type vectorFixture struct {
	SPDX              string `json:"_spdx"`
	Shape             string `json:"shape"`
	TenantID          string `json:"tenant_id"`
	IssuerNameDERHex  string `json:"issuer_name_der_hex"`
	SerialHex         string `json:"serial_hex"`
	LogicalID         string `json:"logical_id"`
	Namespace         string `json:"namespace"`
	Path              string `json:"path"`
	SPIFFEID          string `json:"spiffe_id"`
	Algorithm         string `json:"algorithm"`
	Status            string `json:"status"`
	AuthorityID       string `json:"authority_id"`
	NativeID          string `json:"native_id"`
	CreatedAt         string `json:"created_at"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	DeletedAt         string `json:"deleted_at"`
	SubjectDN         string `json:"subject_dn"`
	SANURI            string `json:"san_uri"`
	Critical          *bool  `json:"critical"`
	Purpose           string `json:"purpose"`
	ProviderVersionID string `json:"provider_version_id"`
	ValueSHA256Hex    string `json:"value_sha256_hex"`
	SelectorCount     *int64 `json:"selector_count"`
	TrustDomain       string `json:"trust_domain"`
}

func mustReadFixture(t *testing.T, name string) ObservedRecord {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".fixture.json"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var f vectorFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	if f.SPDX != "LicenseRef-trstctl-EE" {
		t.Fatalf("fixture %s SPDX = %q, want LicenseRef-trstctl-EE", name, f.SPDX)
	}
	obs := ObservedRecord{
		TenantID:   f.TenantID,
		RecordType: f.Shape,
		Algorithm:  f.Algorithm,
		Validity: ValidityInput{
			CreatedAt: optionalTime(t, f.CreatedAt),
			NotBefore: optionalTime(t, f.NotBefore),
			NotAfter:  optionalTime(t, f.NotAfter),
			DeletedAt: optionalTime(t, f.DeletedAt),
		},
		Status:     f.Status,
		Provenance: Provenance{AuthorityID: f.AuthorityID, NativeID: f.NativeID},
		Attributes: map[string]Value{},
	}
	switch f.Shape {
	case RecordTypeX509Certificate:
		issuer, err := hex.DecodeString(f.IssuerNameDERHex)
		if err != nil {
			t.Fatalf("fixture %s issuer DER hex: %v", name, err)
		}
		obs.X509 = &X509Identity{IssuerNameDER: issuer, SerialHex: f.SerialHex}
	case RecordTypeKey:
		obs.Key = &KeyIdentity{LogicalID: f.LogicalID}
	case RecordTypeSecretRef:
		obs.SecretRef = &SecretRefIdentity{Namespace: f.Namespace, Path: f.Path}
	case RecordTypeWorkloadIdentity:
		obs.Workload = &WorkloadIdentity{SPIFFEID: f.SPIFFEID}
	default:
		t.Fatalf("fixture %s unsupported shape %q", name, f.Shape)
	}
	if f.SubjectDN != "" {
		obs.Attributes["subject_dn"] = DN(f.SubjectDN)
	}
	if f.SANURI != "" {
		obs.Attributes["san_uri"] = URI(f.SANURI)
	}
	if f.Critical != nil {
		obs.Attributes["critical"] = Bool(*f.Critical)
	}
	if f.Purpose != "" {
		obs.Attributes["purpose"] = String(f.Purpose)
	}
	if f.ProviderVersionID != "" {
		obs.Attributes["provider_version_id"] = String(f.ProviderVersionID)
	}
	if f.ValueSHA256Hex != "" {
		value, err := hex.DecodeString(f.ValueSHA256Hex)
		if err != nil {
			t.Fatalf("fixture %s value_sha256_hex: %v", name, err)
		}
		obs.Attributes["value_sha256"] = Bytes(value)
	}
	if f.SelectorCount != nil {
		obs.Attributes["selector_count"] = Int(*f.SelectorCount)
	}
	if f.TrustDomain != "" {
		obs.Attributes["trust_domain"] = String(f.TrustDomain)
	}
	if len(obs.Attributes) == 0 {
		obs.Attributes = nil
	}
	return obs
}

func optionalTime(t *testing.T, s string) *time.Time {
	t.Helper()
	if s == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse fixture time %q: %v", s, err)
	}
	return &parsed
}

func equalByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func findRecordBytes(t *testing.T, records [][]byte, marker string) []byte {
	t.Helper()
	for _, record := range records {
		if bytes.Contains(record, []byte(marker)) {
			return record
		}
	}
	t.Fatalf("record marker %q not found in %q", marker, records)
	return nil
}

func assertNoEvidenceSecret(t *testing.T, b []byte) {
	t.Helper()
	for _, bad := range [][]byte{
		[]byte("super-secret-password"),
		[]byte("BEGIN PRIVATE KEY"),
		[]byte("private_key"),
		[]byte("password"),
		[]byte("token_value"),
		[]byte("access_token"),
	} {
		if bytes.Contains(bytes.ToLower(b), bytes.ToLower(bad)) {
			t.Fatalf("secret marker %q leaked into evidence bytes: %s", bad, b)
		}
	}
}
