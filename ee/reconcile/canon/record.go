// SPDX-License-Identifier: LicenseRef-trstctl-EE

package canon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	SpecVersionV1 = "xrec.canon/v1"

	RecordTypeX509Certificate  = "x509_certificate"
	RecordTypeKey              = "key"
	RecordTypeSecretRef        = "secret_ref"
	RecordTypeWorkloadIdentity = "workload_identity"

	StatusActive          = "active"
	StatusDisabled        = "disabled"
	StatusRevoked         = "revoked"
	StatusExpired         = "expired"
	StatusPendingDeletion = "pending_deletion"
	StatusUnknown         = "unknown"
)

const defaultBucketSeconds int64 = 300

var (
	ErrTenantScope           = errors.New("canon: observed record outside tenant scope")
	ErrInvalidCanonicalValue = errors.New("canon: invalid canonical value")
	ErrSecretMaterial        = errors.New("canon: secret material is not allowed in canonical evidence")
	ErrDuplicateKey          = errors.New("canon: duplicate canonical record key")
)

// ObservedRecord is the feature-neutral input shape for R-1..R-10 reduction.
// The fields are identifiers and metadata only. Secret material belongs in the
// observed-state substrate and is rejected if it reaches this boundary.
type ObservedRecord struct {
	TenantID   string
	RecordType string
	StableID   string

	X509      *X509Identity
	Key       *KeyIdentity
	SecretRef *SecretRefIdentity
	Workload  *WorkloadIdentity

	Algorithm  string
	Validity   ValidityInput
	Status     string
	Provenance Provenance
	Attributes map[string]Value
}

type X509Identity struct {
	IssuerNameDER []byte
	SerialHex     string
}

type KeyIdentity struct {
	LogicalID string
	SPKI      []byte
}

type SecretRefIdentity struct {
	Namespace string
	Path      string
}

type WorkloadIdentity struct {
	SPIFFEID string
}

type ValidityInput struct {
	CreatedAt *time.Time
	NotBefore *time.Time
	NotAfter  *time.Time
	DeletedAt *time.Time
}

type Validity struct {
	CreatedAt *int64
	NotBefore *int64
	NotAfter  *int64
	DeletedAt *int64
}

type Provenance struct {
	AuthorityID string
	NativeID    string
}

type RecordKey struct {
	TenantID   string
	RecordType string
	StableID   string
}

type CanonicalRecord struct {
	SpecVersion string
	RecordKey   RecordKey
	RecordType  string
	TenantID    string
	Algorithm   string
	Validity    Validity
	Status      string
	Provenance  Provenance
	Attributes  map[string]Value
}

type Set struct {
	SpecVersion string
	TenantID    string
	Records     []CanonicalRecord
}

func ReduceTenant(specVersion, tenantID string, observed []ObservedRecord) (Set, error) {
	if specVersion == "" {
		specVersion = SpecVersionV1
	}
	tenantID = normalizeText(strings.TrimSpace(tenantID))
	if tenantID == "" {
		return Set{}, fmt.Errorf("%w: empty tenant id", ErrInvalidCanonicalValue)
	}

	records := make([]CanonicalRecord, 0, len(observed))
	for _, obs := range observed {
		rec, err := reduceOne(specVersion, tenantID, obs)
		if err != nil {
			return Set{}, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].RecordKey.tuple() < records[j].RecordKey.tuple()
	})
	for i := 1; i < len(records); i++ {
		if records[i-1].RecordKey.tuple() == records[i].RecordKey.tuple() {
			return Set{}, fmt.Errorf("%w: %s", ErrDuplicateKey, records[i].RecordKey.tuple())
		}
	}
	return Set{SpecVersion: specVersion, TenantID: tenantID, Records: records}, nil
}

func reduceOne(specVersion, tenantID string, obs ObservedRecord) (CanonicalRecord, error) {
	obsTenant := normalizeText(strings.TrimSpace(obs.TenantID))
	if obsTenant != tenantID {
		return CanonicalRecord{}, ErrTenantScope
	}
	recordType := normalizeRecordType(obs.RecordType)
	stableID, err := deriveStableID(recordType, obs)
	if err != nil {
		return CanonicalRecord{}, err
	}
	if hasSecretFieldName(obs.Provenance.NativeID) || hasSecretFieldName(obs.Provenance.AuthorityID) {
		return CanonicalRecord{}, ErrSecretMaterial
	}
	if _, err := canonicalizeAttributes(obs.Attributes); err != nil {
		return CanonicalRecord{}, err
	}
	return CanonicalRecord{
		SpecVersion: specVersion,
		RecordKey:   RecordKey{TenantID: tenantID, RecordType: recordType, StableID: stableID},
		RecordType:  recordType,
		TenantID:    tenantID,
		Algorithm:   NormalizeAlgorithm(obs.Algorithm),
		Validity:    bucketValidity(obs.Validity),
		Status:      normalizeStatus(obs.Status),
		Provenance: Provenance{
			AuthorityID: normalizeText(strings.TrimSpace(obs.Provenance.AuthorityID)),
			NativeID:    normalizeText(strings.TrimSpace(obs.Provenance.NativeID)),
		},
		Attributes: copyAttributes(obs.Attributes),
	}, nil
}

func (s Set) DigestInputs() ([][]byte, error) {
	out := make([][]byte, 0, len(s.Records))
	for _, r := range s.Records {
		b, err := r.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (r CanonicalRecord) CanonicalBytes() ([]byte, error) {
	attrs, err := canonicalizeAttributes(r.Attributes)
	if err != nil {
		return nil, err
	}
	obj := jsonObject{
		"algorithm":    jsonString(r.Algorithm),
		"attributes":   attrs,
		"provenance":   r.Provenance.jsonValue(),
		"record_key":   r.RecordKey.jsonValue(),
		"record_type":  jsonString(r.RecordType),
		"spec_version": jsonString(r.SpecVersion),
		"status":       jsonString(r.Status),
		"tenant_id":    jsonString(r.TenantID),
		"validity":     r.Validity.jsonValue(),
	}
	return canonicalBytes(obj)
}

func (p Provenance) jsonValue() jsonObject {
	return jsonObject{
		"authority_id": jsonString(normalizeText(strings.TrimSpace(p.AuthorityID))),
		"native_id":    jsonString(normalizeText(strings.TrimSpace(p.NativeID))),
	}
}

func (k RecordKey) jsonValue() jsonObject {
	return jsonObject{
		"record_type": jsonString(k.RecordType),
		"stable_id":   jsonString(k.StableID),
		"tenant_id":   jsonString(k.TenantID),
	}
}

func (k RecordKey) tuple() string {
	return k.TenantID + "\x00" + k.RecordType + "\x00" + k.StableID
}

func (v Validity) jsonValue() jsonObject {
	obj := jsonObject{}
	if v.CreatedAt != nil {
		obj["created_at"] = jsonInt(*v.CreatedAt)
	}
	if v.DeletedAt != nil {
		obj["deleted_at"] = jsonInt(*v.DeletedAt)
	}
	if v.NotAfter != nil {
		obj["not_after"] = jsonInt(*v.NotAfter)
	}
	if v.NotBefore != nil {
		obj["not_before"] = jsonInt(*v.NotBefore)
	}
	return obj
}

func copyAttributes(in map[string]Value) map[string]Value {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]Value, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeRecordType(s string) string {
	switch normalizeToken(strings.ReplaceAll(s, "-", "_")) {
	case "x509", "x509_cert", "x509_certificate", "certificate":
		return RecordTypeX509Certificate
	case "key", "kms_key", "public_key":
		return RecordTypeKey
	case "secret", "secret_ref", "secret_reference":
		return RecordTypeSecretRef
	case "workload", "workload_identity", "spiffe", "spiffe_id":
		return RecordTypeWorkloadIdentity
	default:
		return normalizeToken(s)
	}
}

func deriveStableID(recordType string, obs ObservedRecord) (string, error) {
	if obs.StableID != "" {
		return normalizeText(strings.TrimSpace(obs.StableID)), nil
	}
	switch recordType {
	case RecordTypeX509Certificate:
		if obs.X509 == nil {
			return "", fmt.Errorf("%w: x509 identity missing", ErrInvalidCanonicalValue)
		}
		return X509StableID(obs.X509.IssuerNameDER, obs.X509.SerialHex)
	case RecordTypeKey:
		if obs.Key == nil {
			return "", fmt.Errorf("%w: key identity missing", ErrInvalidCanonicalValue)
		}
		return KeyStableID(obs.Key.LogicalID, obs.Key.SPKI)
	case RecordTypeSecretRef:
		if obs.SecretRef == nil {
			return "", fmt.Errorf("%w: secret ref identity missing", ErrInvalidCanonicalValue)
		}
		return SecretRefStableID(obs.SecretRef.Namespace, obs.SecretRef.Path), nil
	case RecordTypeWorkloadIdentity:
		if obs.Workload == nil {
			return "", fmt.Errorf("%w: workload identity missing", ErrInvalidCanonicalValue)
		}
		return WorkloadIdentityStableID(obs.Workload.SPIFFEID)
	default:
		return normalizeText(strings.TrimSpace(obs.StableID)), nil
	}
}

func X509StableID(issuerNameDER []byte, serialHex string) (string, error) {
	serial, err := decodeSerialHex(serialHex)
	if err != nil {
		return "", err
	}
	material := make([]byte, 0, len(issuerNameDER)+len(serial))
	material = append(material, issuerNameDER...)
	material = append(material, serial...)
	return crypto.SHA256Hex(material), nil
}

func KeyStableID(logicalID string, subjectPublicKeyInfoDER []byte) (string, error) {
	if id := normalizeText(strings.TrimSpace(logicalID)); id != "" {
		return id, nil
	}
	if len(subjectPublicKeyInfoDER) == 0 {
		return "", fmt.Errorf("%w: key identity requires logical id or SPKI", ErrInvalidCanonicalValue)
	}
	return crypto.SHA256Hex(subjectPublicKeyInfoDER), nil
}

func SecretRefStableID(namespace, p string) string {
	return normalizeSecretRef(namespace, p)
}

func WorkloadIdentityStableID(spiffeID string) (string, error) {
	return normalizeSPIFFEID(spiffeID)
}

func decodeSerialHex(s string) ([]byte, error) {
	clean := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	if clean == "" {
		return nil, fmt.Errorf("%w: empty x509 serial", ErrInvalidCanonicalValue)
	}
	if len(clean)%2 == 1 {
		clean = "0" + clean
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: serial hex: %v", ErrInvalidCanonicalValue, err)
	}
	return b, nil
}

func NormalizeAlgorithm(native string) string {
	raw := normalizeText(strings.TrimSpace(native))
	key := strings.ToLower(raw)
	key = strings.NewReplacer("_", "-", " ", "-", "/", "-", ".", ".").Replace(key)
	key = strings.Trim(key, "-")
	for strings.Contains(key, "--") {
		key = strings.ReplaceAll(key, "--", "-")
	}
	if canonical, ok := algorithmAliases[key]; ok {
		return canonical
	}
	return "unknown-" + crypto.SHA256Hex([]byte(raw))
}

var algorithmAliases = map[string]string{
	"rsa-2048":                      "rsa-2048",
	"rsa2048":                       "rsa-2048",
	"rsaencryption-2048-oid":        "rsa-2048",
	"rsa-encryption-2048-oid":       "rsa-2048",
	"1.2.840.113549.1.1.1-2048":     "rsa-2048",
	"oid-1.2.840.113549.1.1.1-2048": "rsa-2048",

	"ecc-nist-p256": "ecdsa-p256",
	"ec-p256":       "ecdsa-p256",
	"ecdsa-p256":    "ecdsa-p256",
	"secp256r1":     "ecdsa-p256",
	"prime256v1":    "ecdsa-p256",
	"nist-p256":     "ecdsa-p256",

	"ed25519":         "ed25519",
	"eddsa":           "ed25519",
	"jose-ed25519":    "ed25519",
	"cose-ed25519":    "ed25519",
	"crv-ed25519":     "ed25519",
	"1.3.101.112":     "ed25519",
	"oid-1.3.101.112": "ed25519",

	"ml-dsa-44": "ml-dsa-44",
	"mldsa44":   "ml-dsa-44",
	"ml-dsa44":  "ml-dsa-44",
	"ml-dsa-65": "ml-dsa-65",
	"mldsa65":   "ml-dsa-65",
	"ml-dsa65":  "ml-dsa-65",
	"ml-dsa-87": "ml-dsa-87",
	"mldsa87":   "ml-dsa-87",
	"ml-dsa87":  "ml-dsa-87",
}

func bucketValidity(v ValidityInput) Validity {
	var out Validity
	if v.CreatedAt != nil {
		created := floorUnix(v.CreatedAt.Unix(), defaultBucketSeconds)
		out.CreatedAt = &created
	}
	if v.NotBefore != nil {
		nb := floorUnix(v.NotBefore.Unix(), defaultBucketSeconds)
		out.NotBefore = &nb
	}
	if v.NotAfter != nil {
		na := ceilUnix(v.NotAfter.Unix(), defaultBucketSeconds)
		out.NotAfter = &na
	}
	if v.DeletedAt != nil {
		deleted := ceilUnix(v.DeletedAt.Unix(), defaultBucketSeconds)
		out.DeletedAt = &deleted
	}
	return out
}

func floorUnix(ts, granularity int64) int64 {
	return ts - positiveMod(ts, granularity)
}

func ceilUnix(ts, granularity int64) int64 {
	rem := positiveMod(ts, granularity)
	if rem == 0 {
		return ts
	}
	return ts + (granularity - rem)
}

func positiveMod(v, m int64) int64 {
	r := v % m
	if r < 0 {
		return r + m
	}
	return r
}

func normalizeStatus(s string) string {
	switch normalizeToken(strings.ReplaceAll(s, "-", "_")) {
	case "active", "enabled", "valid", "current", "ok":
		return StatusActive
	case "disabled", "inactive", "suspended":
		return StatusDisabled
	case "revoked", "revoke":
		return StatusRevoked
	case "expired":
		return StatusExpired
	case "pending_deletion", "pendingdelete", "deleting", "delete_pending":
		return StatusPendingDeletion
	default:
		return StatusUnknown
	}
}

func hasSecretFieldName(name string) bool {
	n := strings.ToLower(normalizeText(name))
	n = strings.NewReplacer("-", "", "_", "", ".", "", " ", "", "/", "").Replace(n)
	switch {
	case strings.Contains(n, "privatekey"):
		return true
	case strings.Contains(n, "secretvalue"):
		return true
	case strings.Contains(n, "tokenvalue"):
		return true
	case strings.Contains(n, "password") || strings.Contains(n, "passwd"):
		return true
	case strings.Contains(n, "apikey"):
		return true
	case strings.Contains(n, "accesstoken") || strings.Contains(n, "refreshtoken"):
		return true
	case strings.Contains(n, "clientsecret"):
		return true
	default:
		return false
	}
}

func hasSecretValue(value string) bool {
	n := strings.ToLower(normalizeText(value))
	for _, marker := range []string{
		"-----begin private key-----",
		"-----begin rsa private key-----",
		"-----begin ec private key-----",
		"-----begin openssh private key-----",
		"super-secret-password",
		"token-value-sentinel",
		"password-value-sentinel",
		"secret-value-sentinel",
		"private-key-value-sentinel",
	} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

func hasSecretBytes(value []byte) bool {
	return hasSecretValue(string(value))
}
