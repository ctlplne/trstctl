// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reducers

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/internal/connector"
)

// Heterogeneous authority types through one reducer contract (XREC-claim-17).
func TestReducer_VaultKMSSelfShapes(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-a"
	nb := mustTestTime("2026-07-08T12:02:04Z")
	na := mustTestTime("2026-07-08T13:02:04Z")
	issuer := []byte{0x30, 0x03, 0x31, 0x01, 0x61}
	serial := "00:AA:10"
	x509Stable, err := canon.X509StableID(issuer, serial)
	if err != nil {
		t.Fatalf("x509 stable id: %v", err)
	}

	vaultSource := &fakeVaultSource{snapshot: VaultSnapshot{
		Watermark: Watermark{Mode: ModePoll, Position: "vault-index-42", ObservedAt: nb},
		Secrets: []VaultSecretRef{{
			Namespace:                "Prod",
			Path:                     "/TLS/API",
			Status:                   "enabled",
			CreatedAt:                nb,
			ProviderVersionID:        "v42",
			ProviderValueSHA256Hex:   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			ProviderNativeResourceID: "secret/data/tls/api",
		}},
		PKICertificates: []VaultPKICertificate{{
			IssuerNameDER: issuer,
			SerialHex:     serial,
			Algorithm:     "RSA_2048",
			Status:        "valid",
			NotBefore:     nb,
			NotAfter:      na,
			SubjectDN:     " CN=api , O=Example ",
			NativeID:      "pki/cert/AA10",
		}},
		Keys: []VaultKey{{
			LogicalID: "transit/prod/signing",
			Algorithm: "EdDSA",
			Status:    "enabled",
			CreatedAt: nb,
			NativeID:  "transit/keys/prod-signing",
		}},
	}}
	vault := NewVaultReducer(ReducerConfig{AuthorityID: "vault-prod", Scope: "vault-prod"}, vaultSource)
	vaultObs, err := vault.Observe(ctx, tenantID)
	if err != nil {
		t.Fatalf("vault observe: %v", err)
	}
	if got := len(vaultObs.Set.Records); got != 3 {
		t.Fatalf("vault records = %d, want 3", got)
	}
	assertRecord(t, vaultObs.Set, canon.RecordTypeSecretRef, "prod:/TLS/API", canon.NormalizeAlgorithm("unknown"), canon.StatusActive)
	assertRecord(t, vaultObs.Set, canon.RecordTypeX509Certificate, x509Stable, "rsa-2048", canon.StatusActive)
	assertRecord(t, vaultObs.Set, canon.RecordTypeKey, "transit/prod/signing", "ed25519", canon.StatusActive)
	if rec := mustRecordByType(t, vaultObs.Set, canon.RecordTypeX509Certificate); rec.Validity.NotBefore == nil || *rec.Validity.NotBefore != mustUnix("2026-07-08T12:00:00Z") {
		t.Fatalf("vault x509 not_before bucket = %v, want 2026-07-08T12:00:00Z", rec.Validity.NotBefore)
	}

	kmsSource := &fakeKMSSource{snapshot: CloudKMSSnapshot{
		Watermark: Watermark{Mode: ModePoll, Position: "kms-page-token-9", ObservedAt: nb},
		Keys: []CloudKMSKey{{
			KeyID:           "arn:aws:kms:us-east-1:123456789012:key/abcd",
			AlgorithmSpec:   "ECC_NIST_P256",
			Status:          "Enabled",
			CreatedAt:       nb,
			RotationEnabled: true,
			NativeID:        "key/abcd",
		}},
	}}
	kms := NewCloudKMSReducer(ReducerConfig{AuthorityID: "aws-kms-prod", Scope: "aws-kms-prod"}, kmsSource)
	kmsObs, err := kms.Observe(ctx, tenantID)
	if err != nil {
		t.Fatalf("kms observe: %v", err)
	}
	assertRecord(t, kmsObs.Set, canon.RecordTypeKey, "arn:aws:kms:us-east-1:123456789012:key/abcd", "ecdsa-p256", canon.StatusActive)

	selfSource := &fakeSelfSource{snapshot: SelfSnapshot{
		Watermark: Watermark{Mode: ModeSubscription, Position: "projection-checkpoint-77", ObservedAt: nb},
		Workloads: []SelfWorkloadIdentity{{
			SPIFFEID:  "SPIFFE://Example.COM/ns/prod/sa/api",
			Algorithm: "Ed25519",
			Status:    "active",
			NativeID:  "workload/api",
		}},
	}}
	self := NewSelfReducer("trstctl-self", selfSource)
	selfObs, err := self.Observe(ctx, tenantID)
	if err != nil {
		t.Fatalf("self observe: %v", err)
	}
	assertRecord(t, selfObs.Set, canon.RecordTypeWorkloadIdentity, "spiffe://example.com/ns/prod/sa/api", "ed25519", canon.StatusActive)
	if selfSource.tenantID != tenantID {
		t.Fatalf("self projection query tenant = %q, want %q", selfSource.tenantID, tenantID)
	}
}

// Foreign authorities are observed read-only (XREC-claim-8).
func TestConnector_ReadOnlyNoMutation(t *testing.T) {
	ctx := context.Background()
	recorder := &recordingTransport{}
	source := &fakeVaultSource{snapshot: VaultSnapshot{
		Watermark: Watermark{Mode: ModePoll, Position: "idx-1", ObservedAt: mustTestTime("2026-07-08T12:00:00Z")},
		Secrets:   []VaultSecretRef{{Namespace: "prod", Path: "/tls/api", Status: "active"}},
	}}
	reducer := NewVaultReducer(ReducerConfig{
		AuthorityID: "vault-prod",
		Scope:       "vault-prod",
		Transport:   recorder,
	}, source)
	if _, err := reducer.Observe(ctx, "tenant-a"); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if recorder.hasMutation() {
		t.Fatalf("observation issued a mutation: %#v", recorder.calls)
	}
	if !recorder.has(OpList) || !recorder.has(OpDescribe) {
		t.Fatalf("observation calls = %#v, want list and describe", recorder.calls)
	}
}

// Observation outside the granted capability is denied (XREC-claim-8).
func TestConnector_CapabilityGrantDenied(t *testing.T) {
	ctx := context.Background()
	sb := NewObservationSandbox(ReadOnlyObservationGrant("vault-prod"), &recordingTransport{})
	if _, err := sb.List(ctx, "vault-prod/metadata"); err != nil {
		t.Fatalf("allowed list denied: %v", err)
	}
	if _, err := sb.Describe(ctx, "other-vault/metadata"); !errors.Is(err, connector.ErrDenied) {
		t.Fatalf("out-of-scope describe error = %v, want connector.ErrDenied", err)
	}
	if err := sb.Mutate(ctx, "vault-prod/metadata", []byte("nope")); !errors.Is(err, connector.ErrDenied) {
		t.Fatalf("mutation error = %v, want connector.ErrDenied", err)
	}
	if got := sb.Denied(); got != 2 {
		t.Fatalf("denied count = %d, want 2", got)
	}
}

func TestForeignPlane_PollOrSubscriptionWatermark(t *testing.T) {
	ctx := context.Background()
	ts := mustTestTime("2026-07-08T12:00:00Z")
	kms := NewCloudKMSReducer(ReducerConfig{AuthorityID: "aws-kms", Scope: "aws-kms-prod"}, &fakeKMSSource{snapshot: CloudKMSSnapshot{
		Watermark: Watermark{Mode: ModePoll, Position: "poll-snapshot-token-10", ObservedAt: ts},
		Keys:      []CloudKMSKey{{KeyID: "kms/key/one", AlgorithmSpec: "RSA_2048", Status: "enabled"}},
	}})
	pollObs, err := kms.Observe(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("poll observe: %v", err)
	}
	if pollObs.Watermark.Mode != ModePoll || pollObs.Watermark.Position != "poll-snapshot-token-10" {
		t.Fatalf("poll watermark = %#v", pollObs.Watermark)
	}

	self := NewSelfReducer("trstctl-self", &fakeSelfSource{snapshot: SelfSnapshot{
		Watermark: Watermark{Mode: ModeSubscription, Position: "projection-checkpoint-88", ObservedAt: ts},
		Keys:      []SelfKey{{LogicalID: "self/key/one", Algorithm: "Ed25519", Status: "active"}},
	}})
	subObs, err := self.Observe(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("subscription observe: %v", err)
	}
	if subObs.Watermark.Mode != ModeSubscription || subObs.Watermark.Position != "projection-checkpoint-88" {
		t.Fatalf("subscription watermark = %#v", subObs.Watermark)
	}
}

func TestConnector_DiscardsValuesBeforePersist(t *testing.T) {
	ctx := context.Background()
	secretBytes := []byte("secret-value-sentinel: super-secret-password")
	source := &fakeVaultSource{snapshot: VaultSnapshot{
		Watermark: Watermark{Mode: ModePoll, Position: "idx-2", ObservedAt: mustTestTime("2026-07-08T12:00:00Z")},
		Secrets: []VaultSecretRef{{
			Namespace:              "prod",
			Path:                   "/tls/api",
			Status:                 "active",
			Value:                  secretBytes,
			ProviderVersionID:      "version-7",
			ProviderValueSHA256Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}}
	reducer := NewVaultReducer(ReducerConfig{AuthorityID: "vault-prod", Scope: "vault-prod"}, source)
	obs, err := reducer.Observe(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !bytes.Equal(secretBytes, make([]byte, len(secretBytes))) {
		t.Fatalf("secret value buffer was not wiped: %q", secretBytes)
	}
	for _, rec := range obs.Set.Records {
		b, err := rec.CanonicalBytes()
		if err != nil {
			t.Fatalf("canonical bytes: %v", err)
		}
		for _, bad := range [][]byte{
			[]byte("secret-value-sentinel"),
			[]byte("super-secret-password"),
			[]byte("password"),
			[]byte("token_value"),
		} {
			if bytes.Contains(bytes.ToLower(b), bytes.ToLower(bad)) {
				t.Fatalf("secret marker %q leaked into canonical bytes: %s", bad, b)
			}
		}
		if !bytes.Contains(b, []byte(`"provider_version_id":"version-7"`)) {
			t.Fatalf("provider version id missing from canonical bytes: %s", b)
		}
		if !bytes.Contains(b, []byte(`"value_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)) {
			t.Fatalf("provider value hash missing from canonical bytes: %s", b)
		}
	}
}

type fakeVaultSource struct {
	snapshot VaultSnapshot
}

func (f *fakeVaultSource) VaultSnapshot(ctx context.Context, tenantID string, sb *ObservationSandbox) (VaultSnapshot, error) {
	if _, err := sb.List(ctx, "vault-prod/metadata/"+tenantID); err != nil {
		return VaultSnapshot{}, err
	}
	if _, err := sb.Describe(ctx, "vault-prod/data/"+tenantID); err != nil {
		return VaultSnapshot{}, err
	}
	return f.snapshot, nil
}

type fakeKMSSource struct {
	snapshot CloudKMSSnapshot
}

func (f *fakeKMSSource) CloudKMSSnapshot(ctx context.Context, tenantID string, sb *ObservationSandbox) (CloudKMSSnapshot, error) {
	if _, err := sb.List(ctx, "aws-kms-prod/keys/"+tenantID); err != nil {
		return CloudKMSSnapshot{}, err
	}
	return f.snapshot, nil
}

type fakeSelfSource struct {
	snapshot SelfSnapshot
	tenantID string
}

func (f *fakeSelfSource) SelfSnapshot(_ context.Context, tenantID string) (SelfSnapshot, error) {
	f.tenantID = tenantID
	return f.snapshot, nil
}

type recordingTransport struct {
	calls []AuthorityOperation
}

func (r *recordingTransport) DoObservation(_ context.Context, op AuthorityOperation) ([]byte, error) {
	r.calls = append(r.calls, op)
	return nil, nil
}

func (r *recordingTransport) has(kind OperationKind) bool {
	for _, call := range r.calls {
		if call.Kind == kind {
			return true
		}
	}
	return false
}

func (r *recordingTransport) hasMutation() bool {
	return r.has(OpMutate)
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

func mustRecordByType(t *testing.T, set canon.Set, recordType string) canon.CanonicalRecord {
	t.Helper()
	for _, rec := range set.Records {
		if rec.RecordType == recordType {
			return rec
		}
	}
	t.Fatalf("record type %s not found", recordType)
	return canon.CanonicalRecord{}
}

func mustTestTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func mustUnix(s string) int64 { return mustTestTime(s).Unix() }
