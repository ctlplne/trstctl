// SPDX-License-Identifier: BUSL-1.1

// CR-012 regression for S4-L3: a signer caller previously could use generic
// SignArtifact to sign a destruction-record commitment for a key that still
// existed. The control plane must only receive a record after the isolated
// signer has destroyed the exact custody handle.
package signing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/decommission/retirementwire"
	vdecsigner "trstctl.com/trstctl/internal/decommission/signerwiring"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestV5L3SignArtifactMintsAVerifyingDestructionRecordForALiveKey(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := vdecsigner.NewRuntime(vdecsigner.Config{SignerID: "trstctl-signer", FloorDir: filepath.Join(dir, "keys"), Wrapper: wrapper})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Destroy)
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(dir, "sign-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	// As cmd/trstctl-signer/attach_families.go:107,118 attaches it: gate AND artifact signer.
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper),
		signing.WithAuthorizer(authz), signing.WithGatedDestruction(runtime), signing.WithArtifactSigner(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	ctx := context.Background()
	dual := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1",
		"trstctl-key-owner-tenant", tenant, "trstctl-key-class", signing.KeyClassTenantCA))
	for _, h := range []string{"issuing-ca", "throwaway-ca"} {
		keyCtx := dual
		if h == "issuing-ca" {
			keyCtx = metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1"))
		}
		if _, err := srv.GenerateKey(keyCtx, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
			RequestedId: h, AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN}}); err != nil {
			t.Fatal(err)
		}
	}

	// 1. A genuine record: a gated destruction of throwaway-ca through the gate.
	segment, head := cr012CompletedDependencyEvidence(t, tenant, "throwaway-authority")
	digest := crypto.SHA256Sum([]byte("completion events"))
	finalization, err := retirementwire.Encode("genuine-command", "ca-signing-key", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request := signing.GatedDestroyRequest{TenantID: tenant, Handle: "throwaway-ca", SubjectRef: "throwaway-authority",
		LedgerPosition: 2, AssertedFinalEpoch: 1, SatisfactionEvidence: segment, AuditChainHead: head, Context: finalization}
	intent, err := signing.GatedDestroyIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authz.Authorize(intent)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{TenantId: tenant, Handle: &signerpb.KeyHandle{Id: "throwaway-ca"},
		SubjectRef: "throwaway-authority", LedgerPosition: 2, AssertedFinalEpoch: 1,
		SatisfactionEvidence: segment, AuditChainHead: head, Context: finalization, Authorization: token})
	if err != nil || !dec.GetApproved() {
		t.Fatalf("precondition: genuine gated destruction = %+v, %v", dec, err)
	}
	genuine, err := record.DecodeRecord(dec.GetEvidence())
	if err != nil {
		t.Fatalf("decode genuine record: %v", err)
	}

	// 2. A "destruction record" for issuing-ca, which is never destroyed: the caller
	// supplies every commitment field and the runtime signs it.
	evidence := record.EvidenceBinding{Kind: gate.TypeCustodyZeroized, Digest: crypto.SHA256Sum([]byte("forged zeroize evidence")),
		AttestationClassID: gate.ClassSoftwareZeroize.ID()}
	mint := record.MintRequest{TenantID: tenant, StableKeyID: "issuing-ca-authority", FinalEpoch: 1,
		CompletionEventsDigest: digest, DestructionEvidence: evidence, AuditChainHead: "00"}
	payload, err := json.Marshal(mint)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	sig, err := srv.SignArtifact(ctx, &signerpb.SignArtifactRequest{Kind: vdecsigner.ArtifactKindDestructionRecord,
		TenantId: tenant, AuthorityId: "vdec", KeyId: "vdec-destruction-record", Payload: payload})
	after := time.Now().Unix()
	if status.Code(err) == codes.FailedPrecondition {
		t.Logf("SignArtifact refused a destruction record for a live key: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("SignArtifact returned %v; want FailedPrecondition", err)
	}
	if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); err != nil {
		t.Fatalf("issuing-ca should still be alive: %v", err)
	}
	trust := crypto.PublicKey{Algorithm: genuine.AttestationAlgorithm, DER: sig.GetPublicKey()}
	for at := before; at <= after; at++ {
		c := record.Commitment{TenantID: mint.TenantID, StableKeyID: mint.StableKeyID, FinalEpoch: 1,
			CompletionEventsDigest: digest, DestructionEvidence: evidence, AuditChainHead: "00", MintedAtUnix: at}
		cd, err := record.CommitmentDigest(c)
		if err != nil {
			t.Fatal(err)
		}
		forged := record.SignedRecord{Version: record.SchemaV1, Type: record.TypeDestructionRecord, Commitment: c,
			CommitmentDigest: cd, SignerID: "trstctl-signer", AttestationAlgorithm: trust.Algorithm,
			AttestationPublicKeyDER: trust.DER, Signature: sig.GetSignature()}
		if record.VerifyRecord(forged, trust) == nil {
			t.Errorf("SignArtifact minted a verifying VDEC destruction record for issuing-ca-authority while the issuing-ca key "+
				"is still alive; its attestation key is the one genuine gated-destruction records carry: %v",
				bytes.Equal(trust.DER, genuine.AttestationPublicKeyDER))
			return
		}
	}
	t.Fatalf("could not reconstruct the signed commitment (minted between %d and %d)", before, after)
}

func cr012CompletedDependencyEvidence(t *testing.T, tenant, subject string) ([]byte, []byte) {
	t.Helper()
	dependent := depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:retired"}
	payloads := []depstate.Payload{
		depstate.DependencyRegisteredV1{TenantID: tenant, KeyID: subject, Dependent: dependent},
		depstate.DependencyReleasedV1{TenantID: tenant, KeyID: subject, Dependent: dependent, Reason: "retired"},
	}
	events := make([]eventspec.Event, 0, len(payloads))
	for i, payload := range payloads {
		event, err := depstate.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}
		event.Sequence = uint64(i + 1)
		events = append(events, event)
	}
	segment, err := gate.EncodeLedgerSegment(1, events)
	if err != nil {
		t.Fatal(err)
	}
	return segment, gate.AuditChainHead(events)
}

func TestCR012GatedDestroyRejectsFabricatedLedgerForAnotherSubject(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := vdecsigner.NewRuntime(vdecsigner.Config{SignerID: "trstctl-signer", FloorDir: filepath.Join(dir, "keys"), Wrapper: wrapper})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Destroy)
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(dir, "sign-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper),
		signing.WithAuthorizer(authz), signing.WithGatedDestruction(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	ctx := context.Background()
	dual := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1"))
	if _, err := srv.GenerateKey(dual, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: "issuing-ca", AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN}}); err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Sum([]byte("fabricated completion events"))
	finalization, err := retirementwire.Encode("fabricated-command", "ca-signing-key", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{
		TenantId: "tenant-a", Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, SubjectRef: "never-registered-subject",
		LedgerPosition: 1, AssertedFinalEpoch: 1, SatisfactionEvidence: []byte(`{"version":1,"events":[]}`),
		AuditChainHead: gate.AuditChainHead(nil), Context: finalization,
	})
	if err == nil && decision.GetApproved() {
		t.Errorf("gate approved an empty caller-made ledger for another subject and destroyed issuing-ca")
	}
	if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); err != nil {
		t.Errorf("gate must leave issuing-ca alive after fabricated evidence: %v", err)
	}
	// A caller can also invent the registration and its release. The signer must
	// authenticate that ledger segment before considering the apparent set empty.
	segment, head := cr012CompletedDependencyEvidence(t, "tenant-a", "never-registered-subject")
	decision, err = srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{
		TenantId: "tenant-a", Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, SubjectRef: "never-registered-subject",
		LedgerPosition: 2, AssertedFinalEpoch: 1, SatisfactionEvidence: segment,
		AuditChainHead: head, Context: finalization,
	})
	if err == nil && decision.GetApproved() {
		t.Errorf("gate approved caller-made registration and release evidence and destroyed issuing-ca")
	}
	if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); err != nil {
		t.Errorf("gate must leave issuing-ca alive after forged nonempty evidence: %v", err)
	}
}

func TestCR012OwnedCARejectsCallerMadeDestructionLedger(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const handle = "ca-hierarchy-cr012-owned"
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := vdecsigner.NewRuntime(vdecsigner.Config{SignerID: "trstctl-signer", FloorDir: filepath.Join(dir, "keys"), Wrapper: wrapper})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Destroy)
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(dir, "sign-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper),
		signing.WithAuthorizer(authz), signing.WithGatedDestruction(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	ctx := context.Background()
	owned := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1",
		"trstctl-key-owner-tenant", tenant, "trstctl-key-class", signing.KeyClassTenantCA))
	if _, err := srv.GenerateKey(owned, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: handle, AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN}}); err != nil {
		t.Fatal(err)
	}
	segment, head := cr012CompletedDependencyEvidence(t, tenant, "invented-authority")
	digest := crypto.SHA256Sum([]byte("invented completion events"))
	finalization, err := retirementwire.Encode("invented-command", "ca-signing-key", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{
		TenantId: tenant, Handle: &signerpb.KeyHandle{Id: handle}, SubjectRef: "invented-authority",
		LedgerPosition: 2, AssertedFinalEpoch: 1, SatisfactionEvidence: segment,
		AuditChainHead: head, Context: finalization,
	})
	if err == nil && decision.GetApproved() {
		t.Error("gate approved caller-made events for a tenant-owned CA and destroyed its handle")
	}
	if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: handle}}); err != nil {
		t.Errorf("tenant-owned CA must remain alive after forged ledger: %v", err)
	}
}

func TestCR012DestructionAuthorizationBindsLedgerSubjectHandleAndContext(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const handle = "ca-hierarchy-cr012-binding"
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := vdecsigner.NewRuntime(vdecsigner.Config{SignerID: "trstctl-signer", FloorDir: filepath.Join(dir, "keys"), Wrapper: wrapper})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Destroy)
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(dir, "sign-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper),
		signing.WithAuthorizer(authz), signing.WithGatedDestruction(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	ctx := context.Background()
	owned := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1",
		"trstctl-key-owner-tenant", tenant, "trstctl-key-class", signing.KeyClassTenantCA))
	if _, err := srv.GenerateKey(owned, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: handle, AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN}}); err != nil {
		t.Fatal(err)
	}
	segment, head := cr012CompletedDependencyEvidence(t, tenant, "real-authority")
	digest := crypto.SHA256Sum([]byte("completion"))
	finalization, err := retirementwire.Encode("real-command", "ca-signing-key", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	base := signing.GatedDestroyRequest{TenantID: tenant, Handle: handle, SubjectRef: "real-authority",
		LedgerPosition: 2, AssertedFinalEpoch: 1, SatisfactionEvidence: segment,
		AuditChainHead: head, Context: finalization}
	intent, err := signing.GatedDestroyIntent(base)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authz.Authorize(intent)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*signing.GatedDestroyRequest){
		"ledger": func(r *signing.GatedDestroyRequest) {
			r.SatisfactionEvidence = append([]byte(nil), r.SatisfactionEvidence...)
			r.SatisfactionEvidence[0] ^= 1
		},
		"subject": func(r *signing.GatedDestroyRequest) { r.SubjectRef = "invented-authority" },
		"handle":  func(r *signing.GatedDestroyRequest) { r.Handle = "another-ca-handle" },
		"context": func(r *signing.GatedDestroyRequest) { r.Context = append([]byte(nil), r.Context...); r.Context[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			request.Authorization = token
			_, err := srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{
				TenantId: request.TenantID, Handle: &signerpb.KeyHandle{Id: request.Handle},
				SubjectRef: request.SubjectRef, AssertedFinalEpoch: request.AssertedFinalEpoch,
				LedgerPosition: request.LedgerPosition, SatisfactionEvidence: request.SatisfactionEvidence,
				AuditChainHead: request.AuditChainHead, Context: request.Context, Authorization: request.Authorization,
			})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("tampered %s was accepted or failed open: %v", name, err)
			}
			if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: handle}}); err != nil {
				t.Fatalf("tenant CA was destroyed after tampered %s: %v", name, err)
			}
		})
	}
	wrongClass := base
	wrongClass.Context, err = retirementwire.Encode("real-command", "platform-signing-key", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	wrongIntent, err := signing.GatedDestroyIntent(wrongClass)
	if err != nil {
		t.Fatal(err)
	}
	wrongToken, err := authz.Authorize(wrongIntent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.GatedDestroy(ctx, &signerpb.GatedDestroyRequest{
		TenantId: tenant, Handle: &signerpb.KeyHandle{Id: handle}, SubjectRef: base.SubjectRef,
		AssertedFinalEpoch: 1, LedgerPosition: 2, SatisfactionEvidence: segment,
		AuditChainHead: head, Context: wrongClass.Context, Authorization: wrongToken,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("valid token for wrong key class passed: %v", err)
	}
	if _, err := srv.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: handle}}); err != nil {
		t.Fatalf("tenant CA was destroyed by wrong key class: %v", err)
	}
}
