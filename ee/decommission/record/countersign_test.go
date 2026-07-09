// SPDX-License-Identifier: LicenseRef-trstctl-EE

package record

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCountersign_DistinctAuthorityDoesNotAlterRecord(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	base, err := minter.Mint(ctx, validRequest(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := VerifyRecord(base, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord base: %v", err)
	}
	baseCommitment := append([]byte(nil), base.CommitmentDigest...)
	baseSignature := append([]byte(nil), base.Signature...)

	authority := newCountersignKey(t)
	sink := gate.NewMemorySink()
	withCounter, err := AttachCountersignature(ctx, base, CountersignatureRequest{
		AuthorityID: "regulator-a",
		KeyID:       "regulator-a-key",
		Signer:      authority,
		Sink:        sink,
		Now:         func() time.Time { return time.Unix(1800000800, 0) },
	})
	if err != nil {
		t.Fatalf("AttachCountersignature: %v", err)
	}
	if !bytes.Equal(withCounter.CommitmentDigest, baseCommitment) || !bytes.Equal(withCounter.Signature, baseSignature) {
		t.Fatal("countersignature altered the base commitment digest or minting signature")
	}
	if err := VerifyRecord(withCounter, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord with countersignature: %v", err)
	}
	if err := VerifyRecord(base, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord without countersignature: %v", err)
	}
	if len(withCounter.Countersignatures) != 1 {
		t.Fatalf("countersignatures = %d, want 1", len(withCounter.Countersignatures))
	}
	if err := VerifyCountersignature(withCounter, withCounter.Countersignatures[0], authority.Public()); err != nil {
		t.Fatalf("VerifyCountersignature: %v", err)
	}
	events := sink.Events()
	if got := len(events); got != 1 {
		t.Fatalf("countersignature ledger events = %d, want one", got)
	}
	if events[0].Type != TypeRecordCountersigned {
		t.Fatalf("countersignature ledger event type = %q, want %q", events[0].Type, TypeRecordCountersigned)
	}

	notDistinct := newCountersignKey(t)
	if _, err := AttachCountersignature(ctx, base, CountersignatureRequest{
		AuthorityID: base.SignerID,
		KeyID:       "not-distinct-key",
		Signer:      notDistinct,
		Sink:        gate.NewMemorySink(),
	}); !errors.Is(err, ErrDistinctAuthorityRequired) {
		t.Fatalf("same-authority countersign error = %v, want distinct authority refusal", err)
	}

	secondAuthority := newCountersignKey(t)
	withTwo, err := AttachCountersignature(ctx, withCounter, CountersignatureRequest{
		AuthorityID: "customer-security-office",
		KeyID:       "customer-security-office-key",
		Signer:      secondAuthority,
		Sink:        sink,
		Now:         func() time.Time { return time.Unix(1800000810, 0) },
	})
	if err != nil {
		t.Fatalf("AttachCountersignature second: %v", err)
	}
	if len(withTwo.Countersignatures) != 2 {
		t.Fatalf("countersignatures after second attach = %d, want 2", len(withTwo.Countersignatures))
	}
	if !bytes.Equal(withTwo.CommitmentDigest, baseCommitment) || !bytes.Equal(withTwo.Signature, baseSignature) {
		t.Fatal("second countersignature altered the base commitment digest or minting signature")
	}
	if err := VerifyCountersignatures(withTwo, map[string]crypto.PublicKey{
		"regulator-a-key":              authority.Public(),
		"customer-security-office-key": secondAuthority.Public(),
	}); err != nil {
		t.Fatalf("VerifyCountersignatures: %v", err)
	}
	if err := VerifyRecord(withTwo, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord with two countersignatures: %v", err)
	}
}

func newCountersignKey(t *testing.T) *crypto.LockedSigner {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey countersign: %v", err)
	}
	t.Cleanup(key.Destroy)
	return key
}
