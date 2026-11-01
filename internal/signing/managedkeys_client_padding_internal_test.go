// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// An ECDSA caller's signing options carry no RSA padding, but the request puts
// one on the wire. The client must authorize the wire value, or the signer —
// which rebuilds the intent from the request — refuses the signature.
func TestManagedKeyClientAuthorizesTheWirePadding(t *testing.T) {
	authorizer, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rpc := &capturingManagedKeyRPC{}
	client := &Client{svc: rpc}
	signer, err := client.SignerForManagedKey("tenant-a", "pkcs11", "key-ref", crypto.ECDSAP256, []byte{0x30, 0x00}, PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{7}, 32)
	if _, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatal(err)
	}
	req := rpc.request
	hash, _, err := hashFromProto(req.GetHash())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ManagedKeySignAuthorizationIntent(req.GetTenantId(), req.GetProvider(), req.GetKeyId(), crypto.ECDSAP256,
		req.GetPurpose(), req.GetAuthorizationExpiresUnix(), req.GetAuthorizationNonce(), req.GetDigest(),
		crypto.SignOptions{Hash: hash, RSAPadding: paddingFromProto(req.GetRsaPadding())})
	if err != nil {
		t.Fatal(err)
	}
	if !authorizer.Verify(intent, rpc.tokenAtRPC) {
		t.Fatal("the signer would refuse this ECDSA signature: the authorized padding differs from the request's")
	}
}
