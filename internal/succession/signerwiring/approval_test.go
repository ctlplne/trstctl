// SPDX-License-Identifier: BUSL-1.1

package signerwiring_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession/minter"
)

func approvalAuthority(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func approveMint(t *testing.T, authority crypto.Signer, req signing.MintRequest, nonce string) []byte {
	t.Helper()
	payload, err := json.Marshal(minter.AuthorizationToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID,
		PredecessorCustody:       "signer",
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch,
		TargetAlgorithm:          req.TargetAlgorithm, ParamsDigest: minter.RequestParamsDigest(req), Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
