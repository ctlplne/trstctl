// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// EvidenceSignerHandle is a stable, signer-owned authority for AGID revocation
// evidence. It is separate from audit exports and other evidence classes.
const EvidenceSignerHandle = "agid-revocation-evidence"

// BindEvidenceSigner reopens the same purpose-constrained key after a control
// plane restart. The signer keeps the private key; only its SPKI crosses the RPC.
func BindEvidenceSigner(ctx context.Context, client *signing.Client) (crypto.Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("revoke: isolated evidence signer is unavailable")
	}
	remote, err := client.SignerForHandleWithPurpose(ctx, EvidenceSignerHandle, signing.PurposeAuditEvidence)
	if status.Code(err) == codes.NotFound {
		remote, err = client.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, EvidenceSignerHandle,
			[]signing.KeyPurpose{signing.PurposeAuditEvidence}, signing.PurposeAuditEvidence)
		if status.Code(err) == codes.AlreadyExists {
			remote, err = client.SignerForHandleWithPurpose(ctx, EvidenceSignerHandle, signing.PurposeAuditEvidence)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("revoke: bind evidence signer: %w", err)
	}
	if remote.Algorithm() != crypto.ECDSAP256 || remote.RequiresAuthorization() {
		return nil, fmt.Errorf("revoke: evidence signer has an incompatible key constraint")
	}
	revoked, err := client.KeyRevoked(ctx, EvidenceSignerHandle)
	if err != nil {
		return nil, fmt.Errorf("revoke: read evidence signer revocation: %w", err)
	}
	if revoked {
		return nil, fmt.Errorf("revoke: evidence signer is revoked")
	}
	// GetPublicKey does not expose the allowed-purpose set. Prove this fixed
	// handle cannot sign under a CA purpose before accepting a preexisting key.
	wrongPurpose, err := client.SignerForHandleWithPurpose(ctx, EvidenceSignerHandle, signing.PurposeCASign)
	if err != nil {
		return nil, fmt.Errorf("revoke: inspect evidence signer purpose: %w", err)
	}
	if _, err := crypto.SignMessage(wrongPurpose, []byte("agid-revocation-evidence-purpose-check/v1")); status.Code(err) != codes.FailedPrecondition {
		return nil, fmt.Errorf("revoke: evidence signer is not restricted to its evidence purpose: %v", err)
	}
	return crypto.SignerFromDigestSigner(remote), nil
}
