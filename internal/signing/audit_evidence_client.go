// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// AuditEvidenceSigningKey gives first-party callers the signer's typed artifact
// path. The returned key has no raw digest signer, so it cannot bypass the
// signer's kind and authority admission checks.
func AuditEvidenceSigningKey(client *Client, remote *RemoteSigner) (*jose.SigningKey, error) {
	if client == nil || remote == nil {
		return nil, errors.New("signing: audit evidence signer is unavailable")
	}
	public := remote.Public()
	return jose.NewArtifactSigningKey("audit-export", public, auditEvidenceClient{client: client, public: public})
}

type auditEvidenceClient struct {
	client *Client
	public crypto.PublicKey
}

func (s auditEvidenceClient) SignArtifact(kind string, payload []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := s.client.SignArtifact(ctx, ArtifactSignRequest{
		Kind: kind, TenantID: "deployment", AuthorityID: "audit-evidence",
		KeyID: "audit-export", Payload: payload,
	})
	if err != nil {
		return "", err
	}
	if result.KeyID != "audit-export" || result.Algorithm != s.public.Algorithm || !bytes.Equal(result.PublicKeyDER, s.public.DER) {
		return "", errors.New("signing: audit evidence signer returned mismatched public identity")
	}
	return string(result.Signature), nil
}
