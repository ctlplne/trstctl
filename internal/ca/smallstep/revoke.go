// SPDX-License-Identifier: BUSL-1.1

package smallstep

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

const revokePath = "/1.0/revoke"

var _ catemplate.RevokingBackend = (*backend)(nil)

// errAlreadyRevoked is step-ca's answer to a serial it has already revoked; a
// retried revocation reads it as done.
var errAlreadyRevoked = errors.New("smallstep: certificate already revoked")

// Revoke revokes through step-ca's /1.0/revoke (A164). step-ca authorizes it
// with a JWK-provisioner token whose subject is the serial in decimal, and
// revokes passively: the serial is recorded and leaves step-ca's CRL and OCSP.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial, err := decimalSerial(req.Serial)
	if err != nil {
		return err
	}
	if err := b.validateEndpoint(); err != nil {
		return err
	}
	ott, err := b.mintRevokeOTT(serial)
	if err != nil {
		return err
	}
	defer secret.Wipe(ott)
	payload := map[string]any{
		"serial":     serial,
		"ott":        secretjson.StringBytes(ott),
		"reasonCode": req.ReasonCode,
		"reason":     reasonText(req.ReasonCode),
		"passive":    true,
	}
	var out struct {
		Status string `json:"status"`
	}
	err = b.post(ctx, b.cfg.BaseURL+revokePath, payload, &out)
	if errors.Is(err, errAlreadyRevoked) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("smallstep: revoke %s: %w", serial, err)
	}
	if out.Status != "ok" {
		return fmt.Errorf("smallstep: revoke %s was not confirmed", serial)
	}
	return nil
}

// decimalSerial turns trstctl's hex serial into the decimal step-ca keys its
// certificate database and revocation tokens by.
func decimalSerial(serial string) (string, error) {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(serial), ":", ""))
	n, ok := new(big.Int).SetString(cleaned, 16)
	if cleaned == "" || !ok || n.Sign() <= 0 {
		return "", fmt.Errorf("smallstep: revocation needs a hex serial number; got %q", serial)
	}
	return n.String(), nil
}

// mintRevokeOTT signs a revocation token for one serial through the jose
// boundary.
func (b *backend) mintRevokeOTT(serial string) ([]byte, error) {
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(nonce)
	now := b.now()
	claims, err := json.Marshal(map[string]any{
		"iss": b.cfg.ProvisionerName,
		"aud": b.cfg.BaseURL + revokePath,
		"sub": serial,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(ottValidity).Unix(),
		"jti": hex.EncodeToString(nonce),
	})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(claims)
	return jose.SignHS256Bytes(b.cfg.ProvisionerKey, claims), nil
}

// reasonText is the RFC 5280 reason name step-ca records beside the code.
func reasonText(code int) string {
	if reason, ok := crypto.RevocationReasonFromCRLCode(code); ok {
		return string(reason)
	}
	return "unspecified"
}
