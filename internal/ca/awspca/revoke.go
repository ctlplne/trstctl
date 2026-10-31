// SPDX-License-Identifier: BUSL-1.1

package awspca

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
)

// ErrAlreadyRevoked is AWS Private CA's RequestAlreadyProcessedException for a
// certificate it has already revoked; a retried revocation reads it as done.
var ErrAlreadyRevoked = errors.New("awspca: certificate already revoked")

// RevokeCertificateInput is the RevokeCertificate request.
type RevokeCertificateInput struct {
	CertificateAuthorityArn string
	CertificateSerial       string // colon-separated hex, as AWS prints it
	RevocationReason        string
}

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through AWS Private CA's RevokeCertificate (A164). The serial
// goes in the colon-separated hex AWS prints, the reason in AWS's vocabulary,
// and AWS's answer that the request was already processed counts as done.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial, err := colonSerial(req.Serial)
	if err != nil {
		return err
	}
	err = b.api.RevokeCertificate(ctx, RevokeCertificateInput{
		CertificateAuthorityArn: b.cfg.CertificateAuthorityArn,
		CertificateSerial:       serial,
		RevocationReason:        awsReason(req.ReasonCode),
	})
	if errors.Is(err, ErrAlreadyRevoked) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("awspca: revoke %s: %w", serial, err)
	}
	return nil
}

// awsReason maps an RFC 5280 reason to AWS Private CA's RevocationReason; a
// reason AWS does not take is recorded there as UNSPECIFIED, and trstctl's own
// event keeps the precise one.
func awsReason(code int) string {
	switch code {
	case 1:
		return "KEY_COMPROMISE"
	case 2:
		return "CERTIFICATE_AUTHORITY_COMPROMISE"
	case 3:
		return "AFFILIATION_CHANGED"
	case 4:
		return "SUPERSEDED"
	case 5:
		return "CESSATION_OF_OPERATION"
	case 9:
		return "PRIVILEGE_WITHDRAWN"
	case 10:
		return "A_A_COMPROMISE"
	default:
		return "UNSPECIFIED"
	}
}

// colonSerial formats a hex serial as AWS prints it: lower-case octets joined
// by colons.
func colonSerial(serial string) (string, error) {
	cleaned := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(serial)))
	if cleaned == "" || len(cleaned) > 40 {
		return "", fmt.Errorf("awspca: revocation needs a hex serial number; got %q", serial)
	}
	for _, r := range cleaned {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", fmt.Errorf("awspca: revocation needs a hex serial number; got %q", serial)
		}
	}
	if len(cleaned)%2 == 1 {
		cleaned = "0" + cleaned
	}
	octets := make([]string, 0, len(cleaned)/2)
	for i := 0; i < len(cleaned); i += 2 {
		octets = append(octets, cleaned[i:i+2])
	}
	return strings.Join(octets, ":"), nil
}
