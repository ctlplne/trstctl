// SPDX-License-Identifier: BUSL-1.1

package awspcafake

import (
	"context"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Revocations returns each revoked certificate ARN with its AWS reason.
func (a *API) Revocations() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]string, len(a.revoked))
	for arn, reason := range a.revoked {
		out[arn] = reason
	}
	return out
}

// RevokeCertificate implements awspca.API with the service's semantics: the
// serial is colon-separated hex, the reason one of AWS's, and a second
// revocation of a serial is RequestAlreadyProcessedException.
func (a *API) RevokeCertificate(_ context.Context, in awspca.RevokeCertificateInput) error {
	if in.CertificateAuthorityArn != caArn {
		return errors.New("ResourceNotFoundException: certificate authority not found")
	}
	switch in.RevocationReason {
	case "UNSPECIFIED", "KEY_COMPROMISE", "CERTIFICATE_AUTHORITY_COMPROMISE", "AFFILIATION_CHANGED",
		"SUPERSEDED", "CESSATION_OF_OPERATION", "PRIVILEGE_WITHDRAWN", "A_A_COMPROMISE":
	default:
		return errors.New("InvalidArgsException: revocation reason")
	}
	if !strings.Contains(in.CertificateSerial, ":") {
		return errors.New("InvalidArgsException: serial must be colon-separated hex")
	}
	want := strings.TrimLeft(strings.ReplaceAll(in.CertificateSerial, ":", ""), "0")
	a.mu.Lock()
	defer a.mu.Unlock()
	for arn, chain := range a.certs {
		info, err := certinfo.Inspect(chain)
		if err != nil || strings.TrimLeft(strings.ToLower(info.SerialNumber), "0") != want {
			continue
		}
		if _, done := a.revoked[arn]; done {
			return awspca.ErrAlreadyRevoked
		}
		a.revoked[arn] = in.RevocationReason
		return nil
	}
	return errors.New("ResourceNotFoundException: certificate not found")
}
