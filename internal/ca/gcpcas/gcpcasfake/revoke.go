// SPDX-License-Identifier: BUSL-1.1

package gcpcasfake

import (
	"context"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Revocations returns each revoked certificate name with its CAS reason.
func (a *API) Revocations() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]string, len(a.revoked))
	for name, reason := range a.revoked {
		out[name] = reason
	}
	return out
}

// FindCertificateBySerial implements gcpcas.API: the pool's one certificate
// whose hex serial matches.
func (a *API) FindCertificateBySerial(_ context.Context, pool, hexSerial string) (gcpcas.RevocationTarget, error) {
	if pool != caPool {
		return gcpcas.RevocationTarget{}, fmt.Errorf("NOT_FOUND: CA pool %q not found", pool)
	}
	want := strings.TrimLeft(strings.ToLower(hexSerial), "0")
	a.mu.Lock()
	defer a.mu.Unlock()
	for name, leaf := range a.certs {
		info, err := certinfo.Inspect([]byte(leaf))
		if err != nil || strings.TrimLeft(strings.ToLower(info.SerialNumber), "0") != want {
			continue
		}
		_, revoked := a.revoked[name]
		return gcpcas.RevocationTarget{Name: name, Revoked: revoked}, nil
	}
	return gcpcas.RevocationTarget{}, fmt.Errorf("NOT_FOUND: no certificate with serial %s", hexSerial)
}

// RevokeCertificate implements gcpcas.API with CAS's semantics: a request id is
// required, and a second revocation is refused as already revoked.
func (a *API) RevokeCertificate(_ context.Context, name, reason, requestID string) error {
	if requestID == "" {
		return fmt.Errorf("INVALID_ARGUMENT: requestId is required")
	}
	switch reason {
	case "REVOCATION_REASON_UNSPECIFIED", "KEY_COMPROMISE", "CERTIFICATE_AUTHORITY_COMPROMISE", "AFFILIATION_CHANGED",
		"SUPERSEDED", "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "PRIVILEGE_WITHDRAWN", "ATTRIBUTE_AUTHORITY_COMPROMISE":
	default:
		return fmt.Errorf("INVALID_ARGUMENT: reason %q", reason)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.certs[name]; !ok {
		return fmt.Errorf("NOT_FOUND: certificate %q", name)
	}
	if _, done := a.revoked[name]; done {
		return gcpcas.ErrAlreadyRevoked
	}
	a.revoked[name] = reason
	return nil
}
