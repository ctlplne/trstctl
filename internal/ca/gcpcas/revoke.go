// SPDX-License-Identifier: BUSL-1.1

package gcpcas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/secrettext"
)

// ErrAlreadyRevoked is CAS's answer for a certificate it has already revoked;
// a retried revocation reads it as done.
var ErrAlreadyRevoked = errors.New("gcpcas: certificate already revoked")

// RevocationTarget is one CAS certificate found by serial, and whether CAS has
// already revoked it.
type RevocationTarget struct {
	Name    string
	Revoked bool
}

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through CAS (A164): it finds the pool's certificate with this
// serial, and revokes it by resource name with the reason unless CAS already
// has.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(req.Serial)))
	if serial == "" || len(serial) > 40 || strings.Trim(serial, "0123456789abcdef") != "" {
		return fmt.Errorf("gcpcas: revocation needs a hex serial number; got %q", req.Serial)
	}
	target, err := b.api.FindCertificateBySerial(ctx, b.cfg.CaPool, serial)
	if err != nil {
		return fmt.Errorf("gcpcas: find serial %s: %w", serial, err)
	}
	if target.Revoked {
		return nil
	}
	err = b.api.RevokeCertificate(ctx, target.Name, casReason(req.ReasonCode), uuid.NewString())
	if errors.Is(err, ErrAlreadyRevoked) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("gcpcas: revoke %s: %w", serial, err)
	}
	return nil
}

// casReason maps an RFC 5280 reason to CAS's RevocationReason; a reason CAS
// does not take is recorded there as unspecified, and trstctl's own event keeps
// the precise one.
func casReason(code int) string {
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
	case 6:
		return "CERTIFICATE_HOLD"
	case 9:
		return "PRIVILEGE_WITHDRAWN"
	case 10:
		return "ATTRIBUTE_AUTHORITY_COMPROMISE"
	default:
		return "REVOCATION_REASON_UNSPECIFIED"
	}
}

// FindCertificateBySerial lists the pool's certificates filtered to one hex
// serial (caPools.certificates.list).
func (a *HTTPAPI) FindCertificateBySerial(ctx context.Context, caPool, hexSerial string) (RevocationTarget, error) {
	parent := strings.Trim(strings.TrimSpace(caPool), "/")
	if parent == "" {
		return RevocationTarget{}, errors.New("gcpcas: CA pool parent is required")
	}
	query := url.Values{}
	query.Set("filter", `certificate_description.subject_description.hex_serial_number = "`+hexSerial+`"`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/v1/"+parent+"/certificates?"+query.Encode(), nil)
	if err != nil {
		return RevocationTarget{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", a.token))
	var out struct {
		Certificates []struct {
			Name              string `json:"name"`
			RevocationDetails *struct {
				RevocationState string `json:"revocationState"`
			} `json:"revocationDetails"`
		} `json:"certificates"`
	}
	if err := cloudhttp.JSON(a.doer, req, &out, cloudhttp.WithTimeout(a.timeout)); err != nil {
		return RevocationTarget{}, casError("list certificates", err)
	}
	if len(out.Certificates) != 1 || out.Certificates[0].Name == "" {
		return RevocationTarget{}, errors.New("gcpcas: the serial does not name exactly one certificate in the pool")
	}
	return RevocationTarget{Name: out.Certificates[0].Name, Revoked: out.Certificates[0].RevocationDetails != nil}, nil
}

// RevokeCertificate revokes one certificate by resource name
// (caPools.certificates.revoke).
func (a *HTTPAPI) RevokeCertificate(ctx context.Context, name, reason, requestID string) error {
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" {
		return errors.New("gcpcas: certificate name is required")
	}
	body, err := json.Marshal(map[string]string{"reason": reason, "requestId": requestID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/v1/"+name+":revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", a.token))
	req.Header.Set("Content-Type", "application/json")
	var out json.RawMessage
	err = cloudhttp.JSON(a.doer, req, &out, cloudhttp.WithTimeout(a.timeout), cloudhttp.WithStatusMapper(func(_ int, body []byte) error {
		if bytes.Contains(bytes.ToLower(body), []byte("already revoked")) {
			return ErrAlreadyRevoked
		}
		return nil
	}))
	if errors.Is(err, ErrAlreadyRevoked) {
		return ErrAlreadyRevoked
	}
	if err != nil {
		return casError("revoke certificate", err)
	}
	return nil
}

func casError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var statusErr *cloudhttp.StatusError
	if errors.As(err, &statusErr) {
		return fmt.Errorf("gcpcas: %s: status %d", operation, statusErr.StatusCode)
	}
	return fmt.Errorf("gcpcas: %s request failed", operation)
}
