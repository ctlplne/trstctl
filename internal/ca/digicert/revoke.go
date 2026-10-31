// SPDX-License-Identifier: BUSL-1.1

package digicert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
)

var _ catemplate.RevokingBackend = (*backend)(nil)

type serialOrder struct {
	ID          int    `json:"id"`
	Status      string `json:"status"`
	Certificate struct {
		ID           int    `json:"id"`
		SerialNumber string `json:"serial_number"`
	} `json:"certificate"`
}

// Revoke revokes through CertCentral (A164). It finds the order whose
// certificate has this serial, asks CertCentral to revoke that certificate with
// the reason and no further approval, and counts the revocation done only when
// the order reads back revoked: a request waiting for an approver is not a
// revocation. A retry finds the order already revoked and changes nothing.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial := normalizeSerial(req.Serial)
	if serial == "" {
		return fmt.Errorf("digicert: revocation needs a hex serial number; got %q", req.Serial)
	}
	if err := b.validateEndpoint(); err != nil {
		return err
	}
	order, err := b.orderBySerial(ctx, serial)
	if err != nil {
		return err
	}
	if order.Status == "revoked" {
		return nil
	}
	var requested struct {
		Status string `json:"status"`
	}
	if err := b.do(ctx, http.MethodPut, b.baseURL+apiBase+"/certificate/"+strconv.Itoa(order.Certificate.ID)+"/revoke", map[string]any{
		"reason":        digicertReason(req.ReasonCode),
		"comments":      "Revoked through trstctl",
		"skip_approval": true,
	}, &requested); err != nil {
		return fmt.Errorf("digicert: revoke %s: %w", serial, err)
	}
	var info struct {
		Status string `json:"status"`
	}
	if err := b.do(ctx, http.MethodGet, b.orderURL(strconv.Itoa(order.ID)), nil, &info); err != nil {
		return fmt.Errorf("digicert: read revocation back: %w", err)
	}
	if info.Status != "revoked" {
		return errors.New("digicert: revocation was requested but CertCentral has not revoked the certificate; it may be waiting for approval")
	}
	return nil
}

// orderBySerial finds the one order whose certificate has this serial.
func (b *backend) orderBySerial(ctx context.Context, serial string) (serialOrder, error) {
	var out struct {
		Orders []serialOrder `json:"orders"`
	}
	query := url.Values{"filters[serial_number]": {serial}}.Encode()
	if err := b.do(ctx, http.MethodGet, b.baseURL+apiBase+"/order/certificate?"+query, nil, &out); err != nil {
		return serialOrder{}, fmt.Errorf("digicert: find the order for serial %s: %w", serial, err)
	}
	var match []serialOrder
	for _, o := range out.Orders {
		if normalizeSerial(o.Certificate.SerialNumber) == serial && o.Certificate.ID != 0 {
			match = append(match, o)
		}
	}
	if len(match) != 1 {
		return serialOrder{}, fmt.Errorf("digicert: serial %s does not name exactly one CertCentral certificate", serial)
	}
	return match[0], nil
}

// digicertReason maps an RFC 5280 reason to CertCentral's vocabulary; a reason
// CertCentral does not take is recorded there as unspecified, and trstctl's own
// event keeps the precise one.
func digicertReason(code int) string {
	switch code {
	case 1:
		return "key_compromise"
	case 3:
		return "affiliation_changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation_of_operation"
	default:
		return "unspecified"
	}
}

func normalizeSerial(serial string) string {
	cleaned := strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(serial)))
	if cleaned == "" || len(cleaned) > 64 {
		return ""
	}
	for _, r := range cleaned {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return ""
		}
	}
	return strings.TrimLeft(cleaned, "0")
}
