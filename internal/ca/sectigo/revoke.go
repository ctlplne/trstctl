// SPDX-License-Identifier: BUSL-1.1

package sectigo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through SCM's revoke-by-serial call (A164). SCM refuses a
// second revocation of a certificate it already revoked, so a refused call is
// read back by serial before it counts as a failure: a retried revocation of
// a revoked certificate is done, not an error.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial := strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(req.Serial)))
	if !hexSerial(serial) {
		return fmt.Errorf("sectigo: revocation needs a hex serial number; got %q", req.Serial)
	}
	if err := b.validateEndpoint(); err != nil {
		return err
	}
	err := b.postJSON(ctx, b.cfg.BaseURL+apiBase+"/revoke/serial/"+url.PathEscape(serial), map[string]any{
		"reasonCode": sectigoReason(req.ReasonCode),
		"reason":     "Revoked through trstctl",
	}, nil)
	if err == nil {
		return nil
	}
	if revoked, readErr := b.revokedBySerial(ctx, serial); readErr == nil && revoked {
		return nil
	}
	return fmt.Errorf("sectigo: revoke %s: %w", serial, err)
}

// sectigoReason maps an RFC 5280 reason to the codes SCM accepts (0, 1, 3, 4,
// 5); any other reason is recorded at SCM as unspecified, and trstctl's own
// event keeps the precise one.
func sectigoReason(code int) int {
	switch code {
	case 1, 3, 4, 5:
		return code
	default:
		return 0
	}
}

func hexSerial(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// revokedBySerial reads SCM's status for the certificate with this serial.
func (b *backend) revokedBySerial(ctx context.Context, serial string) (bool, error) {
	var found []struct {
		SSLID int `json:"sslId"`
	}
	if err := b.getJSON(ctx, b.cfg.BaseURL+apiBase+"?serialNumber="+url.QueryEscape(serial), &found); err != nil {
		return false, err
	}
	if len(found) != 1 || found[0].SSLID == 0 {
		return false, errors.New("sectigo: the serial does not name exactly one certificate")
	}
	var detail struct {
		Status string `json:"status"`
	}
	if err := b.getJSON(ctx, b.cfg.BaseURL+apiBase+"/"+strconv.Itoa(found[0].SSLID), &detail); err != nil {
		return false, err
	}
	return strings.EqualFold(detail.Status, "Revoked"), nil
}

func (b *backend) getJSON(ctx context.Context, url string, out any) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	b.setAuth(httpReq)
	resp, err := b.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return errors.New("sectigo: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := secret.ReadBounded(resp.Body, maxBody)
	if err != nil {
		return errors.New("sectigo: read response failed")
	}
	defer secret.Wipe(data)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sectigo: api error %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("sectigo: decode response: %w", err)
	}
	return nil
}
