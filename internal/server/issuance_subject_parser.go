// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

type platformIssuanceTenantKey struct{}

func withPlatformIssuanceTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, platformIssuanceTenantKey{}, tenantID)
}

func platformIssuanceTenant(ctx context.Context) string {
	if command, ok := ctx.Value(leafCommandContextKey{}).(leafCommand); ok {
		return command.tenantID
	}
	if tenantID, ok := ctx.Value(platformIssuanceTenantKey{}).(string); ok {
		return tenantID
	}
	return ""
}

// A signer must not trust tenant-authored profiles for name ownership. The
// operator's namespace grants are checked on every platform-CA CSR, including
// the licensed subject signer, before either receives the request.
func (s *Server) admitPlatformCSR(ctx context.Context, der []byte) error {
	info, _, err := inspectSubjectCSR(der, s.licensedCSRParser, s.licensedCSRInspector)
	if err != nil {
		return err
	}
	if s.store == nil {
		return errors.New("server: platform CA cannot authorize names without tenant state")
	}
	count, err := s.store.TenantCountUpToTwo(ctx)
	if err != nil {
		return err
	}
	if count == 1 && len(s.tenantDNSNamespaces) == 0 {
		return nil // one-tenant evaluation retains its existing CSR contract
	}
	if count == 0 {
		return errors.New("server: platform CA requires a registered tenant")
	}
	for _, raw := range info.URIs {
		scheme, _, _ := strings.Cut(raw, ":")
		if strings.EqualFold(scheme, "spiffe") {
			return errors.New("server: shared platform CA refuses SPIFFE workload identities; use the tenant SPIFFE issuer")
		}
	}
	tenantID := platformIssuanceTenant(ctx)
	if tenantID == "" {
		return errors.New("server: shared platform CA issuance requires a tenant-bound command")
	}
	if len(s.tenantDNSNamespaces[tenantID]) == 0 {
		return fmt.Errorf("server: tenant %s has no operator-owned platform CA DNS namespace", tenantID)
	}
	if info.CommonName == "" && len(info.DNSNames) == 0 {
		return errors.New("server: shared platform CA requires an operator-owned DNS identity")
	}
	if info.CommonName != "" && !s.tenantDNSNamespaces.Allows(tenantID, info.CommonName) {
		return fmt.Errorf("server: platform CA common name %q is outside tenant %s's DNS namespace", info.CommonName, tenantID)
	}
	for _, name := range info.DNSNames {
		if !s.tenantDNSNamespaces.Allows(tenantID, name) {
			return fmt.Errorf("server: platform CA DNS name %q is outside tenant %s's DNS namespace", name, tenantID)
		}
	}
	if len(info.IPAddresses)+len(info.EmailAddresses)+len(info.SmtpUTF8Mailboxes)+len(info.URIs) > 0 {
		return errors.New("server: shared platform CA has no operator-owned IP, email, or URI namespace for this tenant")
	}
	return nil
}

// inspectSubjectCSR verifies possession before returning any attributes used by
// endpoint admission. Classical requests may also carry a hybrid proof: a valid
// classical signature must not conceal an invalid post-quantum proof extension.
// Missing runtime support refuses a pure request rather than replacing its key.
func inspectSubjectCSR(der []byte, parser LicensedCSRParser, inspector LicensedCSRInspector) (crypto.CSRInfo, bool, error) {
	info, coreErr := crypto.InspectCSR(der)
	if coreErr == nil {
		if inspector != nil {
			pqc, err := inspector(der, info)
			if err != nil {
				return crypto.CSRInfo{}, false, err
			}
			return info, pqc, nil
		}
		return info, false, nil
	}
	if parser != nil {
		info, recognized, err := parser(der)
		if err != nil {
			return crypto.CSRInfo{}, recognized, err
		}
		if recognized {
			return info, true, nil
		}
	}
	return crypto.CSRInfo{}, false, coreErr
}

func (d *issuanceDispatcher) inspectSubjectCSR(der []byte) (crypto.CSRInfo, error) {
	info, _, err := inspectSubjectCSR(der, d.parseSubjectCSR, d.inspectHybridSubjectCSR)
	return info, err
}
