// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// The Workload API has its own tenant-bound CA. Its SPIFFE IDs must never be
// minted by the shared platform issuer, including through the licensed subject
// signer. The signed CSR is inspected before either signer receives it.
func (s *Server) refusePlatformWorkloadCSR(ctx context.Context, der []byte) error {
	info, _, err := inspectSubjectCSR(der, s.licensedCSRParser, s.licensedCSRInspector)
	if err != nil {
		return err
	}
	for _, raw := range info.URIs {
		scheme, _, _ := strings.Cut(raw, ":")
		if strings.EqualFold(scheme, "spiffe") {
			// Single-tenant deployments retain their existing CSR contract. Once a
			// second tenant exists, the shared CA is never an identity authority
			// for workload URIs; use the tenant-specific Workload API CA.
			if s.store == nil {
				return errors.New("server: platform CA cannot authorize a SPIFFE workload identity without tenant state")
			}
			count, err := s.store.TenantCountUpToTwo(ctx)
			if err != nil {
				return err
			}
			if count != 1 {
				return errors.New("server: shared platform CA refuses SPIFFE workload identities; use the tenant SPIFFE issuer")
			}
		}
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
