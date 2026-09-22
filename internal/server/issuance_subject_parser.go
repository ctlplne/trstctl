// SPDX-License-Identifier: BUSL-1.1

package server

import "trstctl.com/trstctl/internal/crypto"

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
