// SPDX-License-Identifier: BUSL-1.1

package server

// ErrEnterpriseSSORequired is shared with both binary attach seams so an
// unavailable implementation refuses startup before reading SSO credentials.
// The typed error preserves the complete operator-facing sentence required by
// the edition contract, including its final period.
var ErrEnterpriseSSORequired error = enterpriseSSORequiredError{}

type enterpriseSSORequiredError struct{}

func (enterpriseSSORequiredError) Error() string {
	return "SAML, LDAP and SCIM login require an Enterprise licence."
}

func requireTenantAuthAttachment(d Deps) error {
	if (d.SAML.Enabled || d.LDAP.Enabled || d.SCIM.Enabled) && d.TenantAuthFactory == nil {
		return ErrEnterpriseSSORequired
	}
	return nil
}
