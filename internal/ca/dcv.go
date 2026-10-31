// SPDX-License-Identifier: BUSL-1.1

package ca

import "context"

// TXTPublisher publishes one DNS TXT record for an authority's domain
// validation and returns its retraction (A165). Vendors whose validation is a
// TXT record of their own token at their own name (DigiCert's _dnsauth record,
// Sectigo's DCV host) use it the way ACME issuance uses its dns-01 solver; the
// server's implementation goes through the tenant's DNS-01 provider configs
// under the same consent and CAA checks as upstream ACME validation.
type TXTPublisher interface {
	PublishTXT(ctx context.Context, tenantID, identifier, recordName, value string) (retract func(context.Context) error, err error)
}
