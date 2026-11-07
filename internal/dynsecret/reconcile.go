// SPDX-License-Identifier: BUSL-1.1
package dynsecret

// ADReconcilePrincipal identifies one operator-designated directory writer.
// It intentionally carries no credential or reference that a host can redeem.
type ADReconcilePrincipal struct {
	DN   string `json:"dn"`
	SID  string `json:"sid"`
	GUID string `json:"guid"`
}

// StaticReconciliationProvider selects a separate, unregistered, role-scoped
// provider. Only an approved coordinated reconciliation may invoke it; selection
// performs no native I/O and never modifies the registered ordinary provider.
type StaticReconciliationProvider interface {
	StaticReconciliation(role string) (Provider, ADReconcilePrincipal, error)
}

// ADReconcileAuthority is an internal directory-backend grant. The ordinary
// writer's native identity is read only to rule out principal aliasing.
type ADReconcileAuthority struct {
	Principal      ADReconcilePrincipal
	RotationBindDN string
}
