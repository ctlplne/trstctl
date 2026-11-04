// SPDX-License-Identifier: BUSL-1.1

package license

// Display names for the edition ledger (A253): the docs render tiers, features
// and rights from these, so a page cannot name an edition's contents
// differently from the table that licenses them.

// TierDisplay is a tier's name as the docs print it.
func TierDisplay(t Tier) string {
	switch t {
	case TierCommunity:
		return "Free"
	case TierEnterprise:
		return "Enterprise"
	case TierProvider:
		return "Provider / MSP"
	}
	return string(t)
}

// Tiers is every tier, Free first.
func Tiers() []Tier { return []Tier{TierCommunity, TierEnterprise, TierProvider} }

var featureDisplay = map[Feature]string{
	FeatureFIPS:            "FIPS artifact posture",
	FeatureHASupport:       "HA support",
	FeatureBYOK:            "BYOK",
	FeatureGovernance:      "governance",
	FeatureEnterpriseSSO:   "tenant SAML/LDAP/SCIM (Enterprise SSO)",
	FeatureAuditCompliance: "audit anchoring, retention and compliance packaging",
	FeatureProviderPlane:   "Provider plane",
	FeatureMetering:        "metering",
	FeatureWhiteLabel:      "white label",
	FeatureSiloedIsolation: "siloed isolation",
}

// FeatureDisplay is a feature's name as the docs print it.
func FeatureDisplay(f Feature) string {
	if name, ok := featureDisplay[f]; ok {
		return name
	}
	return string(f)
}

var rightDisplay = map[Right]string{
	RightSelfHost:       "self-host",
	RightManagedService: "operate as a managed service",
	RightResale:         "resell",
}

// RightDisplay is a use right's name as the docs print it.
func RightDisplay(r Right) string {
	if name, ok := rightDisplay[r]; ok {
		return name
	}
	return string(r)
}

// CoreFamilies are the patent-pending families and post-quantum cryptography:
// core code that attaches in every build (cmd/trstctl/attach_families.go) and
// takes no license gate.
func CoreFamilies() []string {
	return []string{"PCAS", "AGID", "XREC", "VDEC", "PQC"}
}
