// SPDX-License-Identifier: BUSL-1.1

package cbom

// Licensed posture seam (AN-9). The MPL core classifies classical cryptography
// and names only edition-neutral migration placeholders; it deliberately does
// not name licensed algorithms. A licensed edition may install one resolver
// pair that (a) names the concrete replacement algorithm for a classical
// finding and (b) recognizes licensed algorithm families the core does not
// know. Installation happens exactly once, from the tagged attach seam
// (cmd/trstctl/ee_attach.go, one block per feature), before the server begins
// serving. Nothing else may install, and the core-only build never calls it.

// LicensedTargetResolver names a concrete migration target for a finding.
// ok=false hands the finding back to the core placeholder mapping.
type LicensedTargetResolver func(Finding) (MigrationTarget, bool)

// LicensedKeyClassifier classifies an algorithm label the core does not
// recognize. ok=false hands classification back to the core rules.
type LicensedKeyClassifier func(algorithm string, keyBits int) (Classification, bool)

var (
	licensedTargetFor   LicensedTargetResolver
	licensedClassifyKey LicensedKeyClassifier
)

// InstallLicensedPosture registers the licensed migration-target resolver and
// key classifier. Call it once at process attach time, never per request.
func InstallLicensedPosture(targets LicensedTargetResolver, keys LicensedKeyClassifier) {
	licensedTargetFor = targets
	licensedClassifyKey = keys
}
