// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"strings"

	"trstctl.com/trstctl/internal/cbom"
)

// CBOM licensed posture: the MPL core inventories cryptography but deliberately
// names no licensed algorithm, so its migration targets are edition-neutral
// placeholders and its classifier treats post-quantum families as unknown.
// These two resolvers are installed through cbom.InstallLicensedPosture by the
// tagged attach seam (cmd/trstctl/ee_attach.go attachPQC) when FeaturePQC is
// licensed. They give every classical finding its FIPS-mandated replacement and
// recognize the post-quantum families so a migrated asset counts as
// future-ready instead of "unrecognized".

const (
	standardFIPS203 = "FIPS 203" // ML-KEM, module-lattice key encapsulation
	standardFIPS204 = "FIPS 204" // ML-DSA, module-lattice signatures
	standardFIPS205 = "FIPS 205" // SLH-DSA, stateless hash-based signatures
)

// cbomPQCFamily normalizes an observed algorithm label to a post-quantum
// family and its FIPS standard. Hybrid labels are checked first because they
// embed the component names (Hybrid-ML-DSA-44-ECDSA-P256,
// Hybrid-Ed25519-Dilithium3).
func cbomPQCFamily(algorithm string) (family, standard string, ok bool) {
	u := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case u == "":
		return "", "", false
	case strings.HasPrefix(u, "HYBRID"):
		return "Hybrid", standardFIPS204, true
	case strings.HasPrefix(u, "ML-DSA") || strings.Contains(u, "DILITHIUM"):
		return "ML-DSA", standardFIPS204, true
	case strings.HasPrefix(u, "ML-KEM") || strings.Contains(u, "KYBER"):
		return "ML-KEM", standardFIPS203, true
	case strings.HasPrefix(u, "SLH-DSA") || strings.Contains(u, "SPHINCS"):
		return "SLH-DSA", standardFIPS205, true
	}
	return "", "", false
}

// cbomClassicalFamily mirrors the core's classical family buckets so the
// resolver can name a concrete replacement per family without exporting core
// internals.
func cbomClassicalFamily(algorithm string) string {
	u := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.HasPrefix(u, "RSA"):
		return "RSA"
	case strings.HasPrefix(u, "ECDSA") || strings.HasPrefix(u, "EC") || strings.Contains(u, "P-"):
		return "ECDSA"
	case strings.HasPrefix(u, "ED25519") || strings.HasPrefix(u, "ED448"):
		return "EdDSA"
	case strings.HasPrefix(u, "DSA"):
		return "DSA"
	}
	return ""
}

// CBOMTargetFor names the FIPS-mandated replacement for a CBOM finding.
//
//   - Classical signatures (RSA, ECDSA, EdDSA) migrate to ML-DSA-65 (FIPS 204).
//   - Deprecated DSA migrates to SLH-DSA-SHA2-128s (FIPS 205).
//   - Key establishment (TLS protocol/cipher findings) migrates to ML-KEM-768
//     (FIPS 203).
//   - Pure post-quantum assets are future-ready: no further migration.
//   - Hybrid assets stay migration-required — they are quantum-safe today but
//     still carry a classical component, so the migration endpoint remains the
//     pure post-quantum algorithm.
//
// ok=false hands anything else back to the core's edition-neutral placeholder.
func CBOMTargetFor(f cbom.Finding) (cbom.MigrationTarget, bool) {
	if f.Protocol != "" || f.Cipher != "" {
		return cbom.MigrationTarget{
			Algorithm:  string(MLKEM768),
			Standard:   standardFIPS203,
			Generation: cbom.GenerationMigrationRequired,
		}, true
	}
	if family, standard, ok := cbomPQCFamily(f.Algorithm); ok {
		if family == "Hybrid" {
			return cbom.MigrationTarget{
				Algorithm:  string(MLDSA65),
				Standard:   standardFIPS204,
				Generation: cbom.GenerationMigrationRequired,
			}, true
		}
		return cbom.MigrationTarget{
			Algorithm:  strings.TrimSpace(f.Algorithm),
			Standard:   standard,
			Generation: cbom.GenerationFutureReady,
		}, true
	}
	switch cbomClassicalFamily(f.Algorithm) {
	case "RSA", "ECDSA", "EdDSA":
		return cbom.MigrationTarget{
			Algorithm:  string(MLDSA65),
			Standard:   standardFIPS204,
			Generation: cbom.GenerationMigrationRequired,
		}, true
	case "DSA":
		return cbom.MigrationTarget{
			Algorithm:  string(SLHDSA128s),
			Standard:   standardFIPS205,
			Generation: cbom.GenerationMigrationRequired,
		}, true
	}
	return cbom.MigrationTarget{}, false
}

// CBOMClassifyKey recognizes post-quantum key algorithms the core classifier
// deliberately does not know. Pure ML-DSA / ML-KEM / SLH-DSA keys are strong
// and not quantum-vulnerable; hybrid keys are quantum-safe through their
// post-quantum component and marked transitional. ok=false hands classical and
// unknown labels back to the core rules.
func CBOMClassifyKey(algorithm string, _ int) (cbom.Classification, bool) {
	family, standard, ok := cbomPQCFamily(algorithm)
	if !ok {
		return cbom.Classification{}, false
	}
	c := cbom.Classification{Strength: cbom.StrengthStrong}
	if family == "Hybrid" {
		c.Reasons = []string{"hybrid classical + post-quantum scheme: quantum-safe via its post-quantum component, transitional until pure post-quantum"}
		return c, true
	}
	c.Reasons = []string{family + " is a NIST post-quantum algorithm (" + standard + ")"}
	return c, true
}
