// SPDX-License-Identifier: MPL-2.0

package cbom

// MigrationTarget names the edition-neutral replacement posture a finding should
// move toward. Concrete licensed algorithm choices are supplied by ee/.
type MigrationTarget struct {
	Algorithm  string `json:"algorithm"`
	Standard   string `json:"standard"`
	Generation string `json:"generation"`
}

// MigrationTargetFor maps observed classical cryptography to an edition-neutral
// remediation target. The MPL core deliberately does not name licensed algorithms.
func MigrationTargetFor(f Finding) MigrationTarget {
	if f.Protocol != "" || f.Cipher != "" {
		return MigrationTarget{Algorithm: "licensed-key-establishment-transition", Standard: "licensed", Generation: "migration-required"}
	}
	switch keyFamily(f.Algorithm) {
	case "RSA", "ECDSA", "EdDSA":
		return MigrationTarget{Algorithm: "licensed-signature-transition", Standard: "licensed", Generation: "migration-required"}
	case "DSA":
		return MigrationTarget{Algorithm: "licensed-deprecated-signature-transition", Standard: "licensed", Generation: "migration-required"}
	default:
		return MigrationTarget{Algorithm: "licensed-crypto-transition", Standard: "licensed", Generation: "migration-required"}
	}
}

// MigrationProgress summarizes how much of a tenant's observed CBOM is already
// future-ready. It intentionally uses all observed assets as the denominator:
// a classical TLS endpoint and a classical certificate key both count as migration
// work, even when they are not weak by today's classical policy.
type MigrationProgress struct {
	TotalAssets             int     `json:"total_assets"`
	QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
	OutOfPolicyAssets       int     `json:"out_of_policy_assets"`
	PostQuantumReadyAssets  int     `json:"post_quantum_ready_assets"`
	PercentMigrated         float64 `json:"percent_migrated"`
}

// ProgressFor computes migration progress over classified findings.
func ProgressFor(findings []Finding) MigrationProgress {
	var p MigrationProgress
	p.TotalAssets = len(findings)
	for _, f := range findings {
		if f.Class.QuantumVulnerable {
			p.QuantumVulnerableAssets++
		}
		if f.Class.OutOfPolicy {
			p.OutOfPolicyAssets++
		}
		if MigrationTargetFor(f).Generation == "future-ready" {
			p.PostQuantumReadyAssets++
		}
	}
	if p.TotalAssets > 0 {
		p.PercentMigrated = float64(p.PostQuantumReadyAssets) * 100 / float64(p.TotalAssets)
	}
	return p
}
