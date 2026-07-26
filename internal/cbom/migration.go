// SPDX-License-Identifier: MPL-2.0

package cbom

// MigrationTarget names the edition-neutral replacement posture a finding should
// move toward. Concrete licensed algorithm choices are supplied by ee/ through
// the InstallLicensedPosture seam.
type MigrationTarget struct {
	Algorithm  string `json:"algorithm"`
	Standard   string `json:"standard"`
	Generation string `json:"generation"`
}

// Generation values a MigrationTarget may carry. GenerationFutureReady marks an
// asset that needs no further migration; ProgressFor counts exactly these into
// PostQuantumReadyAssets. The core mapping never emits it — only an installed
// licensed resolver can recognize a future-ready asset.
const (
	GenerationMigrationRequired = "migration-required"
	GenerationFutureReady       = "future-ready"
)

// MigrationTargetFor maps observed cryptography to a remediation target. An
// installed licensed resolver names concrete algorithms; the MPL core fallback
// deliberately does not, and emits edition-neutral placeholders.
func MigrationTargetFor(f Finding) MigrationTarget {
	if licensedTargetFor != nil {
		if t, ok := licensedTargetFor(f); ok {
			return t
		}
	}
	if f.Protocol != "" || f.Cipher != "" {
		return MigrationTarget{Algorithm: "licensed-key-establishment-transition", Standard: "licensed", Generation: GenerationMigrationRequired}
	}
	switch keyFamily(f.Algorithm) {
	case "RSA", "ECDSA", "EdDSA":
		return MigrationTarget{Algorithm: "licensed-signature-transition", Standard: "licensed", Generation: GenerationMigrationRequired}
	case "DSA":
		return MigrationTarget{Algorithm: "licensed-deprecated-signature-transition", Standard: "licensed", Generation: GenerationMigrationRequired}
	default:
		return MigrationTarget{Algorithm: "licensed-crypto-transition", Standard: "licensed", Generation: GenerationMigrationRequired}
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
		if MigrationTargetFor(f).Generation == GenerationFutureReady {
			p.PostQuantumReadyAssets++
		}
	}
	if p.TotalAssets > 0 {
		p.PercentMigrated = float64(p.PostQuantumReadyAssets) * 100 / float64(p.TotalAssets)
	}
	return p
}
