// Package risk computes a composite, numerical risk score per credential — the
// single answer to "what should I rotate first" (F19). The score combines six
// factors, each normalized to [0,1] and rising with risk: age (how far through
// its validity window the credential is), exposure (how many resources it
// reaches in the credential graph, F21), privilege (what it grants access to),
// rotation history (staleness, or never rotated), owner activity (orphaned
// credentials are riskier), and inferred sensitivity. The factors are weighted
// into a 0..100 composite; each factor is independently testable.
package risk

import "time"

// PrivilegeClass ranks what a credential grants access to.
type PrivilegeClass int

const (
	PrivilegeLow      PrivilegeClass = iota // a single low-value endpoint
	PrivilegeStandard                       // ordinary service access
	PrivilegeHigh                           // broad or sensitive access
	PrivilegeCritical                       // a CA or admin-equivalent authority
)

// Sensitivity ranks the inferred sensitivity of what a credential protects.
type Sensitivity int

const (
	SensitivityLow Sensitivity = iota
	SensitivityMedium
	SensitivityHigh
)

const (
	// exposureSaturation is the half-saturation constant of the exposure curve:
	// the factor reaches 0.5 at this many reachable resources and asymptotes to
	// 1, so additional reach matters most for low-exposure credentials.
	exposureSaturation = 8.0
	// rotationHorizon is the staleness window: a credential not rotated within it
	// scores the maximum rotation risk.
	rotationHorizon = 365 * 24 * time.Hour
)

// Signals are the per-credential inputs to the score.
type Signals struct {
	Now         time.Time
	NotBefore   time.Time // issuance time
	NotAfter    time.Time // expiry
	Exposure    int       // resources reachable in the graph (F21)
	Privilege   PrivilegeClass
	LastRotated time.Time // zero == never rotated
	OwnerActive bool      // the credential has a present, active owner
	Sensitivity Sensitivity
}

// Components is each factor's contribution, normalized to [0,1].
type Components struct {
	Age         float64 `json:"age"`
	Exposure    float64 `json:"exposure"`
	Privilege   float64 `json:"privilege"`
	Rotation    float64 `json:"rotation"`
	Owner       float64 `json:"owner"`
	Sensitivity float64 `json:"sensitivity"`
}

// Weights set each factor's share of the composite. The score is normalized by
// their sum, so weights are relative.
type Weights struct {
	Age         float64
	Exposure    float64
	Privilege   float64
	Rotation    float64
	Owner       float64
	Sensitivity float64
}

// DefaultWeights favors exposure and privilege — the blast-radius signals — with
// age, rotation, and sensitivity moderate and owner activity a lighter nudge.
func DefaultWeights() Weights {
	return Weights{Age: 0.15, Exposure: 0.25, Privilege: 0.20, Rotation: 0.15, Owner: 0.10, Sensitivity: 0.15}
}

// Score is the composite risk score (0..100, higher = rotate sooner) and its
// per-factor breakdown.
type Score struct {
	Total      float64    `json:"total"`
	Components Components `json:"components"`
}

// Compute scores a credential with the default weights.
func Compute(s Signals) Score { return ComputeWith(s, DefaultWeights()) }

// ComputeWith scores a credential with explicit weights.
func ComputeWith(s Signals, w Weights) Score {
	c := Components{
		Age:         ageFactor(s),
		Exposure:    exposureFactor(s),
		Privilege:   privilegeFactor(s),
		Rotation:    rotationFactor(s),
		Owner:       ownerFactor(s),
		Sensitivity: sensitivityFactor(s),
	}
	wsum := w.Age + w.Exposure + w.Privilege + w.Rotation + w.Owner + w.Sensitivity
	total := 0.0
	if wsum > 0 {
		weighted := w.Age*c.Age + w.Exposure*c.Exposure + w.Privilege*c.Privilege +
			w.Rotation*c.Rotation + w.Owner*c.Owner + w.Sensitivity*c.Sensitivity
		total = 100 * weighted / wsum
	}
	return Score{Total: total, Components: c}
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// ageFactor is the fraction of the validity window already elapsed: a credential
// near expiry is riskier than a fresh one. A degenerate window scores maximal.
func ageFactor(s Signals) float64 {
	life := s.NotAfter.Sub(s.NotBefore)
	if life <= 0 {
		return 1
	}
	return clamp01(s.Now.Sub(s.NotBefore).Seconds() / life.Seconds())
}

// exposureFactor saturates with the number of resources the credential reaches.
func exposureFactor(s Signals) float64 {
	if s.Exposure <= 0 {
		return 0
	}
	e := float64(s.Exposure)
	return e / (e + exposureSaturation)
}

// privilegeFactor scales linearly from low to critical.
func privilegeFactor(s Signals) float64 {
	return clamp01(float64(s.Privilege) / float64(PrivilegeCritical))
}

// rotationFactor is maximal for a credential never rotated, and otherwise rises
// with the time since its last rotation up to the staleness horizon.
func rotationFactor(s Signals) float64 {
	if s.LastRotated.IsZero() {
		return 1
	}
	return clamp01(s.Now.Sub(s.LastRotated).Seconds() / rotationHorizon.Seconds())
}

// ownerFactor flags orphaned credentials: an absent or inactive owner is the
// maximum, a present one is zero.
func ownerFactor(s Signals) float64 {
	if s.OwnerActive {
		return 0
	}
	return 1
}

// sensitivityFactor scales linearly from low to high.
func sensitivityFactor(s Signals) float64 {
	return clamp01(float64(s.Sensitivity) / float64(SensitivityHigh))
}
