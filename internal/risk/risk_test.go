package risk_test

import (
	"testing"
	"time"

	"certctl.io/certctl/internal/risk"
)

func now() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// base is a low-risk credential: fresh, unexposed, low privilege, just rotated,
// owned, low sensitivity. Each factor test perturbs one signal.
func base() risk.Signals {
	n := now()
	return risk.Signals{
		Now:         n,
		NotBefore:   n.Add(-24 * time.Hour),
		NotAfter:    n.Add(365 * 24 * time.Hour),
		Exposure:    0,
		Privilege:   risk.PrivilegeLow,
		LastRotated: n.Add(-24 * time.Hour),
		OwnerActive: true,
		Sensitivity: risk.SensitivityLow,
	}
}

// Each factor returns 0..1 and rises with risk. We test the monotonic direction
// and the boundaries per factor, in isolation, by perturbing one signal.

func TestAgeFactorRisesTowardExpiry(t *testing.T) {
	n := now()
	young := base()
	young.NotBefore, young.NotAfter = n.Add(-1*time.Hour), n.Add(1000*time.Hour)
	old := base()
	old.NotBefore, old.NotAfter = n.Add(-900*time.Hour), n.Add(100*time.Hour)

	cy := risk.Compute(young).Components.Age
	co := risk.Compute(old).Components.Age
	if !(co > cy) {
		t.Errorf("age factor: old %.3f should exceed young %.3f", co, cy)
	}
	if cy < 0 || co > 1 {
		t.Errorf("age factor out of [0,1]: young=%.3f old=%.3f", cy, co)
	}
	// An expired certificate saturates at 1.
	exp := base()
	exp.NotBefore, exp.NotAfter = n.Add(-200*time.Hour), n.Add(-1*time.Hour)
	if got := risk.Compute(exp).Components.Age; got < 0.999 {
		t.Errorf("expired age factor = %.3f, want ~1", got)
	}
}

func TestExposureFactorRisesWithReach(t *testing.T) {
	low := base()
	low.Exposure = 1
	high := base()
	high.Exposure = 20
	cl := risk.Compute(low).Components.Exposure
	ch := risk.Compute(high).Components.Exposure
	if !(ch > cl) {
		t.Errorf("exposure factor: 20 targets %.3f should exceed 1 target %.3f", ch, cl)
	}
	if z := risk.Compute(base()).Components.Exposure; z != 0 {
		t.Errorf("zero exposure factor = %.3f, want 0", z)
	}
	if ch > 1 {
		t.Errorf("exposure factor exceeds 1: %.3f", ch)
	}
}

func TestPrivilegeFactorOrdersByClass(t *testing.T) {
	var prev float64 = -1
	for _, p := range []risk.PrivilegeClass{risk.PrivilegeLow, risk.PrivilegeStandard, risk.PrivilegeHigh, risk.PrivilegeCritical} {
		s := base()
		s.Privilege = p
		got := risk.Compute(s).Components.Privilege
		if got < prev {
			t.Errorf("privilege factor not monotonic at %v: %.3f < %.3f", p, got, prev)
		}
		prev = got
	}
	crit := base()
	crit.Privilege = risk.PrivilegeCritical
	if got := risk.Compute(crit).Components.Privilege; got != 1 {
		t.Errorf("critical privilege factor = %.3f, want 1", got)
	}
}

func TestRotationFactorPenalizesStaleAndNever(t *testing.T) {
	n := now()
	recent := base()
	recent.LastRotated = n.Add(-24 * time.Hour)
	stale := base()
	stale.LastRotated = n.Add(-400 * 24 * time.Hour)
	never := base()
	never.LastRotated = time.Time{}

	cr := risk.Compute(recent).Components.Rotation
	cs := risk.Compute(stale).Components.Rotation
	cn := risk.Compute(never).Components.Rotation
	if !(cn >= cs && cs > cr) {
		t.Errorf("rotation factor: never %.3f >= stale %.3f > recent %.3f expected", cn, cs, cr)
	}
	if cn != 1 {
		t.Errorf("never-rotated factor = %.3f, want 1", cn)
	}
}

func TestOwnerFactorFlagsOrphans(t *testing.T) {
	owned := base()
	owned.OwnerActive = true
	orphan := base()
	orphan.OwnerActive = false
	if risk.Compute(owned).Components.Owner != 0 {
		t.Error("owned credential owner factor should be 0")
	}
	if risk.Compute(orphan).Components.Owner != 1 {
		t.Error("orphaned credential owner factor should be 1")
	}
}

func TestSensitivityFactorOrders(t *testing.T) {
	var prev float64 = -1
	for _, s := range []risk.Sensitivity{risk.SensitivityLow, risk.SensitivityMedium, risk.SensitivityHigh} {
		sig := base()
		sig.Sensitivity = s
		got := risk.Compute(sig).Components.Sensitivity
		if got < prev {
			t.Errorf("sensitivity factor not monotonic: %.3f < %.3f", got, prev)
		}
		prev = got
	}
}

// The composite is in [0,100] and a clearly-riskier credential outranks a middle
// one, which outranks a clearly-safe one.
func TestCompositeRanksSensibly(t *testing.T) {
	n := now()
	safe := base()

	mid := base()
	mid.Exposure = 3
	mid.Privilege = risk.PrivilegeStandard
	mid.LastRotated = n.Add(-200 * 24 * time.Hour)
	mid.Sensitivity = risk.SensitivityMedium

	risky := base()
	risky.NotBefore, risky.NotAfter = n.Add(-900*time.Hour), n.Add(50*time.Hour) // near expiry
	risky.Exposure = 25
	risky.Privilege = risk.PrivilegeCritical
	risky.LastRotated = time.Time{} // never rotated
	risky.OwnerActive = false       // orphaned
	risky.Sensitivity = risk.SensitivityHigh

	ss := risk.Compute(safe).Total
	sm := risk.Compute(mid).Total
	sr := risk.Compute(risky).Total
	if !(sr > sm && sm > ss) {
		t.Errorf("composite ranking wrong: risky=%.1f mid=%.1f safe=%.1f", sr, sm, ss)
	}
	for _, v := range []float64{ss, sm, sr} {
		if v < 0 || v > 100 {
			t.Errorf("composite out of [0,100]: %.1f", v)
		}
	}
	if sr < 80 {
		t.Errorf("worst-case credential should score high, got %.1f", sr)
	}
	if ss > 20 {
		t.Errorf("best-case credential should score low, got %.1f", ss)
	}
}

// Weights change the composite: zeroing every weight but exposure makes the
// score track exposure alone.
func TestComputeWithWeights(t *testing.T) {
	s := base()
	s.Exposure = 25
	s.Privilege = risk.PrivilegeCritical // would dominate under default weights

	onlyExposure := risk.Weights{Exposure: 1}
	got := risk.ComputeWith(s, onlyExposure)
	want := risk.Compute(s).Components.Exposure * 100
	if diff := got.Total - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("exposure-only weight: total %.3f, want %.3f", got.Total, want)
	}
}
