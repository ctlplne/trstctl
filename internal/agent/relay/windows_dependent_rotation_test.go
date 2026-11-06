// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

type rotationServiceBoundary struct{ writes, reads int }

func (s *rotationServiceBoundary) ObserveForRotation(_ context.Context, v windependents.Service) (windependents.Runtime, error) {
	s.reads++
	if !v.WasRunning {
		return windependents.Runtime{}, nil
	}
	return windependents.Runtime{Running: v.WasRunning, ProcessID: 42, AccountSID: v.AccountSID}, nil
}
func (s *rotationServiceBoundary) StopForRotation(context.Context, windependents.Service) (windependents.Runtime, error) {
	return windependents.Runtime{}, nil
}
func (s *rotationServiceBoundary) StartAfterRotation(_ context.Context, v windependents.Service) (windependents.Runtime, error) {
	return windependents.Runtime{Running: true, ProcessID: 43, AccountSID: v.AccountSID}, nil
}
func (s *rotationServiceBoundary) UpdatePassword(_ context.Context, v windependents.Service, password []byte) error {
	if v.WasRunning || len(password) != 32 {
		panic("wrong native stopped authority")
	}
	s.writes++
	return nil
}

type rotationCredentialBoundary struct {
	Channel
	material    []byte
	redemptions int
}

func (c *rotationCredentialBoundary) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redemptions++
	return map[string][]byte{servicedependents.RotationCredentialName: c.material}, nil
}
func TestDependentWriteNeverUsesInventoryOnlyGrantA267(t *testing.T) {
	source := hostInventoryIntent(t)
	step := servicedependents.RotationStep{RotationID: uuid.NewString(), PlanDigest: strings.Repeat("a", 64), Direction: servicedependents.Forward, Action: servicedependents.Update, Ref: servicedependents.DependentRef{AgentID: source.Binding.AgentID, Family: "services", Name: "owned-service"}, AccountSID: source.Binding.Account.SID, ProbeID: "owned"}
	step.Service = &windependents.Service{Name: step.Ref.Name, AccountSID: step.AccountSID, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true}
	// Derive the same canonical step identity as the reviewed workflow.
	step.ID = dependentTestStepID(step)
	step.Challenge = uuid.NewString()
	step.NotBefore = time.Now().UTC()
	step.Deadline = step.NotBefore.Add(time.Minute)
	native := &rotationServiceBoundary{}
	material := []byte(strings.Repeat("x", 32))
	channel := &rotationCredentialBoundary{material: material}
	profile := connector.LocalOpsConfig{WindowsDependentSIDs: []string{step.AccountSID}}
	report := executeDependentStep(t.Context(), channel, profile, Job{JobID: 17, Attempt: 1}, step, dependentNativeAdapters{services: native})
	if report.Status != "failed" || report.Failure != "local_grant_absent" || native.writes != 0 || native.reads != 0 || channel.redemptions != 0 {
		t.Fatal("read-only account grant widened to a password write")
	}
	profile.WindowsDependentWrites = []connector.WindowsDependentWriteGrant{{AccountSID: step.AccountSID, Family: step.Ref.Family, Name: step.Ref.Name, ProbeID: step.ProbeID}}
	profile.WindowsDependentProbes = []connector.WindowsDependentProbe{{ID: step.ProbeID, URL: "http://127.0.0.1:8080/owned-work"}}
	report = executeDependentStep(t.Context(), channel, profile, Job{JobID: 17, Attempt: 1}, step, dependentNativeAdapters{services: native})
	if report.Status != "succeeded" || native.writes != 1 || channel.redemptions != 1 {
		t.Fatal("exact native write failed", report.Failure)
	}
	for _, b := range material {
		if b != 0 {
			t.Fatal("redeemed material was not wiped")
		}
	}
}

func dependentTestStepID(s servicedependents.RotationStep) string {
	return crypto.SHA256Hex([]byte(s.RotationID + "\x00" + s.PlanDigest + "\x00" + s.Direction + "\x00" + s.Action + "\x00" + s.Ref.AgentID + "\x00" + s.Ref.Family + "\x00" + s.Ref.Name))[:32]
}
