// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func (a *API) dependentRotationParent(ctx context.Context, cmd store.SecretStaticRotationCommand) (store.ServiceDependentRotation, error) {
	parent, e := a.store.GetServiceDependentRotation(ctx, cmd.TenantID, cmd.DependentChangeID)
	if e != nil {
		return parent, e
	}
	event, found, e := a.log.EventByID(ctx, parent.ID)
	if e != nil {
		return parent, e
	}
	var source projections.ServiceDependentRotationQueued
	if !found || event.TenantID != cmd.TenantID || event.Type != projections.EventServiceDependentRotationQueued || json.Unmarshal(event.Data, &source) != nil {
		return parent, errors.New("api: native rotation has no canonical parent authority")
	}
	digest, e := source.Intent.Digest()
	if e != nil || digest != parent.IntentDigest || digest != cmd.RequestBinding || source.Child.ID != cmd.ID || parent.CommandID != cmd.ID || source.Child.ProviderBinding != cmd.ProviderBinding || cmd.Provider != source.Intent.Plan.Account.ProviderID || cmd.Key != source.Intent.Plan.SecretName || cmd.OldRef != source.Intent.Plan.Account.DN || cmd.ExpectedVersion != source.Intent.ExpectedVersion || cmd.TenantEpoch != source.Child.TenantEpoch {
		return parent, errors.New("api: native rotation parent or sealed generation differs")
	}
	retained, e := parent.Intent.Digest()
	if e != nil || retained != digest {
		return parent, errors.New("api: retained native intent differs from its source")
	}
	if err := projections.ValidateServiceDependentRotationSource(event, source); err != nil {
		return parent, err
	}
	if source.Approval != nil {
		approval, err := a.store.GetOperationApproval(ctx, cmd.TenantID, source.Approval.RequestID)
		if err != nil {
			return parent, err
		}
		if approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID != event.ID {
			return parent, errors.New("api: reconciliation lacks exact consumed approval authority")
		}
		if err := validateConsumedReconcileReadAuthority(event.ID, source.Intent.Plan.Account.Name, *source.Approval, approval); err != nil {
			return parent, err
		}
	}
	applying, hasApplying, e := a.log.EventByID(ctx, servicedependents.DirectoryApplyStartedSourceID(parent.ID))
	if e != nil {
		return parent, e
	}
	if hasApplying {
		var started projections.ServiceDependentDirectoryApplyStarted
		if applying.TenantID != cmd.TenantID || applying.Type != projections.EventServiceDependentDirectoryApplyStarted || json.Unmarshal(applying.Data, &started) != nil || started.RotationID != parent.ID || started.IntentDigest != digest {
			return parent, errors.New("api: native apply intent source differs")
		}
	}
	if parent.DirectoryApplyStarted != hasApplying {
		return parent, errors.New("api: native apply state differs from its source")
	}
	inverse, hasInverse, e := a.log.EventByID(ctx, servicedependents.InverseSourceID(parent.ID))
	if e != nil {
		return parent, e
	}
	direction := servicedependents.Forward
	if hasInverse {
		var selected projections.ServiceDependentRotationInverse
		if inverse.TenantID != cmd.TenantID || inverse.Type != projections.EventServiceDependentRotationInverse || json.Unmarshal(inverse.Data, &selected) != nil || selected.RotationID != parent.ID || selected.IntentDigest != digest || selected.Failure != parent.Failure {
			return parent, errors.New("api: native inverse source differs")
		}
		direction = servicedependents.Inverse
	}
	restored, hasRestored, e := a.log.EventByID(ctx, servicedependents.DirectoryRestoredSourceID(parent.ID))
	if e != nil {
		return parent, e
	}
	if hasRestored {
		var proof projections.ServiceDependentDirectoryRestored
		if !hasInverse || restored.TenantID != cmd.TenantID || restored.Type != projections.EventServiceDependentDirectoryRestored || json.Unmarshal(restored.Data, &proof) != nil || proof.RotationID != parent.ID || proof.IntentDigest != digest {
			return parent, errors.New("api: native directory recovery source differs")
		}
	}
	if parent.Direction != direction || parent.DirectoryRestored != hasRestored {
		return parent, errors.New("api: native recovery state differs from its canonical source")
	}
	return parent, nil
}
func (a *API) dependentNativePreparation(ctx context.Context, parent store.ServiceDependentRotation, cmd store.SecretStaticRotationCommand) error {
	raw, e := a.secrets.open(ctx, cmd.TenantID, cmd.SealedPreparation, staticRotationAAD(cmd.TenantID, cmd.ID, "prepared"))
	if e != nil {
		return e
	}
	held, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		return e
	}
	defer held.Destroy()
	var identity struct {
		SID     string `json:"native_sid"`
		GUID    string `json:"native_guid"`
		DN      string `json:"bind_dn"`
		User    string `json:"username"`
		Binding string `json:"provider_binding"`
	}
	if json.Unmarshal(held.Bytes(), &identity) != nil || !dependentPreparedIdentityMatches(identity.SID, identity.GUID, identity.DN, identity.User, parent.Intent.Plan.Account) || identity.Binding != parent.Intent.ProviderBinding {
		return errors.New("api: prepared AD object differs from the reviewed native identity")
	}
	return nil
}
func (a *API) selectDependentInverse(ctx context.Context, parent store.ServiceDependentRotation, failure string) error {
	if parent.Direction == servicedependents.Inverse {
		return nil
	}
	// Stable source identity makes a retry keep the first reason and direction.
	eventID := servicedependents.InverseSourceID(parent.ID)
	return a.appendAndProjectStaticRotation(ctx, parent.TenantID, eventID, projections.EventServiceDependentRotationInverse, projections.ServiceDependentRotationInverse{RotationID: parent.ID, IntentDigest: parent.IntentDigest, Failure: failure, At: time.Now().UTC()})
}
func (a *API) driveDependentSteps(ctx context.Context, parent store.ServiceDependentRotation, preflight bool) error {
	next, e := a.nextDependentStep(ctx, parent, preflight)
	if e != nil {
		return e
	}
	if next == nil {
		return nil
	}
	existing, e := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, next.ID)
	if e == nil {
		if existing.Status != "queued" {
			return store.ErrServiceDependentStepFailed
		}
		if time.Now().After(existing.Intent.Deadline.Add(time.Minute)) {
			return store.ErrServiceDependentStepFailed
		}
		return orchestrator.DeferDelivery(errors.New("native dependent evidence is pending"))
	}
	if !errors.Is(e, store.ErrServiceDependentStepNotFound) {
		return e
	}
	next.Challenge = googleuuid.NewString()
	next.NotBefore = time.Now().UTC()
	next.Deadline = next.NotBefore.Add(2 * time.Minute)
	// The retained stop result supplies the exact predecessor process set to the
	// later start/probe. It cannot be invented by a caller of the queue API.
	if next.Action == servicedependents.Start || next.Action == servicedependents.Probe {
		inputs, e := a.dependentRotationStoredInputs(ctx, parent)
		if e != nil {
			return e
		}
		steps, e := parent.Intent.Steps(inputs, parent.Direction)
		if e != nil {
			return e
		}
		if next.Service != nil {
			forward, e := parent.Intent.Steps(inputs, servicedependents.Forward)
			if e != nil {
				return e
			}
			seen := map[uint32]bool{}
			for _, observed := range forward {
				if observed.Ref != next.Ref || observed.Action != servicedependents.Preflight && observed.Action != servicedependents.Probe {
					continue
				}
				saved, e := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, observed.ID)
				if errors.Is(e, store.ErrServiceDependentStepNotFound) {
					continue
				}
				if e != nil {
					return e
				}
				if saved.Status == "succeeded" && saved.Report != nil && saved.Report.Runtime != nil && saved.Report.Runtime.ProcessID != 0 && !seen[saved.Report.Runtime.ProcessID] {
					next.PreviousPIDs = append(next.PreviousPIDs, saved.Report.Runtime.ProcessID)
					seen[saved.Report.Runtime.ProcessID] = true
				}
			}
		}
		for _, step := range steps {
			if step.Action != servicedependents.Stop || step.Ref != next.Ref {
				continue
			}
			saved, e := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, step.ID)
			if e != nil {
				return e
			}
			if saved.Report == nil || saved.Status != "succeeded" {
				return errors.New("api: native start has no durable stopped predecessor")
			}
			if saved.Report.PoolProof != nil {
				next.PreviousPIDs = append([]uint32(nil), saved.Report.PoolProof.PreviousPIDs...)
			}
		}
	}
	value := projections.ServiceDependentStepQueued{Step: *next, At: next.NotBefore}
	if e := a.appendAndProjectStaticRotation(ctx, parent.TenantID, servicedependents.StepSourceID(parent.ID, next.ID), projections.EventServiceDependentStepQueued, value); e != nil {
		return e
	}
	return orchestrator.DeferDelivery(errors.New("exact native dependent work queued"))
}
func (a *API) dependentRotationStoredInputs(ctx context.Context, parent store.ServiceDependentRotation) ([]servicedependents.RotationHostInput, error) {
	var inputs []servicedependents.RotationHostInput
	e := a.store.WithTenant(ctx, parent.TenantID, func(tx pgx.Tx) error {
		var e error
		inputs, e = a.store.ServiceDependentRotationInputsTx(ctx, tx, parent.TenantID, parent.Intent)
		return e
	})
	return inputs, e
}
func (a *API) beforeDependentDirectoryApply(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	parent, e := a.dependentRotationParent(ctx, cmd)
	if e != nil {
		return e
	}
	if parent.Direction == servicedependents.Inverse {
		return a.rollbackStaticRotation(ctx, cmd, provider)
	}
	current, e := a.secrets.be.Store.GetSecret(ctx, cmd.TenantID, cmd.Key)
	if e != nil {
		return e
	}
	if current.Version != cmd.ExpectedVersion {
		if parent.DirectoryApplyStarted {
			return a.rollbackStaticRotation(ctx, cmd, provider)
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: "vault version changed during native preflight; no directory reset was performed"})
	}
	if parent.DirectoryApplyStarted {
		return nil
	} // resume exactly the already-authorized native generation
	if e := a.dependentNativePreparation(ctx, parent, cmd); e != nil {
		return e
	}
	if !time.Now().Before(parent.Intent.Plan.ExpiresAt) {
		if parent.Intent.Mode == servicedependents.Reconcile {
			return a.failUnstartedReconciliation(ctx, cmd, "review deadline expired")
		}
		if e := a.selectDependentInverse(ctx, parent, "deadline_expired"); e != nil {
			return e
		}
		return a.rollbackStaticRotation(ctx, cmd, provider)
	}
	inputs, e := a.dependentRotationInputs(ctx, cmd.TenantID, parent.Intent.Plan.Account.AccountID)
	if e == nil {
		e = parent.Intent.Validate(inputs)
	}
	if e != nil {
		if parent.Intent.Mode == servicedependents.Reconcile {
			return a.failUnstartedReconciliation(ctx, cmd, "reviewed inventory changed")
		}
		if e := a.selectDependentInverse(ctx, parent, "source_changed"); e != nil {
			return e
		}
		return a.rollbackStaticRotation(ctx, cmd, provider)
	}
	e = a.driveDependentSteps(ctx, parent, true)
	if errors.Is(e, store.ErrServiceDependentStepFailed) {
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: "native host preflight failed; no directory reset or dependent mutation was performed"})
	}
	if e != nil {
		return e
	}
	return a.appendAndProjectStaticRotation(ctx, parent.TenantID, servicedependents.DirectoryApplyStartedSourceID(parent.ID), projections.EventServiceDependentDirectoryApplyStarted, projections.ServiceDependentDirectoryApplyStarted{RotationID: parent.ID, IntentDigest: parent.IntentDigest, At: time.Now().UTC()})
}
func (a *API) beforeDependentVaultCutover(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	parent, e := a.dependentRotationParent(ctx, cmd)
	if e != nil {
		return e
	}
	if parent.Direction == servicedependents.Inverse {
		return a.rollbackStaticRotation(ctx, cmd, provider)
	}
	e = a.driveDependentSteps(ctx, parent, false)
	if errors.Is(e, store.ErrServiceDependentStepFailed) {
		if e := a.selectDependentInverse(ctx, parent, "dependent_failed"); e != nil {
			return e
		}
		return a.rollbackStaticRotation(ctx, cmd, provider)
	}
	if e != nil {
		return e
	}
	return a.proveDependentDirectorySuccessor(ctx, cmd, provider)
}
func (a *API) dependentDirectoryRestored(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	parent, e := a.dependentRotationParent(ctx, cmd)
	if e != nil {
		return e
	}
	if parent.Direction != servicedependents.Inverse {
		return errors.New("api: dependent inverse direction was not retained")
	}
	if parent.DirectoryRestored {
		return nil
	}
	eventID := servicedependents.DirectoryRestoredSourceID(parent.ID)
	return a.appendAndProjectStaticRotation(ctx, cmd.TenantID, eventID, projections.EventServiceDependentDirectoryRestored, projections.ServiceDependentDirectoryRestored{RotationID: parent.ID, IntentDigest: parent.IntentDigest, At: time.Now().UTC()})
}
func (a *API) beforeDependentInversePublication(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	parent, e := a.dependentRotationParent(ctx, cmd)
	if e != nil {
		return e
	}
	if !parent.DirectoryRestored {
		return errors.New("api: native directory inverse is not yet observed")
	}
	e = a.driveDependentSteps(ctx, parent, false)
	if errors.Is(e, store.ErrServiceDependentStepFailed) {
		return orchestrator.DeferDelivery(errors.New("dependent inverse needs operator recovery; vault inverse remains unpublished"))
	}
	return e
}

// OpenDependentRotationCredential is the existing mTLS redemption seam. It
// opens only the sealed generation selected by this exact active update step.
// The caller owns wiping returned bytes; no host credential is cached.
func (a *API) OpenDependentRotationCredential(ctx context.Context, tenantID string, step servicedependents.RotationStep) ([]byte, error) {
	if step.Action != servicedependents.Update || !time.Now().Before(step.Deadline) {
		return nil, errors.New("api: only an exact dependent update redeems a credential")
	}
	saved, e := a.canonicalDependentStep(ctx, tenantID, step.RotationID, step.ID)
	if e != nil {
		return nil, e
	}
	if saved.Status != "queued" || !dependentCanonicalJSON(saved.Intent, step) {
		return nil, errors.New("api: native credential step differs from canonical active authority")
	}
	parent, e := a.store.GetServiceDependentRotation(ctx, tenantID, step.RotationID)
	if e != nil {
		return nil, e
	}
	if parent.Direction != step.Direction || parent.IntentDigest != step.PlanDigest {
		return nil, errors.New("api: native step generation was superseded")
	}
	cmd, e := a.store.GetSecretStaticRotationCommand(ctx, tenantID, parent.CommandID)
	if e != nil {
		return nil, e
	}
	if _, e = a.dependentRotationParent(ctx, cmd); e != nil {
		return nil, e
	}
	part := "new"
	sealed := cmd.SealedNew
	if step.Direction == servicedependents.Inverse {
		if !parent.DirectoryRestored {
			return nil, errors.New("api: dependent inverse precedes directory recovery")
		}
		part = "old"
		sealed = cmd.SealedOld
	}
	raw, e := a.secrets.open(ctx, tenantID, sealed, staticRotationAAD(tenantID, cmd.ID, part))
	if e != nil {
		return nil, e
	}
	held, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		return nil, e
	}
	defer held.Destroy()
	// Native AD JSON is decoded with a byte-backed secret field. Public metadata
	// never carries a password string; this one-purpose response is locked by the
	// broker before its gRPC marshal and is wiped by redeemedMaterial.
	var credential struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(held.Bytes(), &credential) != nil || len(credential.Password) == 0 {
		secret.Wipe(credential.Password)
		return nil, errors.New("api: sealed AD credential has no native password")
	}
	return credential.Password, nil
}

func dependentPreparedIdentityMatches(nativeSID, guid, dn, user string, account servicedependents.AccountBinding) bool {
	sid, e := dynsecret.CanonicalADSIDHex(nativeSID)
	return e == nil && sid == account.SID && guid == account.GUID && dynsecret.SameADNativeDN(dn, account.DN) && user == account.Name
}

func (a *API) failUnstartedReconciliation(ctx context.Context, cmd store.SecretStaticRotationCommand, detail string) error {
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: detail + "; no directory reset or predecessor authentication was performed"})
}
