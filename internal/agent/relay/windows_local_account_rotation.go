// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
)

const KindWindowsLocalAccountRotation = hostaccounts.RotationDestination

var localAccountRotationSlots = make(chan struct{}, 1)
var errLocalAccountMaterial = errors.New("relay: local account credential adoption refused")

// LocalAccountRotationRecovery settles a begun generation whose outcome was
// lost, by sign-in alone (A268-O1). A channel without it reports the
// generation uncertain, as before.
type LocalAccountRotationRecovery interface {
	RecoverLocalAccountRotation(context.Context, int64, hostaccounts.RotationIntent, []byte, []byte) (winaccounts.RotationProof, error)
}

// LocalAccountRotationChannel binds the current enrollment, durable host fence
// and terminal report. A generic channel cannot authorize native password work.
type LocalAccountRotationChannel interface {
	AuthorizeLocalAccountRotation(context.Context, hostaccounts.RotationIntent) error
	RedeemLocalAccountRotationCredential(context.Context, int64, int, hostaccounts.RotationIntent) (map[string][]byte, time.Time, error)
	ReplayLocalAccountRotation(context.Context, int64, hostaccounts.RotationIntent) (winaccounts.RotationProof, bool, error)
	ExecuteLocalAccountRotation(context.Context, int64, hostaccounts.RotationIntent, []byte, []byte) (winaccounts.RotationProof, error)
	ReportLocalAccountRotation(context.Context, int64, int, hostaccounts.RotationIntent, hostaccounts.RotationReport) (bool, error)
}

func validateLocalAccountWriteProfile(grants []hostaccounts.RotationGrant) error {
	if len(grants) > winaccounts.MaxLocalAccounts {
		return errors.New("relay: native local account grant count exceeds bound")
	}
	seen := map[hostaccounts.RotationGrant]struct{}{}
	for _, grant := range grants {
		if grant.Validate() != nil {
			return errors.New("relay: native local account grant requires exact tenant, host and local SAM SID")
		}
		if _, ok := seen[grant]; ok {
			return errors.New("relay: duplicate native local account write grant")
		}
		seen[grant] = struct{}{}
	}
	return nil
}
func runWindowsLocalAccountRotation(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	intent, err := hostaccounts.DecodeRotationIntent(job.Payload)
	if err != nil || job.JobID <= 0 || job.Attempt <= 0 {
		report(ctx, ch, job, OutcomeFailed, "Local account rotation authority is invalid")
		return false
	}
	channel, ok := ch.(LocalAccountRotationChannel)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "Local account rotation requires enrollment-bound durable execution and reporting")
		return false
	}
	emit := func(state, reason string, proof *winaccounts.RotationProof) bool {
		observed := time.Now().UTC()
		if proof != nil {
			observed = proof.ObservedAt
		}
		result := hostaccounts.RotationReport{RotationID: intent.RotationID, BindingDigest: intent.BindingDigest, ObservedAt: observed, Status: state, Failure: reason, Proof: proof}
		if result.Validate(intent) != nil {
			return false
		}
		reportCtx, stopReport := context.WithTimeout(ctx, 10*time.Second)
		defer stopReport()
		_, _ = channel.ReportLocalAccountRotation(reportCtx, job.JobID, job.Attempt, intent, result)
		return state == "succeeded"
	}
	if ctx.Err() != nil || job.LeaseExpiresUnix <= time.Now().Unix() {
		return emit("refused", "cancelled", nil)
	}
	if err = channel.AuthorizeLocalAccountRotation(ctx, intent); err != nil {
		if errors.Is(err, winaccounts.ErrUnsupported) {
			return emit("refused", "unsupported_os", nil)
		}
		return emit("refused", "identity_mismatch", nil)
	}
	granted := false
	for _, grant := range profile.WindowsLocalAccountWrites {
		if grant.Allows(intent) {
			granted = true
			break
		}
	}
	if !granted {
		return emit("refused", "local_grant_absent", nil)
	}
	select {
	case localAccountRotationSlots <- struct{}{}:
		defer func() { <-localAccountRotationSlots }()
	default:
		return emit("refused", "worker_busy", nil)
	}
	deadline := time.Now().Add(45 * time.Second)
	lease := time.Unix(job.LeaseExpiresUnix, 0)
	if lease.Before(deadline) {
		deadline = lease
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	proof, found, err := channel.ReplayLocalAccountRotation(bounded, job.JobID, intent)
	// A268-O1: a generation begun here without its proof is settled by
	// sign-in when the channel can; it is never rotated again.
	recovery, canRecover := channel.(LocalAccountRotationRecovery)
	recovering := err != nil && errors.Is(err, winaccounts.ErrRotationUncertain) && canRecover
	if err != nil && !recovering {
		return emit("uncertain", "execution_uncertain", nil)
	}
	if found {
		candidate := hostaccounts.RotationReport{RotationID: intent.RotationID, BindingDigest: intent.BindingDigest, Status: "succeeded", ObservedAt: proof.ObservedAt, Proof: &proof}
		if candidate.Validate(intent) != nil {
			return emit("uncertain", "journal_unavailable", nil)
		}
		return emit("succeeded", "", &proof)
	}
	raw, expires, err := channel.RedeemLocalAccountRotationCredential(bounded, job.JobID, job.Attempt, intent)
	// A reply may contain partial material even with an error. Wipe every entry.
	defer func() {
		for _, value := range raw {
			secret.Wipe(value)
		}
	}()
	if err != nil || !expires.After(time.Now()) || len(raw) != 2 || len(raw[hostaccounts.RotationOldCredentialName]) == 0 || len(raw[hostaccounts.RotationOldCredentialName]) > 4096 || len(raw[hostaccounts.RotationNewCredentialName]) == 0 || len(raw[hostaccounts.RotationNewCredentialName]) > 256 {
		for _, value := range raw {
			secret.Wipe(value)
		}
		return emit("refused", "credential_unavailable", nil)
	}
	if expires.Before(deadline) {
		shorter, stop := context.WithDeadline(bounded, expires)
		defer stop()
		bounded = shorter
	}
	if recovering {
		proof, err = recoverLocalAccountRotationMaterial(bounded, recovery, job.JobID, intent, raw)
		switch {
		case errors.Is(err, winaccounts.ErrRotationNotApplied):
			return emit("not_applied", "predecessor_signs_in", nil)
		case errors.Is(err, errLocalAccountMaterial):
			return emit("refused", "credential_unavailable", nil)
		case err != nil:
			return emit("uncertain", "execution_uncertain", nil)
		}
		candidate := hostaccounts.RotationReport{RotationID: intent.RotationID, BindingDigest: intent.BindingDigest, Status: "succeeded", ObservedAt: proof.ObservedAt, Proof: &proof}
		if candidate.Validate(intent) != nil {
			return emit("uncertain", "native_operation_failed", nil)
		}
		return emit("succeeded", "", &proof)
	}
	proof, err = executeLocalAccountRotationMaterial(bounded, channel, job.JobID, intent, raw)
	if err != nil {
		if errors.Is(err, errLocalAccountMaterial) {
			return emit("refused", "credential_unavailable", nil)
		}
		if errors.Is(err, winaccounts.ErrRotationInvalid) {
			return emit("refused", "native_precondition_refused", nil)
		}
		if errors.Is(err, winaccounts.ErrUnsupported) {
			return emit("refused", "unsupported_os", nil)
		}
		return emit("uncertain", "execution_uncertain", nil)
	}
	candidate := hostaccounts.RotationReport{RotationID: intent.RotationID, BindingDigest: intent.BindingDigest, Status: "succeeded", ObservedAt: proof.ObservedAt, Proof: &proof}
	if candidate.Validate(intent) != nil {
		return emit("uncertain", "native_operation_failed", nil)
	}
	return emit("succeeded", "", &proof)
}

// recoverLocalAccountRotationMaterial settles a begun generation with the
// redeemed material, which is gone on return (A268-O1).
func recoverLocalAccountRotationMaterial(ctx context.Context, channel LocalAccountRotationRecovery, job int64, intent hostaccounts.RotationIntent, raw map[string][]byte) (winaccounts.RotationProof, error) {
	defer func() {
		for _, value := range raw {
			secret.Wipe(value)
		}
	}()
	material, destroy, e := AdoptMaterial(raw)
	if e != nil {
		return winaccounts.RotationProof{}, errors.Join(errLocalAccountMaterial, e)
	}
	defer destroy()
	return channel.RecoverLocalAccountRotation(ctx, job, intent, material[hostaccounts.RotationOldCredentialName], material[hostaccounts.RotationNewCredentialName])
}

// The private phase ends before the caller can perform report-network I/O.
// Every buffer, including a partially adopted reply, is gone on return.
func executeLocalAccountRotationMaterial(ctx context.Context, channel LocalAccountRotationChannel, job int64, intent hostaccounts.RotationIntent, raw map[string][]byte) (winaccounts.RotationProof, error) {
	defer func() {
		for _, value := range raw {
			secret.Wipe(value)
		}
	}()
	material, destroy, e := AdoptMaterial(raw)
	if e != nil {
		return winaccounts.RotationProof{}, errors.Join(errLocalAccountMaterial, e)
	}
	defer destroy()
	return channel.ExecuteLocalAccountRotation(ctx, job, intent, material[hostaccounts.RotationOldCredentialName], material[hostaccounts.RotationNewCredentialName])
}
