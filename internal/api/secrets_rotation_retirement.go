// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A240: a static rotation's retirement gate. A command (or the schedule that
// queues it) may name the consumers of its secret and an approved deadline in
// seconds after verification. The predecessor retires once every named
// consumer reports the result version verified through its delivery reports
// (A238: the version its application proved it uses), or at the deadline,
// whichever comes first. Until then the successor is credential-valid and both
// credentials work; the command view keeps that apart from consumer adoption.

const (
	staticRotationMaxConsumers           = 32
	staticRotationMaxRetireAfterSeconds  = 30 * 24 * 60 * 60
	staticRotationRetirePoll             = 15 * time.Second
	staticRotationConsumersDetail        = "consumers lists at most 32 distinct consumer labels (letters, digits and . _ : / @ -, at most 128)"
	staticRotationRetireAfterDetail      = "retire_after_seconds is between 0 and 2592000 (30 days)"
	staticRotationConsumerDeadlineDetail = "consumers needs retire_after_seconds: the approved deadline at which the predecessor retires if a consumer never reports"
	staticRotationGateOnlyStaticDetail   = "consumers and retire_after_seconds apply to static-provider rotations"

	consumerAdoptionNotRequested = "not_requested"
	consumerAdoptionPending      = "pending"
	consumerAdoptionAdopted      = "adopted"
)

var errStaticRotationAwaitingConsumers = errors.New("api: static rotation retire: waiting for consumer evidence or the approved deadline")

// validateStaticRotationRetirement checks a request's retirement gate.
func validateStaticRotationRetirement(consumers []string, retireAfterSeconds int) error {
	if retireAfterSeconds < 0 || retireAfterSeconds > staticRotationMaxRetireAfterSeconds {
		return errStatus(http.StatusBadRequest, staticRotationRetireAfterDetail)
	}
	if len(consumers) > staticRotationMaxConsumers {
		return errStatus(http.StatusBadRequest, staticRotationConsumersDetail)
	}
	seen := map[string]bool{}
	for _, consumer := range consumers {
		if !secretDeliveryConsumer.MatchString(consumer) || seen[consumer] {
			return errStatus(http.StatusBadRequest, staticRotationConsumersDetail)
		}
		seen[consumer] = true
	}
	if len(consumers) > 0 && retireAfterSeconds == 0 {
		return errStatus(http.StatusBadRequest, staticRotationConsumerDeadlineDetail)
	}
	return nil
}

// refuseRetirementGateOutsideStatic refuses the gate fields on a rotation mode
// that has no retirement phase to hold.
func refuseRetirementGateOutsideStatic(provider string, consumers []string, retireAfterSeconds int) error {
	if (len(consumers) > 0 || retireAfterSeconds != 0) && !isStaticSecretRotation(provider) {
		return errStatus(http.StatusBadRequest, staticRotationGateOnlyStaticDetail)
	}
	return nil
}

// staticRotationConsumerState is one named consumer's evidence for a command.
type staticRotationConsumerState struct {
	Consumer        string `json:"consumer"`
	VerifiedVersion int    `json:"verified_version"`
	Adopted         bool   `json:"adopted"`
}

// staticRotationConsumers reads the named consumers' delivery reports for the
// command's secret: adopted means the consumer reported the result version (or
// a later one) verified. all is false until the successor has a version.
func (a *API) staticRotationConsumers(ctx context.Context, cmd store.SecretStaticRotationCommand) ([]staticRotationConsumerState, bool, error) {
	if len(cmd.Consumers) == 0 {
		return nil, false, nil
	}
	rows, err := a.store.ListSecretDeliveries(ctx, cmd.TenantID, cmd.Key)
	if err != nil {
		return nil, false, err
	}
	verified := map[string]int{}
	for _, row := range rows {
		verified[row.Consumer] = row.VerifiedVersion
	}
	states := make([]staticRotationConsumerState, 0, len(cmd.Consumers))
	all := cmd.ResultVersion > 0
	for _, consumer := range cmd.Consumers {
		adopted := cmd.ResultVersion > 0 && verified[consumer] >= cmd.ResultVersion
		all = all && adopted
		states = append(states, staticRotationConsumerState{Consumer: consumer, VerifiedVersion: verified[consumer], Adopted: adopted})
	}
	return states, all, nil
}

// staticRotationRetireGate reports whether the command may retire its
// predecessor at now and, when not, when to look again. A command verified
// before the gate existed, or with a zero deadline, retires at verification.
func (a *API) staticRotationRetireGate(ctx context.Context, cmd store.SecretStaticRotationCommand, now time.Time) (bool, time.Time, error) {
	if cmd.RetireNotBefore == nil || !now.Before(*cmd.RetireNotBefore) {
		return true, time.Time{}, nil
	}
	if _, adopted, err := a.staticRotationConsumers(ctx, cmd); err != nil {
		return false, time.Time{}, err
	} else if adopted {
		return true, time.Time{}, nil
	}
	next := now.Add(staticRotationRetirePoll)
	if cmd.RetireNotBefore.Before(next) {
		next = *cmd.RetireNotBefore
	}
	return false, next, nil
}

// holdStaticRotationRetirement defers a closed gate's retirement without
// spending the outbox retry budget: no provider call has begun.
func (a *API) holdStaticRotationRetirement(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	open, next, err := a.staticRotationRetireGate(ctx, cmd, time.Now().UTC())
	if err != nil || open {
		return err
	}
	return orchestrator.DeferDeliveryUntil(errStaticRotationAwaitingConsumers, next)
}

// staticRotationView renders a command with its consumer evidence.
func (a *API) staticRotationView(ctx context.Context, cmd store.SecretStaticRotationCommand) (secretStaticRotationView, error) {
	view := toSecretStaticRotationView(cmd)
	view.ConsumerAdoption = consumerAdoptionNotRequested
	if len(cmd.Consumers) == 0 {
		return view, nil
	}
	states, adopted, err := a.staticRotationConsumers(ctx, cmd)
	if err != nil {
		return secretStaticRotationView{}, err
	}
	view.ConsumerStates = states
	view.ConsumerAdoption = consumerAdoptionPending
	if adopted {
		view.ConsumerAdoption = consumerAdoptionAdopted
	}
	return view, nil
}

// staticRotationCredentialValid reports whether the successor passed its
// verification: true from verified on, including a successor left live with
// its predecessor's retirement pending.
func staticRotationCredentialValid(cmd store.SecretStaticRotationCommand) bool {
	switch cmd.Phase {
	case store.SecretStaticRotationVerified, store.SecretStaticRotationCompleted, store.SecretStaticRotationRetirePending:
		return true
	}
	return false
}
