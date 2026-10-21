// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
)

// Connector-side takedown of an installed object (A43).
//
// A network relay removes the fingerprint-named certificate and key objects a
// deploy installed on an appliance, under the same grant and the same
// credential redemption as a deploy. It never unbinds a listener: an object
// the target still serves is reported as bound and left in place, so the
// operator rolls back or deploys a replacement first.

// KindConnectorTakedown is the outbox destination a network relay claims.
const KindConnectorTakedown = "connector.takedown"

// TakedownIntent names the object to remove. It carries no certificate and no
// key: the fingerprint names an object already on the appliance.
type TakedownIntent struct {
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetID       string          `json:"target_id,omitempty"`
	TargetRevision string          `json:"target_revision,omitempty"`
	IdentityID     string          `json:"identity_id,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	TargetConfig   json.RawMessage `json:"target_config,omitempty"`
	CredentialRefs []string        `json:"credential_refs,omitempty"`
	Reason         string          `json:"reason,omitempty"`
}

const (
	// TakedownRemoved: the named object (and its key) was deleted.
	TakedownRemoved = "removed"
	// TakedownBound: the target still serves the object; nothing was deleted.
	TakedownBound = "bound"
	// TakedownNotInstalled: no object of that name exists on the target.
	TakedownNotInstalled = "not_installed"
)

// TakedownReport is the signed account of one takedown. The server re-derives
// its digest from the structured report.
type TakedownReport struct {
	TargetID       string `json:"target_id"`
	TargetRevision string `json:"target_revision"`
	IdentityID     string `json:"identity_id,omitempty"`
	Connector      string `json:"connector"`
	Target         string `json:"target"`
	Fingerprint    string `json:"fingerprint"`
	State          string `json:"state"`
}

// Digest binds the decision to the signed job receipt.
func (r TakedownReport) Digest() string {
	var bytes []byte
	for _, part := range []string{"trstctl-takedown-report/v1", r.TargetID, r.TargetRevision, r.IdentityID,
		r.Connector, r.Target, r.Fingerprint, r.State} {
		bytes = append(bytes, part...)
		bytes = append(bytes, 0)
	}
	return crypto.SHA256Hex(bytes)
}

// ValidateTakedownReport checks that a signed report answers exactly the
// queued intent and that the signed digest is the report's own.
func ValidateTakedownReport(intent TakedownIntent, report TakedownReport, digest string) error {
	if report.TargetID != intent.TargetID || report.TargetRevision != intent.TargetRevision ||
		report.IdentityID != intent.IdentityID || report.Connector != intent.Connector ||
		report.Target != intent.Target || !strings.EqualFold(report.Fingerprint, intent.Fingerprint) {
		return errors.New("takedown report does not answer the queued intent")
	}
	switch report.State {
	case TakedownRemoved, TakedownBound, TakedownNotInstalled:
	default:
		return errors.New("takedown report carries an unknown state")
	}
	if digest == "" || digest != report.Digest() {
		return errors.New("takedown report digest does not match the signed evidence")
	}
	return nil
}

// TakedownCapableKinds is the relay-side census: connectors this relay can
// both reach and remove objects from.
func TakedownCapableKinds() []string {
	var out []string
	for _, kind := range RelayConnectorKinds() {
		if connector.CanTakedown(kind) {
			out = append(out, kind)
		}
	}
	return out
}

// Takedown drives one object removal against a real appliance.
func Takedown(ctx context.Context, client *http.Client, intent TakedownIntent, material Material) (connector.Stats, error) {
	if !Executes(intent.Connector) {
		return connector.Stats{}, fmt.Errorf("relay: connector %q is not relay-executable", intent.Connector)
	}
	if !connector.CanTakedown(intent.Connector) {
		return connector.Stats{}, connector.ErrTakedownUnsupported
	}
	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return connector.Stats{}, fmt.Errorf("relay: decode target config: %w", err)
		}
	}
	if strings.TrimSpace(target.Endpoint) == "" {
		return connector.Stats{}, errors.New("relay: target config carries no endpoint")
	}
	built, err := buildRelayConnector(intent.Connector, target, material)
	if err != nil {
		return connector.Stats{}, err
	}
	return connector.RunTakedown(ctx, built, connector.NewHTTPOps(client), connector.Takedown{
		Target: intent.Target, Fingerprint: intent.Fingerprint, Reason: intent.Reason,
	})
}

func validTakedownIntent(intent TakedownIntent) bool {
	fp, err := hex.DecodeString(strings.TrimSpace(intent.Fingerprint))
	return strings.TrimSpace(intent.Connector) != "" && strings.TrimSpace(intent.Target) != "" &&
		strings.TrimSpace(intent.TargetID) != "" && strings.TrimSpace(intent.TargetRevision) != "" &&
		err == nil && len(fp) == 32
}

// runTakedown is one takedown job's whole life. Refusals happen before any
// credential is redeemed; a bound or absent object is a signed executed
// report, not a failure, because the relay reached the target and learned a
// fact the operator acts on.
func runTakedown(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent TakedownIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || !validTakedownIntent(intent) {
		report(ctx, ch, job, OutcomeFailed, transport.TakedownRefusedBadPayload)
		return false
	}
	if !Executes(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNotExecutable)
		return false
	}
	if !connector.CanTakedown(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, transport.TakedownRefusedUnsupported)
		return false
	}
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoCredential)
		return false
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoLockedMemory)
		return false
	}
	defer destroy()

	result := TakedownReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		IdentityID: intent.IdentityID, Connector: intent.Connector, Target: intent.Target,
		Fingerprint: strings.ToLower(intent.Fingerprint), State: TakedownRemoved}
	stats, execErr := Takedown(ctx, client, intent, material)
	switch {
	case errors.Is(execErr, connector.ErrTakedownObjectBound):
		result.State = TakedownBound
	case errors.Is(execErr, connector.ErrTakedownNotInstalled):
		result.State = TakedownNotInstalled
	case execErr != nil:
		// The connector's error can carry whatever the appliance echoed,
		// including the credential. Never forwarded.
		report(ctx, ch, job, OutcomeFailed, transport.TakedownFailedAtTarget)
		return false
	}
	if stats.Denied > 0 {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedCapability)
		return false
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.TakedownFailedAtTarget)
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), result.Digest())
	return result.State == TakedownRemoved
}
