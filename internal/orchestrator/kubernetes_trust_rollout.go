// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/kubetrust"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// KubernetesTrustRolloutEventID is the deterministic event id of one rollout
// operation, so a retried request appends nothing new (AN-5).
func KubernetesTrustRolloutEventID(tenantID, rolloutID, operation, idempotencyKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"kubernetes-trust-rollout\x00"+tenantID+"\x00"+rolloutID+"\x00"+operation+"\x00"+idempotencyKey)).String()
}

var (
	ErrKubernetesTrustRolloutTargets = errors.New("invalid Kubernetes trust rollout targets")
	ErrKubernetesTrustRolloutInput   = errors.New("invalid Kubernetes trust rollout input")
)

// StartKubernetesTrustRollout records a canonical public TrustBundle and its
// target clusters. Retained starts are exact receipts, including legacy v1
// events. They cannot be reapplied out of source order by an HTTP retry.
func (o *Orchestrator) StartKubernetesTrustRollout(ctx context.Context, tenantID string, in projections.KubernetesTrustRolloutStarted) error {
	id := KubernetesTrustRolloutEventID(tenantID, in.RolloutID, "start", "")
	lock := crypto.SHA256Hex([]byte("kubernetes-trust-start\x00" + tenantID + "\x00" + in.Name))
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := o.store.LockKubernetesTrustRolloutStartTx(ctx, tx, lock); err != nil {
			return err
		}
		retained, found, err := o.log.EventByID(ctx, id)
		if err != nil {
			return err
		}
		if found {
			return matchKubernetesTrustRolloutStart(retained, tenantID, id, in)
		}
		current, err := canonicalKubernetesTrustRolloutStart(in)
		if err != nil {
			return err
		}
		known, err := o.store.KnownKubernetesClustersTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		for _, cluster := range current.Clusters {
			if !known[cluster] {
				return fmt.Errorf("%w: cluster %s has not reported Kubernetes controller posture to this tenant; enroll its agent with --cert-manager-controller first", ErrKubernetesTrustRolloutInput, cluster)
			}
		}
		payload, err := json.Marshal(current)
		if err != nil {
			return err
		}
		next := events.Event{ID: id, Type: projections.EventKubernetesTrustRolloutStarted, TenantID: tenantID,
			SchemaVersion: projections.KubernetesTrustRolloutStartedSchemaVersion, Data: payload}
		appended, err := o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if appended.ID != id || appended.Type != next.Type || appended.TenantID != tenantID ||
			appended.SchemaVersion != next.SchemaVersion || !bytes.Equal(appended.Data, payload) {
			return fmt.Errorf("%w: Kubernetes trust rollout start differs from its retained source", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, appended)
	})
}

func canonicalKubernetesTrustRolloutStart(in projections.KubernetesTrustRolloutStarted) (projections.KubernetesTrustRolloutStarted, error) {
	if err := kubetrust.ValidateTargets(in.Name, in.ConfigMapName, in.Key, in.Namespaces); err != nil {
		return in, fmt.Errorf("%w: %v", ErrKubernetesTrustRolloutTargets, err)
	}
	bundle, hash, err := kubetrust.NormalizeBundle(in.CABundlePEM)
	if err != nil {
		return in, fmt.Errorf("%w: %v", ErrKubernetesTrustRolloutInput, err)
	}
	in.CABundlePEM, in.BundleSHA256 = bundle, hash
	if err := projections.ValidateKubernetesTrustRolloutStarted(in); err != nil {
		return in, fmt.Errorf("%w: %v", ErrKubernetesTrustRolloutInput, err)
	}
	return in, nil
}

func matchKubernetesTrustRolloutStart(retained events.Event, tenantID, id string, in projections.KubernetesTrustRolloutStarted) error {
	conflict := fmt.Errorf("%w: Kubernetes trust rollout start differs from its retained source", store.ErrIdempotencyConflict)
	if retained.ID != id || retained.Type != projections.EventKubernetesTrustRolloutStarted || retained.TenantID != tenantID {
		return conflict
	}
	switch retained.SchemaVersion {
	case 1:
		in.CABundlePEM = strings.TrimSpace(in.CABundlePEM) + "\n"
		in.BundleSHA256 = crypto.SHA256Hex([]byte(in.CABundlePEM))
	case projections.KubernetesTrustRolloutStartedSchemaVersion:
		current, err := canonicalKubernetesTrustRolloutStart(in)
		if err != nil {
			return conflict
		}
		in = current
	default:
		return conflict
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if !bytes.Equal(retained.Data, payload) {
		return conflict
	}
	return nil
}

// ControlKubernetesTrustRollout pauses (resume false) or resumes a rollout.
func (o *Orchestrator) ControlKubernetesTrustRollout(ctx context.Context, tenantID, rolloutID string, resume bool, idempotencyKey string) error {
	eventType, operation := projections.EventKubernetesTrustRolloutPaused, "pause"
	if resume {
		eventType, operation = projections.EventKubernetesTrustRolloutResumed, "resume"
	}
	payload, err := json.Marshal(projections.KubernetesTrustRolloutControlled{RolloutID: rolloutID})
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID:   KubernetesTrustRolloutEventID(tenantID, rolloutID, operation, idempotencyKey),
		Type: eventType, TenantID: tenantID, Data: payload,
	})
	return err
}
