// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// sealKeyWrapper is the envelope-encryption key wrapper the served secret store seals
// values under at rest (the credential KEK). It is an alias for seal.KeyWrapper so
// Deps can name the type without server.go itself importing the seal package.
type sealKeyWrapper = seal.KeyWrapper

type secretCommandMAC interface {
	KeyedDigest(domain, material []byte) ([]byte, error)
}

type secretScanner interface {
	Scan(ctx context.Context, path string) (secretscan.Report, error)
}

func secretScannerFromDeps(d Deps) secretScanner {
	if d.SecretScanner != nil {
		return d.SecretScanner
	}
	runner := secretscan.NewGitleaksRunner(d.SecretScanGitleaksBin)
	if len(d.SecretScanRoots) > 0 {
		runner.AllowedRoots = append([]string(nil), d.SecretScanRoots...)
	}
	return runner
}

// This file wires the SERVED secrets/identity surface (GAP-006): it assembles the
// api.SecretsBackend from the control plane's already-provisioned dependencies — the
// credential KEK (envelope encryption at rest), the RLS-isolated store, the AN-2
// event log (as an auditor), and the issuing CA in the out-of-process signer (AN-4)
// for the dynamic PKI secret. Until now the five frameworks (authmethod F58,
// secretsync F60, secretsdk F64, pkisecret F67, secretshare F68) were library-only
// with zero importers on the served path; this is the composition that mounts them.

// secretRevocationSink is the store-backed pkisecret.RevocationSink (GAP-005): it
// records issued/revoked dynamic-secret serials as events projected into the SAME
// ca_issued_certs table the served OCSP responder / CRL endpoint read (AN-1), so
// a revoked dynamic-secret certificate actually stops validating, exactly like a
// revoked protocol/API leaf. It is the seam pkisecret's WithRevocationSink expects.
type secretRevocationSink struct {
	store *store.Store
	log   *events.Log
}

const dynamicSecretIssueDestination = "dynsecret.issue"
const dynamicSecretRevokeDestination = "dynsecret.revoke"
const secretSyncDestinationPrefix = "secret.sync."

type dynamicSecretOutboxQueue struct {
	store    *store.Store
	outbox   *orchestrator.Outbox
	tenantID string
}

func (q dynamicSecretOutboxQueue) Enqueue(ctx context.Context, item dynsecret.RevokeItem) error {
	tenantEpoch, err := q.store.DynamicSecretTenantEpoch(ctx, q.tenantID)
	if err != nil {
		return fmt.Errorf("server: resolve dynamic-secret revoke tenant epoch: %w", err)
	}
	item.TenantEpoch = tenantEpoch
	payload, err := json.Marshal(item)
	if err != nil {
		return err
	}
	key := dynamicSecretRevokeKey(tenantEpoch, item.LeaseID)
	return q.store.WithTenant(ctx, q.tenantID, func(tx pgx.Tx) error {
		_, err := q.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: q.tenantID, Destination: dynamicSecretRevokeDestination,
			EffectLane: "dynsecret.provider:" + item.Provider, IdempotencyKey: key, Payload: payload,
		})
		return err
	})
}

func (q dynamicSecretOutboxQueue) Pending(ctx context.Context) ([]dynsecret.RevokeItem, error) {
	records, err := q.outbox.Pending(ctx, q.tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]dynsecret.RevokeItem, 0, len(records))
	for _, rec := range records {
		if rec.Destination != dynamicSecretRevokeDestination {
			continue
		}
		if rec.LeaseHeld {
			// The outbox dispatcher is performing this revocation right now under its
			// lease. Handing it to the in-request drainer as well would run the same
			// provider revoke twice, and only the leaseholder may complete the row (AN-6).
			continue
		}
		var item dynsecret.RevokeItem
		if err := json.Unmarshal(rec.Payload, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// completeSecretIntegrationOutbox marks one secret-integration outbox row delivered
// through the orchestrator (AN-6) instead of hand-rolling the UPDATE.
//
// The served production path drains both queues only through
// secretIntegrationOutboxDispatcher. The queue adapters remain usable by explicit
// compatibility callers of dynsecret.Engine.RunRevocations or
// secretsync.Engine.RunDeliveries, but request handlers must never invoke those
// drainers: an external provider or connector call belongs to the worker (AN-6).
// Only the dispatcher ever holds a lease, so a hand-rolled "status <> 'delivered'"
// completion here could flip a row a dispatch worker was still holding — the
// double-completion the lease predicate exists to prevent — and never record the
// destination's circuit success, leaving a healthy endpoint backed off.
// Outbox.CompleteByKey carries both.
//
// orchestrator.ErrOutboxLeaseHeld is deliberately NOT mapped to nil. The queues'
// Pending already skips rows a dispatch worker holds, so this can only fire when the
// dispatcher claimed the row after this drainer read it; reporting success there
// would retire an item whose effect the leaseholder is still performing.
func completeSecretIntegrationOutbox(ctx context.Context, ob *orchestrator.Outbox, tenantID, destination, idempotencyKey string) error {
	if ob == nil {
		return errors.New("server: secret integration outbox completion requires an outbox")
	}
	_, err := ob.CompleteByKey(ctx, tenantID, destination, idempotencyKey)
	return err
}

func (q dynamicSecretOutboxQueue) Done(ctx context.Context, leaseID string) error {
	tenantEpoch, err := q.store.DynamicSecretTenantEpoch(ctx, q.tenantID)
	if err != nil {
		return fmt.Errorf("server: resolve dynamic-secret revoke completion epoch: %w", err)
	}
	return completeSecretIntegrationOutbox(ctx, q.outbox, q.tenantID,
		dynamicSecretRevokeDestination, dynamicSecretRevokeKey(tenantEpoch, leaseID))
}

func dynamicSecretRevokeKey(tenantEpoch, leaseID string) string {
	return store.DynamicSecretRevokeOutboxIdempotencyKey(tenantEpoch, leaseID)
}

type secretSyncOutboxPayload struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Target         string `json:"target"`
	RequestBinding string `json:"request_binding,omitempty"`
	Sealed         []byte `json:"sealed"`
}

func secretSyncDestination(target string) string {
	return secretSyncDestinationPrefix + target
}

func secretSyncAAD(tenantID, target, id, key string) []byte {
	return []byte(tenantID + "/secret-sync/" + target + "/" + id + "/" + key)
}

// RecordIssued notes that the CA issued a serial so OCSP can answer "good" rather
// than "unknown" and a later revoke has a row to flip (idempotent in the store).
func (s *secretRevocationSink) RecordIssued(ctx context.Context, tenantID, caID, serial string) error {
	issuedAt := time.Now().UTC()
	if s.log == nil {
		return errors.New("server: secret revocation sink requires an event log")
	}
	payload, err := json.Marshal(projections.CAIssuedCertificate{
		CAID: caID, Serial: serial, IssuedAt: issuedAt, Source: "pkisecret",
	})
	if err != nil {
		return err
	}
	return s.appendAndProject(ctx, events.Event{
		Type: projections.EventCAIssuedCertificate, TenantID: tenantID, Data: payload,
	})
}

// Revoke records the serial revoked on the served revocation pipeline (reflected in
// OCSP immediately and the next CRL) by emitting a revocation event (AN-2).
// Idempotent on serial (the projection keeps the first revocation time).
func (s *secretRevocationSink) Revoke(ctx context.Context, tenantID, caID, serial string, reasonCode int) error {
	revokedAt := time.Now().UTC()
	if s.log == nil {
		return errors.New("server: secret revocation sink requires an event log")
	}
	payload, err := json.Marshal(projections.CACertificateRevoked{
		CAID: caID, Serial: serial, ReasonCode: reasonCode, RevokedAt: revokedAt, Source: "pkisecret",
	})
	if err != nil {
		return err
	}
	return s.appendAndProject(ctx, events.Event{
		Type: projections.EventCACertificateRevoked, TenantID: tenantID, Data: payload,
	})
}

func (s *secretRevocationSink) appendAndProject(ctx context.Context, ev events.Event) error {
	stored, err := s.log.Append(ctx, ev)
	if err != nil {
		return err
	}
	return projections.New(s.store).Apply(ctx, stored)
}

// apiSecretsServed reports whether the running binary mounts the served secrets/
// identity surface (GAP-006) — the wiring assertion (it delegates to the API's
// SecretsServed). A startup log and the acceptance test consult it.
func (s *Server) apiSecretsServed() bool { return s.api != nil && s.api.SecretsServed() }

// buildSecretsBackend assembles the api.SecretsBackend from the assembled server's
// dependencies. It is wired into the served API only when the secrets surface is
// enabled and a KEK is provided (envelope encryption at rest is mandatory for the
// secret store). The issuing CA + auth secret are optional and gate their
// sub-features (the dynamic PKI secret and machine login respectively); when absent,
// those routes fail closed rather than degrade. The KEK is the same credential KEK
// the rest of the platform uses for secrets at rest (R3.1).
func (s *Server) buildSecretsBackend(d Deps) api.SecretsBackend {
	be := api.SecretsBackend{
		KEK:                d.KEK,
		TenantCrypto:       d.TenantCrypto,
		Store:              d.Store,
		EventLog:           d.Log,
		Audit:              audit.NewAuditor(s.log),
		AuthSecret:         d.SecretsAuthSecret,
		MachineAuthMethods: d.MachineAuthMethods,
		CAID:               IssuingCAID(),
		// Resolve the issuing CA lazily (the control plane provisions it AFTER the API
		// is constructed): the dynamic PKI secret reaches s.caSigner/s.caCertDER once
		// they are set, and reports issuance unavailable (fail closed) until then or if
		// no signer is configured (AN-4).
		CA: func() ([]byte, crypto.DigestSigner) {
			if s.caSigner == nil || len(s.caCertDER) == 0 {
				return nil, nil
			}
			return s.caCertDER, s.caSigner
		},
		// Record dynamic-secret issuance/revocation on the served revocation pipeline so
		// a revoked dynamic-secret cert stops validating (GAP-005). The store ops are
		// harmless when no cert was issued, and the resolver above gates actual issuance.
		RevocationSink:             &secretRevocationSink{store: d.Store, log: s.log},
		DynamicProviders:           d.DynamicSecretProviders,
		DynamicLeaseWorkerInterval: d.DynamicLeaseWorkerInterval,
		SecretRotators:             d.SecretRotators,
		SecretSyncTargets:          d.SecretSyncTargets,
		SecretScanner:              secretScannerFromDeps(d),
	}
	if mac, ok := d.KEK.(secretCommandMAC); ok {
		be.CommandMAC = mac.KeyedDigest
	}
	if d.TenantDynamicSecretProviders != nil {
		be.DynamicProvidersForTenant = d.TenantDynamicSecretProviders.ForTenant
		be.DynamicLifecycleTenantIDs = d.TenantDynamicSecretProviders.TenantIDs
	}
	if d.TenantDynamicSecretProviders != nil || len(d.DynamicSecretProviders) > 0 {
		be.DynamicLifecycleForTenant = func(tenantID string) (dynsecret.Lifecycle, error) {
			providers := append([]dynsecret.Provider(nil), d.DynamicSecretProviders...)
			if d.TenantDynamicSecretProviders != nil {
				providers = d.TenantDynamicSecretProviders.ForTenant(tenantID)
			}
			return newDurableDynamicSecretLifecycle(
				tenantID, providers, d.Store, d.Log, d.KEK, s.outbox,
				s.wakeOutbox, d.TenantCrypto,
			)
		}
	}
	if d.TenantSecretSyncTargets != nil {
		be.SecretSyncTargetsForTenant = d.TenantSecretSyncTargets.ForTenant
	}
	be.QueueSecretSync = func(ctx context.Context, tenantID, secretName string, secretVersion int, target, remoteKey, idempotencyKey, requestBinding string, value []byte) error {
		return queueSecretSyncEvent(ctx, d.Store, d.Log, d.KEK, tenantID, secretName, secretVersion, target, remoteKey, idempotencyKey, requestBinding, value, d.TenantCrypto)
	}
	if s.outbox != nil {
		be.DynamicRevokeQueue = func(tenantID string) dynsecret.RevokeQueue {
			return dynamicSecretOutboxQueue{store: d.Store, outbox: s.outbox, tenantID: tenantID}
		}
	}
	return be
}

// RunDynamicLeaseWorker runs the served dynamic-secret leaseworker (F65). Runtime
// Run starts it as a background worker; served tests start it directly against the
// assembled server just like the SPIFFE worker.
func (s *Server) RunDynamicLeaseWorker(ctx context.Context) {
	if s.api == nil {
		<-ctx.Done()
		return
	}
	s.api.RunDynamicLeaseWorker(ctx)
}
