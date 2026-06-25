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
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// sealKeyWrapper is the envelope-encryption key wrapper the served secret store seals
// values under at rest (the credential KEK). It is an alias for seal.KeyWrapper so
// Deps can name the type without server.go itself importing the seal package.
type sealKeyWrapper = seal.KeyWrapper

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

const dynamicSecretRevokeDestination = "dynsecret.revoke"
const secretSyncDestinationPrefix = "secret.sync."

type dynamicSecretOutboxQueue struct {
	store    *store.Store
	outbox   *orchestrator.Outbox
	tenantID string
}

func (q dynamicSecretOutboxQueue) Enqueue(ctx context.Context, item dynsecret.RevokeItem) error {
	payload, err := json.Marshal(item)
	if err != nil {
		return err
	}
	key := dynamicSecretRevokeKey(item.LeaseID)
	return q.store.WithTenant(ctx, q.tenantID, func(tx pgx.Tx) error {
		_, err := q.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: q.tenantID, Destination: dynamicSecretRevokeDestination,
			IdempotencyKey: key, Payload: payload,
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
		var item dynsecret.RevokeItem
		if err := json.Unmarshal(rec.Payload, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func (q dynamicSecretOutboxQueue) Done(ctx context.Context, leaseID string) error {
	key := dynamicSecretRevokeKey(leaseID)
	return q.store.WithTenant(ctx, q.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status = 'delivered',
			        delivered_at = now(),
			        last_error = NULL,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE tenant_id = $1
			    AND destination = $2
			    AND idempotency_key = $3
			    AND status <> 'delivered'`,
			q.tenantID, dynamicSecretRevokeDestination, key)
		return err
	})
}

func dynamicSecretRevokeKey(leaseID string) string {
	return fmt.Sprintf("%s:%s", dynamicSecretRevokeDestination, leaseID)
}

type secretSyncOutboxPayload struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Target string `json:"target"`
	Sealed []byte `json:"sealed"`
}

type secretSyncOutboxQueue struct {
	store    *store.Store
	outbox   *orchestrator.Outbox
	tenantID string
	target   string
	kek      seal.KeyWrapper
}

func (q secretSyncOutboxQueue) Enqueue(ctx context.Context, item secretsync.SyncItem) error {
	if q.kek == nil {
		return errors.New("server: secret sync outbox requires a KEK")
	}
	sealed, err := seal.Seal(q.kek, item.Value, secretSyncAAD(q.tenantID, q.target, item.ID, item.Key))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(secretSyncOutboxPayload{
		ID: item.ID, Key: item.Key, Target: item.Target, Sealed: sealed,
	})
	if err != nil {
		return err
	}
	key := secretSyncOutboxKey(q.target, item.ID)
	return q.store.WithTenant(ctx, q.tenantID, func(tx pgx.Tx) error {
		_, err := q.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: q.tenantID, Destination: secretSyncDestination(q.target),
			IdempotencyKey: key, Payload: payload,
		})
		return err
	})
}

func (q secretSyncOutboxQueue) Pending(ctx context.Context) ([]secretsync.SyncItem, error) {
	if q.kek == nil {
		return nil, errors.New("server: secret sync outbox requires a KEK")
	}
	records, err := q.outbox.Pending(ctx, q.tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]secretsync.SyncItem, 0, len(records))
	for _, rec := range records {
		if rec.Destination != secretSyncDestination(q.target) {
			continue
		}
		var payload secretSyncOutboxPayload
		if err := json.Unmarshal(rec.Payload, &payload); err != nil {
			wipeSyncItems(out)
			return nil, err
		}
		value, err := seal.Open(q.kek, payload.Sealed, secretSyncAAD(q.tenantID, q.target, payload.ID, payload.Key))
		if err != nil {
			wipeSyncItems(out)
			return nil, err
		}
		out = append(out, secretsync.SyncItem{ID: payload.ID, Key: payload.Key, Target: payload.Target, Value: value})
	}
	return out, nil
}

func (q secretSyncOutboxQueue) Done(ctx context.Context, id string) error {
	key := secretSyncOutboxKey(q.target, id)
	return q.store.WithTenant(ctx, q.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status = 'delivered',
			        delivered_at = now(),
			        last_error = NULL,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE tenant_id = $1
			    AND destination = $2
			    AND idempotency_key = $3
			    AND status <> 'delivered'`,
			q.tenantID, secretSyncDestination(q.target), key)
		return err
	})
}

func secretSyncDestination(target string) string {
	return secretSyncDestinationPrefix + target
}

func secretSyncOutboxKey(target, id string) string {
	return secretSyncDestination(target) + ":" + id
}

func secretSyncAAD(tenantID, target, id, key string) []byte {
	return []byte(tenantID + "/secret-sync/" + target + "/" + id + "/" + key)
}

func wipeSyncItems(items []secretsync.SyncItem) {
	for _, item := range items {
		secret.Wipe(item.Value)
	}
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
		Store:              d.Store,
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
		SecretScanner:              secretscan.NewGitleaksRunner(d.SecretScanGitleaksBin),
	}
	if s.outbox != nil {
		be.DynamicRevokeQueue = func(tenantID string) dynsecret.RevokeQueue {
			return dynamicSecretOutboxQueue{store: d.Store, outbox: s.outbox, tenantID: tenantID}
		}
		be.SecretSyncOutbox = func(tenantID, target string) secretsync.Outbox {
			return secretSyncOutboxQueue{store: d.Store, outbox: s.outbox, tenantID: tenantID, target: target, kek: d.KEK}
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
