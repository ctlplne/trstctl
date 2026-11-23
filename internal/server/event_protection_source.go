// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/journalkey"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

var errProductionIngressCustodyUnavailable = errors.New("server: production event ingress requires tenant custody")

// openConfiguredEventSource creates exactly one custodian before any Open
// recovery can read protected history. The caller closes log, then custody,
// then signer, after all dispatch/projection workers have stopped. Even an
// empty directory setting attaches fail-closed readers for protected source.
func openConfiguredEventSource(ctx context.Context, cfg *config.Config, st *store.Store, key *jose.SigningKey, sanitized bool, backupRoots []string, extra ...events.OpenOption) (*events.Log, *eventProtectionRuntime, error) {
	return openConfiguredEventSourceWithCustody(ctx, cfg, st, key, sanitized, backupRoots, nil, extra...)
}

// Maintenance and recovery must load the deployment KEK that already belongs
// to this target. Creating a fresh key here would make retained sealed history
// look recoverable while disconnecting it from its actual tenant custody.
func openConfiguredEventSourceWithExistingCustody(ctx context.Context, cfg *config.Config,
	st *store.Store, key *jose.SigningKey, signer SignerProvider, sanitized bool,
	backupRoots []string, extra ...events.OpenOption,
) (*events.Log, *eventProtectionRuntime, *runTenantCustodyCore, func(), error) {
	return openConfiguredEventSourceWithExistingCustodyBeforeOpen(ctx, cfg, st, key,
		signer, sanitized, backupRoots, nil, extra...)
}

func openConfiguredEventSourceWithExistingCustodyBeforeOpen(ctx context.Context, cfg *config.Config,
	st *store.Store, key *jose.SigningKey, signer SignerProvider, sanitized bool,
	backupRoots []string, beforeOpen func(*eventProtectionRuntime, *runTenantCustodyCore) error,
	extra ...events.OpenOption,
) (*events.Log, *eventProtectionRuntime, *runTenantCustodyCore, func(), error) {
	deployment, err := kek.Load(cfg.Secrets.KEKFile)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load existing deployment KEK for event source: %w", err)
	}
	core, err := newRunTenantCustodyCore(cfg, st, deployment, signer)
	if err != nil {
		deployment.Destroy()
		return nil, nil, nil, nil, err
	}
	log, protection, err := openConfiguredEventSourceWithCustodyBeforeOpen(ctx, cfg, st, key,
		sanitized, backupRoots, core, func(runtime *eventProtectionRuntime) error {
			if beforeOpen == nil {
				return nil
			}
			return beforeOpen(runtime, core)
		}, extra...)
	if err != nil {
		deployment.Destroy()
		return nil, nil, nil, nil, err
	}
	closeSource := func() {
		_ = log.Close()
		_ = protection.Close()
		deployment.Destroy()
	}
	return log, protection, core, closeSource, nil
}

// The production caller supplies its already assembled custody core. This
// check runs before events.Open can inspect or recover a protected generation.
func openConfiguredEventSourceWithCustody(ctx context.Context, cfg *config.Config, st *store.Store, key *jose.SigningKey, sanitized bool, backupRoots []string, core *runTenantCustodyCore, extra ...events.OpenOption) (*events.Log, *eventProtectionRuntime, error) {
	return openConfiguredEventSourceWithCustodyBeforeOpen(ctx, cfg, st, key, sanitized,
		backupRoots, core, nil, extra...)
}

func openConfiguredEventSourceWithCustodyBeforeOpen(ctx context.Context, cfg *config.Config,
	st *store.Store, key *jose.SigningKey, sanitized bool, backupRoots []string,
	core *runTenantCustodyCore, beforeOpen func(*eventProtectionRuntime) error,
	extra ...events.OpenOption,
) (*events.Log, *eventProtectionRuntime, error) {
	if core != nil && st != nil && (core.access == nil || core.registry == nil || core.keyring == nil) {
		return nil, nil, errors.New("event source requires complete tenant custody")
	}
	if st != nil {
		if err := st.BootstrapRestoreAdmission(ctx); err != nil {
			return nil, nil, fmt.Errorf("bootstrap event ingress admission: %w", err)
		}
	}
	protection, err := newEventProtectionRuntime(cfg, st, key, backupRoots...)
	if err != nil {
		return nil, nil, fmt.Errorf("configure event protection: %w", err)
	}
	if beforeOpen != nil {
		if err := beforeOpen(protection); err != nil {
			_ = protection.Close()
			return nil, nil, fmt.Errorf("preflight event source before broker open: %w", err)
		}
	}
	options := append(protection.openOptions(), extra...)
	if st != nil {
		options = append(options, events.WithRequiredAppendAdmission())
		options = append(options, events.WithRequiredBackupHistoryAdmission())
		options = append(options, events.WithBackupHistoryJournal(
			func(journalCtx context.Context, cut uint64, artifactDigest, action string,
				record events.BackupHistoryRecord, run func(context.Context) error,
			) error {
				return st.WithRawHistoryRecordJournal(journalCtx, cut, artifactDigest, action, record, run)
			}))
		// Install after caller options so no recovery constructor can replace
		// the target-local guards for direct event or raw-history library calls.
		var access func() tenantseal.Access
		if core != nil {
			access = func() tenantseal.Access { return core.access }
		}
		options = append(options, restoreEventIngressOptionWithCustody(st, access))
		options = append(options, events.WithBackupHistoryAdmission(
			func(admitCtx context.Context, cut uint64, artifactDigest string, run func(context.Context) (int, error)) (int, error) {
				// Refuse an absent owner before opening a maintenance activity: this
				// path has definitely performed no raw write and must leave no
				// unresolved restore token behind.
				if err := st.RequireFullRestoreHistoryOwner(admitCtx, cut, artifactDigest); err != nil {
					return 0, err
				}
				var count int
				err := st.WithRestoreRawHistoryAdmission(admitCtx, func(ownerCtx context.Context) error {
					if err := st.RequireFullRestoreHistoryOwner(ownerCtx, cut, artifactDigest); err != nil {
						return err
					}
					var runErr error
					count, runErr = run(ownerCtx)
					return runErr
				})
				return count, err
			}))
	}
	var log *events.Log
	if sanitized {
		log, err = openSanitizedHistoryAwareEventLogWithRecovery(ctx, cfg.NATS, st, key, cfg.Secrets.SecretRotationHistoryFleetReady, func(recovery context.Context, source *events.Log) error {
			return protection.recoverPendingDestruction(recovery, st, source)
		}, options...)
		if err == nil {
			if verifyErr := protection.reader.VerifyCurrentCustody(ctx); verifyErr != nil {
				_ = log.Close()
				log = nil
				err = fmt.Errorf("verify current event-key custody: %w", verifyErr)
			}
		}
	} else {
		log, err = openHistoryAwareEventLog(ctx, cfg.NATS, st, key, options...)
	}
	if err != nil {
		_ = protection.Close()
		return nil, nil, err
	}
	return log, protection, nil
}

func restoreEventIngressOptionWithCustody(st *store.Store, access func() tenantseal.Access) events.OpenOption {
	return events.WithAppendAdmission(restoreEventIngressAdmissionWithCustody(st, access))
}

// CustodyValidatedEventIngressOption lets an isolated local harness use the
// production store-backed append admission with its own tenant custody. The
// caller must bootstrap the store's restore admission before opening the log.
func CustodyValidatedEventIngressOption(st *store.Store, access tenantseal.Access) events.OpenOption {
	return restoreEventIngressOptionWithCustody(st, func() tenantseal.Access { return access })
}

func restoreEventIngressAdmissionWithCustody(st *store.Store, access func() tenantseal.Access) events.AppendAdmission {
	return func(admitCtx context.Context, event events.Event,
		publish func(context.Context) (events.Event, error),
	) (events.Event, error) {
		var published events.Event
		err := st.WithRestoreEventIngress(admitCtx, event.TenantID, event.ID, event.Type,
			func(ownerCtx context.Context) error {
				var current tenantseal.Access
				if access != nil {
					current = access()
				}
				if current == nil {
					return store.RestoreActivityNoEffect(errProductionIngressCustodyUnavailable)
				}
				if err := validateSealedIngressCandidate(ownerCtx, current, event); err != nil {
					// No publication callback has run. Settle this exact ingress
					// start as proven no-effect so a rejected stale candidate cannot
					// block a later restore or key rotation indefinitely.
					return store.RestoreActivityNoEffect(err)
				}
				var publishErr error
				published, publishErr = publish(ownerCtx)
				return publishErr
			})
		return published, err
	}
}

// restoreEventIngressOptionsWithJournal is the store-backed producer, exact
// wire, and canonical readback stage. It is not attached to served construction
// until the separate command/projection token can settle after SQL commit.
type ingressJournalAttemptContextKey struct{}

type ingressJournalAttempt struct {
	eventID, tenantID, keyID string
	mac                      []byte
}

func restoreEventIngressOptionsWithJournal(st *store.Store, access func() tenantseal.Access,
	keys journalkey.Files,
) []events.OpenOption {
	return []events.OpenOption{
		events.WithIngressWireStage(func(ctx context.Context, _ events.Event, wireHash string) error {
			return st.StageEventIngressCandidateWire(ctx, wireHash)
		}),
		events.WithAppendAdmission(func(admitCtx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			if st.HasKeyStateOwnerContext(admitCtx) && !events.IngressHistoryReadPreheld(admitCtx) {
				return events.Event{}, store.ErrKeyStateOwnerUnavailable
			}
			var published events.Event
			mode := store.KeyStateShared
			if events.RequiresExclusiveKeyStateAdmission(event.Type) {
				mode = store.KeyStateExclusive
			}
			err := st.WithRestoreIngressSession(admitCtx, func(session context.Context) error {
				return st.WithGlobalKeyStateAdmission(session, mode, func(keyState context.Context) error {
					return events.WithIngressHistoryRead(keyState, func(history context.Context) error {
						return st.WithRestoreEventIngress(history, event.TenantID, event.ID, event.Type,
							func(ownerCtx context.Context) error {
								var current tenantseal.Access
								if access != nil {
									current = access()
								}
								if current == nil {
									return store.RestoreActivityNoEffect(errProductionIngressCustodyUnavailable)
								}
								if err := validateSealedIngressCandidate(ownerCtx, current, event); err != nil {
									return store.RestoreActivityNoEffect(err)
								}
								var commitment store.EventIngressProducerCommitment
								err := keys.WithActiveKey(func(keyID string, key []byte) error {
									mac, explicitTime, macErr := events.IngressProducerMAC(ownerCtx, key, keyID, event)
									if macErr != nil {
										return macErr
									}
									commitment = store.EventIngressProducerCommitment{
										TenantScope: event.TenantID, EventID: event.ID, EventType: event.Type,
										KeyID: keyID, MAC: mac, ExplicitTime: explicitTime,
									}
									return st.StageEventIngressProducer(ownerCtx, commitment)
								})
								if err != nil {
									// No producer row means no publication path was entered. A
									// failed SQL stage may be ambiguous, so only a missing key or
									// invalid producer view is proven no effect here.
									if commitment.EventID == "" {
										return store.RestoreActivityNoEffect(err)
									}
									return err
								}
								defer secret.Wipe(commitment.MAC)
								var publishErr error
								published, publishErr = publish(context.WithValue(ownerCtx,
									ingressJournalAttemptContextKey{}, &ingressJournalAttempt{
										eventID: event.ID, tenantID: event.TenantID,
										keyID: commitment.KeyID, mac: commitment.MAC,
									}))
								if publishErr != nil {
									if noPublicationErr := st.VerifyEventIngressNoPublication(ownerCtx); noPublicationErr == nil {
										return store.RestoreActivityNoEffect(publishErr)
									}
								}
								return publishErr
							})
					})
				})
			})
			return published, err
		}),
		events.WithIngressCanonicalProof(func(ctx context.Context, candidate, canonical events.Event,
			canonicalWireHash string, duplicate bool,
		) error {
			attempt, ok := ctx.Value(ingressJournalAttemptContextKey{}).(*ingressJournalAttempt)
			if !ok || attempt == nil || candidate.ID != attempt.eventID ||
				candidate.TenantID != attempt.tenantID || canonical.ID != attempt.eventID ||
				canonical.TenantID != attempt.tenantID {
				return store.ErrRestoreActivityUnresolved
			}
			if err := keys.WithKey(attempt.keyID, func(key []byte) error {
				producerMAC, _, err := events.IngressProducerMAC(ctx, key, attempt.keyID, candidate)
				if err != nil {
					return err
				}
				defer secret.Wipe(producerMAC)
				if !crypto.ConstantTimeEqual(producerMAC, attempt.mac) {
					return store.ErrRestoreActivityUnresolved
				}
				canonicalMAC, _, err := events.IngressCanonicalProducerMAC(ctx, key, attempt.keyID, canonical)
				if err != nil {
					return err
				}
				defer secret.Wipe(canonicalMAC)
				if (!duplicate || candidate.Protection != nil || canonical.Protection != nil) &&
					!crypto.ConstantTimeEqual(producerMAC, canonicalMAC) {
					return store.ErrRestoreActivityUnresolved
				}
				return nil
			}); err != nil {
				return err
			}
			return st.VerifyEventIngressCanonical(ctx, canonicalWireHash, canonical.Sequence, duplicate)
		}),
	}
}
