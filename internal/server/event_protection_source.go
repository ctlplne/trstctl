// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// openConfiguredEventSource creates exactly one custodian before any Open
// recovery can read protected history. The caller closes log, then custody,
// then signer, after all dispatch/projection workers have stopped. Even an
// empty directory setting attaches fail-closed readers for protected source.
func openConfiguredEventSource(ctx context.Context, cfg *config.Config, st *store.Store, key *jose.SigningKey, sanitized bool, backupRoots []string, extra ...events.OpenOption) (*events.Log, *eventProtectionRuntime, error) {
	protection, err := newEventProtectionRuntime(cfg, st, key, backupRoots...)
	if err != nil {
		return nil, nil, fmt.Errorf("configure event protection: %w", err)
	}
	options := append(protection.openOptions(), extra...)
	var log *events.Log
	if sanitized {
		log, err = openSanitizedHistoryAwareEventLog(ctx, cfg.NATS, st, key, cfg.Secrets.SecretRotationHistoryFleetReady, options...)
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
