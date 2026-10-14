// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcilePendingCertificateRevocationAuthority recovers the first exact
// command. A missing broker ACK cannot release issuer status denial or mint a
// replacement revocation event.
func reconcilePendingCertificateRevocationAuthority(ctx context.Context, st *store.Store, log *events.Log) (int, error) {
	if st == nil || log == nil {
		return 0, fmt.Errorf("server: certificate revocation recovery needs store and event log")
	}
	healed := 0
	var afterTenant, afterEvent string
	for {
		keys, err := st.PendingCertificateRevocationKeysSystem(ctx, afterTenant, afterEvent, 100)
		if err != nil {
			return healed, err
		}
		if len(keys) == 0 {
			return healed, nil
		}
		for _, key := range keys {
			err := st.WithPrivacyRecoveryBarrier(ctx, key[0], "certificate revocation authority recovery", func(barrierCtx context.Context) error {
				command, err := st.CertificateRevocationAuthorityCommandByEventID(barrierCtx, key[0], key[1])
				if err != nil {
					return err
				}
				if command.Status != "pending" {
					return nil
				}
				retained, found, err := log.EventByID(barrierCtx, command.Event.ID)
				if err != nil {
					return err
				}
				if !found {
					retained, err = log.Append(barrierCtx, command.Event)
					if err != nil {
						return err
					}
				}
				if retained.ID != command.Event.ID || retained.TenantID != command.Event.TenantID ||
					retained.Type != command.Event.Type || retained.SchemaVersion != command.Event.SchemaVersion ||
					!retained.Time.Equal(command.Event.Time) || !bytes.Equal(retained.Data, command.Event.Data) {
					return fmt.Errorf("server: certificate revocation %s differs from first command", key[1])
				}
				return projections.New(st).Apply(barrierCtx, retained)
			})
			if err != nil {
				return healed, fmt.Errorf("server: recover certificate revocation %s: %w", key[1], err)
			}
			healed++
		}
		last := keys[len(keys)-1]
		afterTenant, afterEvent = last[0], last[1]
	}
}
