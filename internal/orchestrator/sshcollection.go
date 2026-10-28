// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshcollection"
)

// BoundSSHCollectionCommand refuses a SQL-only or altered queue command before
// any credential is opened or any public readback is imported.
func (o *Orchestrator) BoundSSHCollectionCommand(ctx context.Context, tenantID, eventID string, payload []byte) (sshcollection.Command, error) {
	var empty sshcollection.Command
	if o.log == nil {
		return empty, errors.New("SSH collection source log is unavailable")
	}
	event, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return empty, err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventSSHTrustCollectionQueued {
		return empty, errors.New("SSH collection job has no matching immutable source")
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		return empty, err
	}
	source, err := sshcollection.DecodeCommand(event.Data)
	if err != nil {
		return empty, err
	}
	candidate, err := sshcollection.DecodeCommand(payload)
	if err != nil {
		return empty, err
	}
	a, _ := source.Digest()
	b, _ := candidate.Digest()
	if a != b {
		return empty, errors.New("SSH collection job differs from its immutable source")
	}
	return source, nil
}
