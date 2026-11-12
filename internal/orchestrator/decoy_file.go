// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"path"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// decoyFileNamespace keys a decoy file's id by tenant, host, path and key, so
// an agent reporting the same planted file again names the same decoy.
var decoyFileNamespace = uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl/decoy-file"))

// DecoyFileID is the id of the decoy for the key with fingerprint planted at
// filePath on host.
func DecoyFileID(tenantID, host, filePath, fingerprint string) string {
	return uuid.NewSHA1(decoyFileNamespace, []byte(tenantID+"\x00"+host+"\x00"+filePath+"\x00"+fingerprint)).String()
}

// RegisterDecoyFile records a decoy file a host agent planted (Q6-O1): an SSH
// private key at filePath on host, identified by its public half's
// fingerprint. The same file reported again is the same decoy (registered is
// false). A new key planted at a path retires the decoy of the key that was
// there, since the file it watched is gone.
func (o *Orchestrator) RegisterDecoyFile(ctx context.Context, tenantID, host, filePath, fingerprint string) (h store.HoneyToken, registered bool, err error) {
	id := DecoyFileID(tenantID, host, filePath, fingerprint)
	if h, err = o.store.GetHoneyToken(ctx, tenantID, id); err == nil {
		return h, false, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return store.HoneyToken{}, false, err
	}
	previous, err := o.store.LiveDecoyFileIDs(ctx, tenantID, host, filePath)
	if err != nil {
		return store.HoneyToken{}, false, err
	}
	payload, err := json.Marshal(projections.HoneyTokenCreated{
		ID: id, Name: truncateRunes("decoy file "+path.Base(filePath), 128), Placement: truncateRunes(host+":"+filePath, 256),
		TokenHash: "file-decoy:" + id, FileHost: host, FilePath: filePath, FileKeyFingerprint: fingerprint,
	})
	if err != nil {
		return store.HoneyToken{}, false, err
	}
	if _, err := o.emit(ctx, projections.EventHoneyTokenCreated, tenantID, payload); err != nil {
		return store.HoneyToken{}, false, err
	}
	for _, old := range previous {
		if old != id {
			if err := o.RevokeHoneyToken(ctx, tenantID, old); err != nil {
				return store.HoneyToken{}, false, err
			}
		}
	}
	h, err = o.store.GetHoneyToken(ctx, tenantID, id)
	return h, err == nil, err
}

// RecordDecoyFileOpened records that reader — the opening program, named with
// its host — opened a decoy file. The projection keeps the first reader and
// alerts once per distinct program, as for a decoy secret's readers.
func (o *Orchestrator) RecordDecoyFileOpened(ctx context.Context, tenantID, id, reader, method, filePath string) error {
	return o.RecordDecoySecretRead(ctx, tenantID, id, reader, method, filePath)
}

// truncateRunes keeps at most n characters of s.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
