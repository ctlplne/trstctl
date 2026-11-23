// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/store"
)

// CheckRecordingUploadsSettled refuses a key change while a chunk object has
// been created but its immutable stored event has not yet been projected. The
// ordinary outbox worker can finish that exact upload before the next retry.
// An absent object is safe: its staged bytes are rewrapped in PostgreSQL.
func CheckRecordingUploadsSettled(ctx context.Context, st *store.Store, objects objectstore.Store, tenantID string) error {
	afterSession, afterOrd := "", -1
	var view objectstore.Tenant
	for {
		uploads, err := st.ListPAMRecordingUploadsForRewrap(ctx, tenantID, afterSession, afterOrd, 64)
		if err != nil {
			return err
		}
		if len(uploads) == 0 {
			return nil
		}
		if objects == nil {
			return errors.New("tenantseal: staged recordings exist but the object store is unavailable")
		}
		if view.TenantID() == "" {
			view, err = objectstore.ForTenant(ctx, objects, tenantID)
			if err != nil {
				return err
			}
		}
		for _, u := range uploads {
			rel := "recordings/" + u.SessionID + "/" + strconv.Itoa(u.Ord) + "-" + strconv.Itoa(u.Attempt) + "-" + strconv.Itoa(u.Seq)
			if _, err := view.Head(ctx, rel); err == nil {
				return fmt.Errorf("tenantseal: recording %s chunk %d object upload must finish before key rewrap", u.SessionID, u.Ord)
			} else if !errors.Is(err, objectstore.ErrNotFound) {
				return err
			}
		}
		last := uploads[len(uploads)-1]
		afterSession, afterOrd = last.SessionID, last.Ord
	}
}

// RewrapRecordingObjects moves the data key of every immutable recording
// object. Only a small envelope header is stored in PostgreSQL; the signed
// object, its digest, payload ciphertext, and manifest remain unchanged.
// Every object is read and checked on each pass, including verification.
func RewrapRecordingObjects(ctx context.Context, st *store.Store, objects objectstore.Store, tenantID string,
	transform func(string, int, []byte) ([]byte, bool, error),
	apply func(context.Context, store.PAMRecordingChunk, []byte) error) (changed, checked int64, err error) {
	if st == nil || tenantID == "" || transform == nil || apply == nil {
		return 0, 0, errors.New("tenantseal: recording rewrap is not configured")
	}
	var view objectstore.Tenant
	afterSession, afterOrd := "", -1
	for {
		chunks, err := st.ListPAMRecordingChunksForRewrap(ctx, tenantID, afterSession, afterOrd, 64)
		if err != nil {
			return changed, checked, err
		}
		if len(chunks) == 0 {
			return changed, checked, nil
		}
		if objects == nil {
			return changed, checked, errors.New("tenantseal: recording objects exist but the object store is unavailable")
		}
		if view.TenantID() == "" {
			view, err = objectstore.ForTenant(ctx, objects, tenantID)
			if err != nil {
				return changed, checked, err
			}
		}
		for _, c := range chunks {
			if !view.Contains(c.ObjectRef) {
				return changed, checked, fmt.Errorf("tenantseal: recording object is outside tenant %s prefix", tenantID)
			}
			var original bytes.Buffer
			if _, err := view.Get(ctx, strings.TrimPrefix(c.ObjectRef, view.Prefix()), &original, 2<<20); err != nil {
				return changed, checked, fmt.Errorf("tenantseal: read recording %s chunk %d: %w", c.SessionID, c.Ord, err)
			}
			if crypto.SHA256Hex(original.Bytes()) != c.SealedSHA256 {
				return changed, checked, fmt.Errorf("tenantseal: recording %s chunk %d object digest mismatch", c.SessionID, c.Ord)
			}
			current := original.Bytes()
			if len(c.RewrapHeader) > 0 {
				current, err = seal.ApplyContainerHeader(current, c.RewrapHeader)
				if err != nil {
					return changed, checked, err
				}
			}
			next, rewrite, err := transform("objectstore.pam_session_recording_chunks", 1, current)
			if err != nil {
				return changed, checked, fmt.Errorf("tenantseal: rewrap recording %s chunk %d: %w", c.SessionID, c.Ord, err)
			}
			checked++
			if !rewrite {
				if !bytes.Equal(next, current) {
					return changed, checked, errors.New("tenantseal: unchanged recording rewrap returned different bytes")
				}
				continue
			}
			header, err := seal.ContainerHeader(next)
			if err != nil {
				return changed, checked, err
			}
			if err := apply(ctx, c, header); err != nil {
				return changed, checked, err
			}
			changed++
		}
		last := chunks[len(chunks)-1]
		afterSession, afterOrd = last.SessionID, last.Ord
	}
}
