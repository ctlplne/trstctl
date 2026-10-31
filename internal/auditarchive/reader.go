// SPDX-License-Identifier: BUSL-1.1

// Package auditarchive reads a tenant's own archived audit segments (A234). It
// is core: tenant audit/export rights are never license-gated, and it imports
// nothing from ee/. The commercial retention worker writes the segments; this
// package only finds them through the tenant's audit.archived events, rebuilds
// the locator the configured archive would have used, and verifies the bytes
// as that tenant's signed retention segment before returning them.
package auditarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
)

// MaxSegmentBytes matches the archivers' read-back bound.
const MaxSegmentBytes = 4 << 20

var (
	// ErrNotFound: no audit.archived event of this tenant has this ID.
	ErrNotFound = errors.New("auditarchive: segment not found")
	// ErrUnavailable: the segment exists but cannot be served to the tenant —
	// its locator is not this deployment's archive location for the tenant, the
	// bytes are missing or oversized, or they do not verify as this tenant's
	// signed retention segment. A custodian fetches it.
	ErrUnavailable = errors.New("auditarchive: segment is not available for tenant download")
)

// Segment describes one archived segment without its locator.
type Segment struct {
	ID               string
	FirstRecord      int
	LastRecord       int
	BoundarySequence uint64
	ChainHead        string
	ArchivedAt       time.Time
}

// Release is one verified segment.
type Release struct {
	Segment
	Signed string
	Bundle audit.Bundle
}

// Reader reads one deployment's archive. Dir and Objects are the configured
// archive targets; either may be empty.
type Reader struct {
	Log     *events.Log
	Keys    func() *jose.JWKSet
	Dir     string
	Objects objectstore.Store
}

// List returns the tenant's v2 segments, oldest first.
func (r Reader) List(ctx context.Context, tenantID string) ([]Segment, error) {
	var out []Segment
	err := r.each(ctx, tenantID, func(s Segment, _ audit.ArchivedEvent) error {
		out = append(out, s)
		return nil
	})
	return out, err
}

// Read returns the verified segment the tenant's archived event names.
func (r Reader) Read(ctx context.Context, tenantID, segmentID string) (Release, error) {
	var hit *Segment
	var payload audit.ArchivedEvent
	if err := r.each(ctx, tenantID, func(s Segment, p audit.ArchivedEvent) error {
		if s.ID == segmentID {
			matched := s
			hit, payload = &matched, p
		}
		return nil
	}); err != nil {
		return Release{}, err
	}
	if hit == nil {
		return Release{}, ErrNotFound
	}
	signed, err := r.stored(ctx, tenantID, payload)
	if err != nil {
		return Release{}, errors.Join(ErrUnavailable, err)
	}
	if r.Keys == nil {
		return Release{}, errors.Join(ErrUnavailable, errors.New("no audit verification keys"))
	}
	bundle, err := audit.VerifyRetentionBundle(signed, r.Keys())
	if err != nil {
		return Release{}, errors.Join(ErrUnavailable, err)
	}
	if bundle.TenantID != tenantID || bundle.ChainHead != payload.BoundaryHash || len(bundle.Records) == 0 || payload.Count <= 0 ||
		bundle.Records[len(bundle.Records)-1].Sequence != uint64(payload.Count) { // #nosec G115 -- positive count checked first (CWE-190)
		return Release{}, errors.Join(ErrUnavailable, errors.New("stored segment is not this tenant's archived segment"))
	}
	release := Release{Segment: *hit, Signed: signed, Bundle: bundle}
	// The verified bundle is contiguous and ends at the positive int count, so
	// its first record fits an int.
	release.FirstRecord = int(bundle.Records[0].Sequence) // #nosec G115 -- bounded by the int count above (CWE-190)
	return release, nil
}

func (r Reader) each(ctx context.Context, tenantID string, visit func(Segment, audit.ArchivedEvent) error) error {
	if r.Log == nil {
		return errors.New("auditarchive: no event log")
	}
	// previous is the cumulative count the last v2 segment ended at; after a
	// legacy v1 segment (segment-local count) the next start is unknown and is
	// reported as 0 until the downloaded bundle names it.
	previous, known := 0, true
	return r.Log.WithHistoryRead(ctx, func(read context.Context) error {
		head, err := r.Log.LastSequence(read)
		if err != nil {
			return err
		}
		return r.Log.ReplayTenantMetadataTypesThrough(read, tenantID, 1, head, []string{audit.EventTypeArchived}, func(meta events.EnvelopeMetadata) error {
			if meta.SchemaVersion != audit.ArchivedEventSchemaVersion {
				known = false
				return nil // legacy segment-local coordinates stay custodian-only
			}
			event, found, err := r.Log.EventAtSequence(read, meta.Sequence)
			if err != nil {
				return err
			}
			if !found || event.ID != meta.ID {
				return errors.New("auditarchive: retained segment event is unreadable")
			}
			var payload audit.ArchivedEvent
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return err
			}
			segment := Segment{ID: meta.ID, LastRecord: payload.Count,
				BoundarySequence: payload.BoundarySeq, ChainHead: payload.BoundaryHash, ArchivedAt: meta.Time.UTC()}
			if known {
				segment.FirstRecord = previous + 1
			}
			previous, known = payload.Count, true
			return visit(segment, payload)
		})
	})
}

// stored reads only from the locator the configured archive writes for this
// tenant and boundary; a retained locator that differs is refused unread.
func (r Reader) stored(ctx context.Context, tenantID string, payload audit.ArchivedEvent) (string, error) {
	name := fmt.Sprintf("audit-%020d.jws", payload.Count)
	if r.Objects != nil {
		view, err := objectstore.ForTenant(ctx, r.Objects, tenantID)
		if err != nil {
			return "", err
		}
		full, err := view.Name("audit/" + name)
		if err != nil {
			return "", err
		}
		if r.Objects.Location(full) == payload.ArchiveURI {
			var buf bytes.Buffer
			if _, err := view.Get(ctx, "audit/"+name, &buf, MaxSegmentBytes); err != nil {
				return "", err
			}
			return buf.String(), nil
		}
	}
	if r.Dir != "" {
		expected := filepath.Join(r.Dir, tenantID, name)
		if payload.ArchiveURI == expected {
			if info, err := os.Lstat(expected); err != nil || !info.Mode().IsRegular() {
				return "", errors.Join(errors.New("stored segment is not a regular file"), err)
			}
			file, err := os.Open(expected) // #nosec G304 -- rebuilt from the configured archive dir, tenant and boundary (CWE-22)
			if err != nil {
				return "", err
			}
			defer func() { _ = file.Close() }()
			info, err := file.Stat()
			if err != nil {
				return "", err
			}
			if !info.Mode().IsRegular() || info.Size() > MaxSegmentBytes {
				return "", errors.New("stored segment is not a bounded regular file")
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(file); err != nil {
				return "", err
			}
			return buf.String(), nil
		}
	}
	return "", errors.New("retained locator is not this deployment's archive location for the tenant")
}
