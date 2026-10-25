// SPDX-License-Identifier: BUSL-1.1

// Package objectstore is the control plane's client for an S3-compatible
// object store (AWS S3, MinIO, or another service that speaks the S3 API). It
// is the durable target for signed audit archive segments, scheduled report
// and evidence-pack artifacts, and full backup sets.
//
// Three rules hold for every caller:
//
//   - Objects are created, never replaced. Create sends a conditional write
//     (If-None-Match: *), so the store itself refuses to overwrite an object;
//     the caller gets ErrExists and compares digests instead of replacing
//     evidence. `trstctl doctor --write-probe` checks that the configured
//     store enforces this.
//   - Every tenant-owned object lives under that tenant's object prefix
//     (tenancy.ObjectPrefix). A Tenant view resolves the prefix once and
//     addresses only names inside it. Callers record the full object name they
//     wrote rather than re-deriving it later, because the Provider can move a
//     tenant between isolation models and its prefix changes with the model.
//   - Calls are bounded (AN-7). Each runs under its own deadline, scaled with
//     its payload, and a store refuses a call outright with ErrBusy once
//     MaxInFlight calls are already running, so a slow endpoint stalls only its
//     own callers and an API request that reads an artifact fails fast.
//
// Writes happen in background workers and one-shot commands, as a
// precondition of the state change that records them: an audit segment is
// archived before its checkpoint advances, a report artifact is stored before
// its run completes, and a backup set's manifest is uploaded last. A crash
// between the write and the state change repeats the write, which the
// conditional create turns into a digest comparison, never a second copy.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"trstctl.com/trstctl/internal/tenancy"
)

// Errors a caller can act on. They wrap the transport's own error where there
// is one, so errors.Is works and the detail is kept.
var (
	ErrNotFound = errors.New("objectstore: object not found")
	ErrExists   = errors.New("objectstore: an object already exists at this name")
	ErrTooLarge = errors.New("objectstore: object exceeds the caller's size limit")
	ErrBusy     = errors.New("objectstore: too many object-store calls in flight")
	ErrDigest   = errors.New("objectstore: object bytes do not match their digest")
	ErrName     = errors.New("objectstore: invalid object name")
)

// maxKeyBytes is S3's limit on a full object key (deployment root included).
const maxKeyBytes = 1024

// Object describes one stored object. Name is relative to the deployment root
// configured for the store; SHA256 is lowercase hex when known.
type Object struct {
	Name   string
	Size   int64
	SHA256 string
}

// Store is the object API the product uses. Names are relative to the
// deployment root and must be clean relative paths (ValidName).
type Store interface {
	// Create writes body (size bytes, whose SHA-256 is sha256) only if no object
	// exists at name. The store verifies the digest on receipt. An existing
	// object yields ErrExists and is left untouched.
	Create(ctx context.Context, name string, body io.ReadSeeker, size int64, sha256 []byte) error
	// Get streams the object into w, refusing one larger than limit bytes, and
	// returns its size and the SHA-256 of the bytes actually received.
	Get(ctx context.Context, name string, w io.Writer, limit int64) (Object, error)
	// Head returns the object's size and, when the store reports one, its
	// SHA-256.
	Head(ctx context.Context, name string) (Object, error)
	// List returns up to limit objects whose names start with prefix, in name
	// order. It returns an error rather than a silently truncated list when
	// more than limit objects match.
	List(ctx context.Context, prefix string, limit int) ([]Object, error)
	// Delete removes one object. Deleting a missing object is not an error.
	Delete(ctx context.Context, name string) error
	// Location is the stable locator recorded for name: s3://bucket/key.
	Location(name string) string
	// NameOf parses a locator this store produced back into a name, refusing
	// one for another bucket or outside the deployment root.
	NameOf(location string) (string, error)
}

// ValidName reports whether name is a clean relative object name: no leading
// slash, no empty, "." or ".." segment, no backslash, and no control bytes.
// A trailing slash is accepted only when allowTrailingSlash is set (list
// prefixes and tenant prefixes).
func ValidName(name string, allowTrailingSlash bool) error {
	if name == "" || len(name) > maxKeyBytes {
		return fmt.Errorf("%w: %q must be 1-%d bytes", ErrName, name, maxKeyBytes)
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("%w: %q must be a relative slash-separated path", ErrName, name)
	}
	for _, b := range []byte(name) {
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("%w: %q contains a control byte", ErrName, name)
		}
	}
	trimmed := name
	if allowTrailingSlash {
		trimmed = strings.TrimSuffix(name, "/")
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: %q has an empty, \".\" or \"..\" segment", ErrName, name)
		}
	}
	return nil
}

// Tenant is a view of a Store confined to one tenant's object prefix. Every
// name it accepts is relative to that prefix, so it cannot address another
// tenant's objects.
type Tenant struct {
	store    Store
	tenantID string
	prefix   string
}

// ForTenant resolves tenantID's object prefix once, through the tenancy
// router: tenant/<id>/ for a pooled tenant, silo/<id>/ for one the Provider
// isolates. The prefix must be a clean relative prefix that names this tenant;
// anything else is refused, so a misrouted lookup cannot place one tenant's
// objects under another tenant's prefix.
func ForTenant(ctx context.Context, store Store, tenantID string) (Tenant, error) {
	if store == nil {
		return Tenant{}, errors.New("objectstore: no object store is configured")
	}
	if tenantID == "" || strings.ContainsAny(tenantID, "/\\") || tenantID == "." || tenantID == ".." {
		return Tenant{}, fmt.Errorf("%w: tenant %q is not a single path segment", ErrName, tenantID)
	}
	prefix, err := tenancy.ObjectPrefix(ctx, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	if err := ValidName(prefix, true); err != nil || !strings.HasSuffix(prefix, "/") {
		return Tenant{}, fmt.Errorf("%w: tenant %s resolved to the malformed prefix %q", ErrName, tenantID, prefix)
	}
	if !strings.Contains("/"+strings.ToLower(prefix), "/"+strings.ToLower(tenantID)+"/") {
		return Tenant{}, fmt.Errorf("%w: tenant %s resolved to the prefix %q, which does not name it", ErrName, tenantID, prefix)
	}
	return Tenant{store: store, tenantID: tenantID, prefix: prefix}, nil
}

// TenantID is the tenant this view is confined to.
func (t Tenant) TenantID() string { return t.tenantID }

// Prefix is the tenant's object prefix, relative to the deployment root.
func (t Tenant) Prefix() string { return t.prefix }

// Name returns the store name for rel inside the tenant's prefix.
func (t Tenant) Name(rel string) (string, error) {
	if t.store == nil {
		return "", errors.New("objectstore: tenant view is not initialized")
	}
	if err := ValidName(rel, false); err != nil {
		return "", err
	}
	name := t.prefix + rel
	if err := ValidName(name, false); err != nil {
		return "", err
	}
	return name, nil
}

// Contains reports whether a store name lies inside the tenant's prefix.
func (t Tenant) Contains(name string) bool {
	return t.prefix != "" && strings.HasPrefix(name, t.prefix) && ValidName(name, false) == nil
}

// Create writes rel inside the tenant's prefix (see Store.Create) and returns
// the full store name to record.
func (t Tenant) Create(ctx context.Context, rel string, body io.ReadSeeker, size int64, sha256 []byte) (string, error) {
	name, err := t.Name(rel)
	if err != nil {
		return "", err
	}
	return name, t.store.Create(ctx, name, body, size, sha256)
}

// Get reads rel inside the tenant's prefix (see Store.Get).
func (t Tenant) Get(ctx context.Context, rel string, w io.Writer, limit int64) (Object, error) {
	name, err := t.Name(rel)
	if err != nil {
		return Object{}, err
	}
	return t.store.Get(ctx, name, w, limit)
}

// List lists the objects under relPrefix inside the tenant's prefix; an empty
// relPrefix lists the whole tenant prefix.
func (t Tenant) List(ctx context.Context, relPrefix string, limit int) ([]Object, error) {
	if t.store == nil {
		return nil, errors.New("objectstore: tenant view is not initialized")
	}
	prefix := t.prefix
	if relPrefix != "" {
		if err := ValidName(relPrefix, true); err != nil {
			return nil, err
		}
		prefix += relPrefix
	}
	return t.store.List(ctx, prefix, limit)
}

// Delete removes rel inside the tenant's prefix.
func (t Tenant) Delete(ctx context.Context, rel string) error {
	name, err := t.Name(rel)
	if err != nil {
		return err
	}
	return t.store.Delete(ctx, name)
}
