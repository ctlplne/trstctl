// SPDX-License-Identifier: BUSL-1.1

package reportarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

// Archive is where scheduled report artifacts are kept: the private
// directory (Dir), the object store under each tenant's prefix (Objects), or
// both while an operator moves from one to the other. New artifacts go to the
// object store when it is set; a read follows the reference the run recorded,
// so artifacts written to the directory stay readable after the move.
type Archive struct {
	Dir     Dir
	Objects objectstore.Store
}

// Configured reports whether the archive can keep new artifacts.
func (a Archive) Configured() bool { return a.Objects != nil || a.Dir.Root != "" }

// Ready is the effect-free readiness check behind scheduled-report previews.
func (a Archive) Ready() error {
	if a.Objects != nil {
		return nil
	}
	return a.Dir.ValidateRoot()
}

// Put stores exact JSON wire bytes once and returns the reference to record.
func (a Archive) Put(ctx context.Context, tenantID, runID string, artifact []byte) (ref, digest string, err error) {
	if a.Objects == nil {
		return a.Dir.Put(tenantID, runID, artifact)
	}
	if len(artifact) > MaxArtifactBytes {
		return "", "", ErrArtifactTooLarge
	}
	if !json.Valid(artifact) {
		return "", "", errors.New("reportarchive: signed report is not JSON")
	}
	digest = crypto.SHA256Hex(artifact)
	if _, err := Reference(tenantID, runID, digest); err != nil {
		return "", "", err
	}
	view, err := objectstore.ForTenant(ctx, a.Objects, tenantID)
	if err != nil {
		return "", "", err
	}
	rel := objectRelative(runID, digest)
	ref, err = view.Create(ctx, rel, bytes.NewReader(artifact), int64(len(artifact)), crypto.SHA256Sum(artifact))
	switch {
	case errors.Is(err, objectstore.ErrExists):
		// A retry after a crash, or a replica that produced the same run: the
		// name carries the digest, so the stored bytes must be these bytes.
		existing, readErr := a.readObject(ctx, ref, digest)
		if readErr != nil || !bytes.Equal(existing, artifact) {
			return "", "", errors.New("reportarchive: existing artifact differs from signed bytes")
		}
	case err != nil:
		return "", "", err
	}
	return ref, digest, nil
}

// Read returns the artifact a completed run recorded, verified against its
// digest, from wherever the run's reference says it was written.
func (a Archive) Read(ctx context.Context, ref, tenantID, runID, digest string) ([]byte, error) {
	if !ValidReference(ref, tenantID, runID, digest) {
		return nil, errors.New("reportarchive: reference does not match the run")
	}
	if IsDirectoryReference(ref) {
		return a.Dir.Read(tenantID, runID, digest)
	}
	if a.Objects == nil {
		return nil, errors.New("reportarchive: the artifact is in the object store, which is not configured")
	}
	return a.readObject(ctx, ref, digest)
}

// FindRun recovers an archived candidate after a crash between Put and the
// completion event, from the target new artifacts go to.
func (a Archive) FindRun(ctx context.Context, tenantID, runID string) (ref, digest string, artifact []byte, err error) {
	if a.Objects == nil {
		return a.Dir.FindRun(tenantID, runID)
	}
	if _, err = Reference(tenantID, runID, strings.Repeat("0", 64)); err != nil {
		return "", "", nil, err
	}
	view, err := objectstore.ForTenant(ctx, a.Objects, tenantID)
	if err != nil {
		return "", "", nil, err
	}
	listed, err := view.List(ctx, "reports/"+runID+"/", 2)
	if err != nil {
		return "", "", nil, err
	}
	switch len(listed) {
	case 0:
		return "", "", nil, fmt.Errorf("reportarchive: no archived artifact for run %s: %w", runID, os.ErrNotExist)
	case 1:
	default:
		return "", "", nil, errors.New("reportarchive: multiple signed artifacts for one run")
	}
	ref = listed[0].Name
	name := strings.TrimPrefix(ref, view.Prefix()+"reports/"+runID+"/")
	digest = strings.TrimSuffix(name, ".json")
	if !digestPattern.MatchString(digest) || name != digest+".json" {
		return "", "", nil, errors.New("reportarchive: malformed artifact for run")
	}
	artifact, err = a.readObject(ctx, ref, digest)
	if err != nil {
		return "", "", nil, err
	}
	return ref, digest, artifact, nil
}

func (a Archive) readObject(ctx context.Context, name, digest string) ([]byte, error) {
	var buf bytes.Buffer
	obj, err := a.Objects.Get(ctx, name, &buf, MaxArtifactBytes)
	if errors.Is(err, objectstore.ErrTooLarge) {
		return nil, ErrArtifactTooLarge
	}
	if err != nil {
		return nil, err
	}
	data := buf.Bytes()
	if !json.Valid(data) || !strings.EqualFold(obj.SHA256, digest) {
		return nil, errors.New("reportarchive: artifact failed digest or JSON validation")
	}
	return data, nil
}

// IsDirectoryReference reports whether a run's reference names the archive
// directory rather than the object store.
func IsDirectoryReference(ref string) bool { return strings.HasPrefix(ref, "reports/") }

func objectRelative(runID, digest string) string {
	return "reports/" + runID + "/" + digest + ".json"
}

// ValidReference reports whether ref is where a completed run's artifact
// lives: the directory form reports/<tenant>/<run>/<sha256>.json, or the
// object form under the tenant's object prefix, tenant/<tenant>/ or
// silo/<tenant>/ followed by reports/<run>/<sha256>.json.
func ValidReference(ref, tenantID, runID, digest string) bool {
	want, err := Reference(tenantID, runID, digest)
	if err != nil {
		return false
	}
	rel := objectRelative(runID, digest)
	return ref == want || ref == "tenant/"+tenantID+"/"+rel || ref == "silo/"+strings.ToLower(tenantID)+"/"+rel
}
