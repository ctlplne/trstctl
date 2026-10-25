// SPDX-License-Identifier: BUSL-1.1

package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

const groupObjectStore = "object-store isolation (AN-1)"

// probeObjectLimit bounds every listing the object lane makes: residue under
// the reserved prefix is a handful of markers, never a bucket walk.
const probeObjectLimit = 100

// runObjectStoreProbes runs the object lane against the object store the
// deployment is configured with (object_store / TRSTCTL_OBJECT_STORE_*), the
// target of its audit archives, report artifacts and backup sets. It uses the
// same tenant-prefixed client those targets use, so the proof and the product
// cannot drift.
func runObjectStoreProbes(ctx context.Context, getenv func(string) string, writeProbe bool) []Probe {
	cfg, err := config.LoadObjectStore(getenv)
	if err != nil {
		return []Probe{{ID: "OBJ-LEAK", Group: groupObjectStore, Status: StatusFail,
			Detail: "the object_store configuration does not load: " + err.Error()}}
	}
	if !cfg.Configured() {
		skip := "no object store is configured (object_store or TRSTCTL_OBJECT_STORE_*); audit archives, report artifacts and backups use local directories"
		var out []Probe
		for _, id := range []string{"OBJ-LEAK", "OBJ-1", "OBJ-2", "OBJ-3"} {
			out = append(out, Probe{ID: id, Group: groupObjectStore, Status: StatusSkip, Detail: skip})
		}
		return out
	}
	store, err := objectstore.FromConfig(cfg)
	if err != nil {
		return []Probe{{ID: "OBJ-LEAK", Group: groupObjectStore, Status: StatusFail,
			Detail: "could not open the configured object store: " + err.Error()}}
	}
	defer store.Destroy()

	out := []Probe{objectResidueProbe(ctx, store, "OBJ-LEAK")}
	if !writeProbe {
		skip := "write probe not permitted (run with --write-probe for the full proof)"
		for _, id := range []string{"OBJ-1", "OBJ-2", "OBJ-3"} {
			out = append(out, Probe{ID: id, Group: groupObjectStore, Status: StatusSkip, Detail: skip})
		}
		return out
	}
	return append(out, runObjectWriteProbes(ctx, store)...)
}

// probeObjectPrefix is where every probe tenant's objects live: the pooled
// tenant prefix of an id under the reserved probe prefix.
func probeObjectPrefix() string { return "tenant/" + ProbeTenantPrefix }

func objectResidueProbe(ctx context.Context, store objectstore.Store, id string) Probe {
	residue, err := store.List(ctx, probeObjectPrefix(), probeObjectLimit)
	switch {
	case err != nil:
		return Probe{ID: id, Group: groupObjectStore, Status: StatusFail,
			Detail: "could not list the reserved probe prefix: " + err.Error()}
	case len(residue) > 0:
		return Probe{ID: id, Group: groupObjectStore, Status: StatusFail,
			Detail:   fmt.Sprintf("%d probe object(s) under %s — a prior doctor run did not clean up", len(residue), store.Location(probeObjectPrefix())),
			Evidence: map[string]any{"first": store.Location(residue[0].Name)}}
	}
	return Probe{ID: id, Group: groupObjectStore, Status: StatusPass,
		Detail: "no objects under the reserved probe prefix " + store.Location(probeObjectPrefix())}
}

// runObjectWriteProbes writes one marker under probe tenant A's prefix and
// tries to reach it as probe tenant B. Every probe object is deleted and the
// deletion verified afterward; failing to clean up is itself OBJ-CLEAN's FAIL.
func runObjectWriteProbes(ctx context.Context, store objectstore.Store) (out []Probe) {
	tenantA, tenantB := newProbeTenantID(), newProbeTenantID()
	defer func() { out = append(out, cleanObjectProbes(ctx, store, tenantA, tenantB)) }()

	viewA, errA := objectstore.ForTenant(ctx, store, tenantA)
	viewB, errB := objectstore.ForTenant(ctx, store, tenantB)
	if err := errors.Join(errA, errB); err != nil {
		return append(out, Probe{ID: "OBJ-1", Group: groupObjectStore, Status: StatusFail,
			Detail: "could not resolve the probe tenants' object prefixes: " + err.Error()})
	}
	rel := "doctor/marker-" + uuid.NewString()
	marker := []byte("trstctl doctor object-lane marker " + tenantA)

	// OBJ-1: the store round-trips a marker under tenant A's prefix.
	name, err := viewA.Create(ctx, rel, bytes.NewReader(marker), int64(len(marker)), crypto.SHA256Sum(marker))
	if err != nil {
		return append(out, Probe{ID: "OBJ-1", Group: groupObjectStore, Status: StatusFail,
			Detail: "could not write the probe marker as tenant A: " + err.Error()})
	}
	var readBack bytes.Buffer
	if obj, err := viewA.Get(ctx, rel, &readBack, int64(len(marker))+1); err != nil || !bytes.Equal(readBack.Bytes(), marker) {
		out = append(out, Probe{ID: "OBJ-1", Group: groupObjectStore, Status: StatusFail,
			Detail: fmt.Sprintf("the probe marker did not read back intact (err %v, %d bytes)", err, obj.Size)})
	} else {
		out = append(out, Probe{ID: "OBJ-1", Group: groupObjectStore, Status: StatusPass,
			Detail:   "a marker written under tenant A's prefix read back byte-for-byte with its SHA-256",
			Limits:   "proves this store accepts and returns an object under a tenant prefix with the deployment's credentials, not the store's durability or replication",
			Evidence: map[string]any{"location": store.Location(name), "prefix": viewA.Prefix(), "sha256": obj.SHA256}})
	}

	// OBJ-2: tenant B cannot list, read or name its way to A's marker.
	out = append(out, objectConfinementProbe(ctx, viewB, rel, name))

	// OBJ-3: the store refuses to replace the marker.
	other := []byte("trstctl doctor overwrite attempt " + tenantB)
	err = store.Create(ctx, name, bytes.NewReader(other), int64(len(other)), crypto.SHA256Sum(other))
	readBack.Reset()
	_, readErr := viewA.Get(ctx, rel, &readBack, int64(len(marker)+len(other)))
	switch {
	case errors.Is(err, objectstore.ErrExists) && readErr == nil && bytes.Equal(readBack.Bytes(), marker):
		out = append(out, Probe{ID: "OBJ-3", Group: groupObjectStore, Status: StatusPass,
			Detail: "the store refused a second write to an existing object and kept the original bytes",
			Limits: "proves the store honors a conditional (If-None-Match) write, not that the bucket has object lock or retention configured"})
	case err == nil:
		out = append(out, Probe{ID: "OBJ-3", Group: groupObjectStore, Status: StatusFail,
			Detail: "the store accepted an overwrite of an existing object: it ignores conditional writes, so audit archives and report artifacts written to it could be overwritten"})
	default:
		out = append(out, Probe{ID: "OBJ-3", Group: groupObjectStore, Status: StatusFail,
			Detail: fmt.Sprintf("the overwrite attempt ended with %v and the marker reads back as err=%v", err, readErr)})
	}
	return out
}

func objectConfinementProbe(ctx context.Context, viewB objectstore.Tenant, rel, nameA string) Probe {
	listed, err := viewB.List(ctx, "", probeObjectLimit)
	if err != nil {
		return Probe{ID: "OBJ-2", Group: groupObjectStore, Status: StatusFail, Detail: "could not list tenant B's prefix: " + err.Error()}
	}
	for _, obj := range listed {
		if obj.Name == nameA || !viewB.Contains(obj.Name) {
			return Probe{ID: "OBJ-2", Group: groupObjectStore, Status: StatusFail,
				Detail: fmt.Sprintf("tenant B's listing returned %s, outside its prefix %s", obj.Name, viewB.Prefix())}
		}
	}
	if _, err := viewB.Get(ctx, rel, &bytes.Buffer{}, 1<<10); !errors.Is(err, objectstore.ErrNotFound) {
		return Probe{ID: "OBJ-2", Group: groupObjectStore, Status: StatusFail,
			Detail: fmt.Sprintf("tenant B reading A's relative name returned %v, want not found under B's own prefix", err)}
	}
	for _, climb := range []string{"../" + nameA, "/" + nameA, "doctor/../../" + nameA} {
		if _, err := viewB.Get(ctx, climb, &bytes.Buffer{}, 1<<10); !errors.Is(err, objectstore.ErrName) {
			return Probe{ID: "OBJ-2", Group: groupObjectStore, Status: StatusFail,
				Detail: fmt.Sprintf("tenant B's name %q was not refused before reaching the store (err %v)", climb, err)}
		}
	}
	return Probe{ID: "OBJ-2", Group: groupObjectStore, Status: StatusPass,
		Detail: fmt.Sprintf("tenant B listed %d objects under its own prefix, could not read A's marker by its relative name, and every name climbing out of its prefix was refused before reaching the store", len(listed)),
		Limits: "proves the product confines each tenant's object names to its prefix on this store; the deployment's credential can still read every prefix in the bucket, so isolation at the storage layer needs per-prefix bucket policies"}
}

// cleanObjectProbes deletes everything under both probe tenants' prefixes and
// then requires the reserved probe prefix to list empty.
func cleanObjectProbes(ctx context.Context, store objectstore.Store, tenants ...string) Probe {
	var failures []error
	for _, tenant := range tenants {
		view, err := objectstore.ForTenant(ctx, store, tenant)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		listed, err := view.List(ctx, "", probeObjectLimit)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, obj := range listed {
			if err := store.Delete(ctx, obj.Name); err != nil {
				failures = append(failures, err)
			}
		}
	}
	verdict := objectResidueProbe(ctx, store, "OBJ-CLEAN")
	if verdict.Status == StatusPass && len(failures) > 0 {
		verdict.Status = StatusFail
		verdict.Detail = "cleanup reported errors: " + errors.Join(failures...).Error()
	} else if verdict.Status == StatusPass {
		verdict.Detail = "probe objects fully cleaned up (verified an empty listing of the reserved probe prefix)"
	}
	return verdict
}
