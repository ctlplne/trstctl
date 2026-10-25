// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ProfileRSAFloorFindingKind is the discovery finding kind recorded while a
// profile's active version sets min_rsa_bits below the 2048-bit default
// (owner decision, batch 14). The finding names the profile, the version and
// its floor; an active version at or above the default resolves it as
// remediated, and lowering the floor again reopens it.
const ProfileRSAFloorFindingKind = "profile-rsa-floor-below-default"

// ProfilePostureActor records the product's own posture changes.
const ProfilePostureActor = "system:profile-posture"

var profilePostureNamespace = uuid.MustParse("5c2d8e91-4a7b-4f3e-9b06-1d7e3a6c2f48")

func profilePostureSourceID(tenantID string) string {
	return uuid.NewSHA1(profilePostureNamespace, []byte(tenantID+"\x00rsa-floor")).String()
}

// ReconcileProfileRSAFloorPosture brings the tenant's profile RSA floor
// findings in line with its active profiles. It runs after a profile version
// is created and on the leader's sweep, and converges: every event it appends
// derives its ID from the tenant, the profile and the version. It returns how
// many findings it recorded, reopened or resolved.
func (o *Orchestrator) ReconcileProfileRSAFloorPosture(ctx context.Context, tenantID string) (int, error) {
	active, err := o.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, rec := range active {
		var spec profile.CertificateProfile
		if err := json.Unmarshal(rec.Spec, &spec); err != nil {
			return changed, fmt.Errorf("orchestrator: decode profile %s v%d: %w", rec.Name, rec.Version, err)
		}
		n, err := o.reconcileProfileRSAFloor(ctx, tenantID, rec, spec)
		changed += n
		if err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func (o *Orchestrator) reconcileProfileRSAFloor(ctx context.Context, tenantID string, rec store.ProfileRecord, spec profile.CertificateProfile) (int, error) {
	sourceID := profilePostureSourceID(tenantID)
	ref := "profile/" + rec.Name
	version := rec.Name + "@v" + strconv.Itoa(rec.Version)
	findingID := discovery.FindingIdentity(tenantID, sourceID, ProfileRSAFloorFindingKind, ref, "")
	current, err := o.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	status := discovery.TriageStatus(current.TriageStatus)
	if !spec.BelowDefaultRSAFloor() {
		switch {
		case !found, status == discovery.TriageRemediated, status == discovery.TriageDismissed, status == discovery.TriageManaged:
			return 0, nil
		}
		return 1, o.changeProfilePostureTriage(ctx, tenantID, current, discovery.TriageRemediated, version,
			fmt.Sprintf("profile %s v%d enforces RSA keys of at least %d bits", rec.Name, rec.Version, spec.EffectiveMinRSABits()),
			"profile:"+version)
	}
	changed := 0
	if !found || current.Provenance != "profile:"+version {
		if err := o.recordProfileRSAFloorFinding(ctx, tenantID, sourceID, ref, version, rec, spec); err != nil {
			return changed, err
		}
		changed++
	}
	if found && status == discovery.TriageRemediated {
		if err := o.changeProfilePostureTriage(ctx, tenantID, current, discovery.TriageUnmanaged, version,
			fmt.Sprintf("profile %s v%d lowered min_rsa_bits to %d again", rec.Name, rec.Version, spec.MinRSABits), ""); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (o *Orchestrator) recordProfileRSAFloorFinding(ctx context.Context, tenantID, sourceID, ref, version string,
	rec store.ProfileRecord, spec profile.CertificateProfile) error {
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "profile_posture", Name: sourcecatalog.ProfilePostureSourcePrefix + "rsa-floor",
		Config: json.RawMessage(`{"check":"min_rsa_bits_below_default"}`),
	}); err != nil {
		return err
	}
	key := "profile-posture:" + version
	runID := uuid.NewSHA1(profilePostureNamespace, []byte(tenantID+"\x00"+key)).String()
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: ProfilePostureActor})
	if err != nil {
		return err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, key, "profile-posture-run-queued"),
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued}); err != nil {
		return err
	}
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, runID, DiscoveryRelayEventID(tenantID, key, "profile-posture-run-started")); err != nil {
		return err
	}
	meta, err := json.Marshal(map[string]any{
		"profile": rec.Name, "version": rec.Version, "min_rsa_bits": spec.MinRSABits,
		"default_min_rsa_bits": profile.DefaultMinRSABits,
		"reason": fmt.Sprintf("profile %s v%d sets min_rsa_bits %d, below the %d-bit default, so it certifies RSA keys the default would refuse",
			rec.Name, rec.Version, spec.MinRSABits, profile.DefaultMinRSABits),
	})
	if err != nil {
		return err
	}
	if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "profile-posture-finding"), store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: ProfileRSAFloorFindingKind, Ref: ref,
		Provenance: "profile:" + version, RiskScore: 50, Metadata: meta, DiscoveredAt: rec.CreatedAt,
	}); err != nil {
		return err
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "profile-posture-run-completed"),
		store.DiscoveryRun{ID: runID, Status: "succeeded", Targets: 1, Discovered: 1})
}

func (o *Orchestrator) changeProfilePostureTriage(ctx context.Context, tenantID string, current store.DiscoveryFinding,
	to discovery.TriageStatus, version, reason, evidenceRef string) error {
	payload, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
		ID: current.ID, Status: string(to), ManagedIdentityID: current.ManagedIdentityID,
		Actor: ProfilePostureActor, Reason: reason, EvidenceRef: evidenceRef,
	})
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(profilePostureNamespace, []byte(tenantID+"\x00"+current.ID+"\x00"+string(to)+"\x00"+version)).String()
	_, err = o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventDiscoveryFindingTriageChanged, TenantID: tenantID, Data: payload})
	return err
}
