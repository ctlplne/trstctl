// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Agent access bundles (A251): a bundle saved or deleted, a grant of it to a
// user or a machine given or removed, and a run's short-lived credential
// issued or revoked. No event carries a credential: a run's token is an API
// token whose own creation event holds only its hash.
const (
	EventAccessBundleSaved      = "access.bundle.saved"
	EventAccessBundleDeleted    = "access.bundle.deleted"
	EventAccessBundleGranted    = "access.bundle.granted"
	EventAccessBundleUngranted  = "access.bundle.ungranted"
	EventAccessBundleRunIssued  = "access.bundle.run_issued"
	EventAccessBundleRunRevoked = "access.bundle.run_revoked"
)

// AccessBundleSaved is the payload of access.bundle.saved.
type AccessBundleSaved struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Permissions      []string `json:"permissions"`
	Audiences        []string `json:"audiences"`
	MaxRunTTLSeconds int      `json:"max_run_ttl_seconds"`
	Revision         int64    `json:"revision"`
	SavedBy          string   `json:"saved_by"`
}

// AccessBundleDeleted is the payload of access.bundle.deleted.
type AccessBundleDeleted struct {
	ID        string `json:"id"`
	DeletedBy string `json:"deleted_by"`
}

// AccessBundleGranted is the payload of access.bundle.granted.
type AccessBundleGranted struct {
	ID            string     `json:"id"`
	BundleID      string     `json:"bundle_id"`
	PrincipalType string     `json:"principal_type"`
	Principal     string     `json:"principal"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	GrantedBy     string     `json:"granted_by"`
}

// AccessBundleUngranted is the payload of access.bundle.ungranted.
type AccessBundleUngranted struct {
	ID        string `json:"id"`
	BundleID  string `json:"bundle_id"`
	RemovedBy string `json:"removed_by"`
	Reason    string `json:"reason"`
}

// AccessBundleRunIssued is the payload of access.bundle.run_issued. ID is the
// run's API token ID.
type AccessBundleRunIssued struct {
	ID          string    `json:"id"`
	Principal   string    `json:"principal"`
	BundleIDs   []string  `json:"bundle_ids"`
	GrantIDs    []string  `json:"grant_ids"`
	Permissions []string  `json:"permissions"`
	Label       string    `json:"label"`
	ExpiresAt   time.Time `json:"expires_at"`
	IssuedBy    string    `json:"issued_by"`
}

// AccessBundleRunRevoked is the payload of access.bundle.run_revoked.
type AccessBundleRunRevoked struct {
	ID        string `json:"id"`
	RevokedBy string `json:"revoked_by"`
}

func init() {
	for _, typ := range []string{EventAccessBundleSaved, EventAccessBundleDeleted, EventAccessBundleGranted,
		EventAccessBundleUngranted, EventAccessBundleRunIssued, EventAccessBundleRunRevoked} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func decodeAccessBundle(e events.Event, v any) error {
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	return nil
}

func (p *Projector) applyAccessBundleTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventAccessBundleSaved:
		var d AccessBundleSaved
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleSavedTx(ctx, tx, e.TenantID, store.AccessBundle{
			ID: d.ID, Name: d.Name, Description: d.Description, Permissions: nonNilStrings(d.Permissions),
			Audiences: nonNilStrings(d.Audiences), MaxRunTTLSeconds: d.MaxRunTTLSeconds, Revision: d.Revision,
			CreatedBy: d.SavedBy, CreatedAt: e.Time,
		}, e.ID, e.Sequence)
	case EventAccessBundleDeleted:
		var d AccessBundleDeleted
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleDeletedTx(ctx, tx, e.TenantID, d.ID, d.DeletedBy, e.Time, e.ID, e.Sequence)
	case EventAccessBundleGranted:
		var d AccessBundleGranted
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleGrantedTx(ctx, tx, e.TenantID, store.AccessBundleGrant{
			ID: d.ID, BundleID: d.BundleID, PrincipalType: d.PrincipalType, Principal: d.Principal,
			ExpiresAt: d.ExpiresAt, GrantedBy: d.GrantedBy, GrantedAt: e.Time,
		}, e.ID, e.Sequence)
	case EventAccessBundleUngranted:
		var d AccessBundleUngranted
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleUngrantedTx(ctx, tx, e.TenantID, d.ID, d.RemovedBy, d.Reason, e.Time, e.ID, e.Sequence)
	case EventAccessBundleRunIssued:
		var d AccessBundleRunIssued
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleRunIssuedTx(ctx, tx, e.TenantID, store.AccessBundleRun{
			ID: d.ID, Principal: d.Principal, BundleIDs: nonNilStrings(d.BundleIDs), GrantIDs: nonNilStrings(d.GrantIDs),
			Permissions: nonNilStrings(d.Permissions), Label: d.Label, ExpiresAt: d.ExpiresAt, IssuedBy: d.IssuedBy, IssuedAt: e.Time,
		}, e.ID, e.Sequence)
	case EventAccessBundleRunRevoked:
		var d AccessBundleRunRevoked
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		return true, p.store.ApplyAccessBundleRunRevokedTx(ctx, tx, e.TenantID, d.ID, d.RevokedBy, e.Time, e.ID, e.Sequence)
	}
	return false, nil
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func addAccessBundlePrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		text   = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventAccessBundleSaved, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", text), privacyRule("/description", text),
		privacyRule("/permissions/*", opaque), privacyRule("/audiences/*", opaque),
		privacyRule("/max_run_ttl_seconds", opaque), privacyRule("/revision", opaque), privacyRule("/saved_by", exact))
	policies[privacyEventPolicyKey{EventAccessBundleDeleted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/deleted_by", exact))
	policies[privacyEventPolicyKey{EventAccessBundleGranted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/bundle_id", opaque), privacyRule("/principal_type", opaque),
		privacyRule("/principal", exact), privacyRule("/expires_at", opaque), privacyRule("/granted_by", exact))
	policies[privacyEventPolicyKey{EventAccessBundleUngranted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/bundle_id", opaque), privacyRule("/removed_by", exact),
		privacyRule("/reason", text))
	policies[privacyEventPolicyKey{EventAccessBundleRunIssued, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/principal", exact), privacyRule("/bundle_ids/*", opaque),
		privacyRule("/grant_ids/*", opaque), privacyRule("/permissions/*", opaque), privacyRule("/label", text),
		privacyRule("/expires_at", opaque), privacyRule("/issued_by", exact))
	policies[privacyEventPolicyKey{EventAccessBundleRunRevoked, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/revoked_by", exact))
}

func addAccessBundlePrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventAccessBundleSaved, 1}] = privacyPayloadShape[AccessBundleSaved]()
	shapes[privacyEventPolicyKey{EventAccessBundleDeleted, 1}] = privacyPayloadShape[AccessBundleDeleted]()
	shapes[privacyEventPolicyKey{EventAccessBundleGranted, 1}] = privacyPayloadShape[AccessBundleGranted]()
	shapes[privacyEventPolicyKey{EventAccessBundleUngranted, 1}] = privacyPayloadShape[AccessBundleUngranted]()
	shapes[privacyEventPolicyKey{EventAccessBundleRunIssued, 1}] = privacyPayloadShape[AccessBundleRunIssued]()
	shapes[privacyEventPolicyKey{EventAccessBundleRunRevoked, 1}] = privacyPayloadShape[AccessBundleRunRevoked]()
}
