// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// The secrets workspace (A235): projects, their environments and members.
const (
	EventSecretProjectCreated          = "secret.project.created"           // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretProjectEnvironmentAdded = "secret.project.environment_added" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretProjectMemberGranted    = "secret.project.member_granted"    // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretProjectMemberRevoked    = "secret.project.member_revoked"    // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

// SecretProjectEnvironment is one environment in a workspace event.
type SecretProjectEnvironment struct {
	Slug       string `json:"slug"`
	Name       string `json:"name,omitempty"`
	Restricted bool   `json:"restricted,omitempty"`
	Position   int    `json:"position,omitempty"`
}

// SecretProjectCreated is the payload of secret.project.created.
type SecretProjectCreated struct {
	Slug         string                     `json:"slug"`
	Name         string                     `json:"name,omitempty"`
	OwnerID      string                     `json:"owner_id,omitempty"`
	CreatedBy    string                     `json:"created_by"`
	Environments []SecretProjectEnvironment `json:"environments"`
}

// SecretProjectEnvironmentAdded is the payload of secret.project.environment_added.
type SecretProjectEnvironmentAdded struct {
	Project     string                   `json:"project"`
	Environment SecretProjectEnvironment `json:"environment"`
	AddedBy     string                   `json:"added_by"`
}

// SecretProjectMemberGranted is the payload of secret.project.member_granted.
type SecretProjectMemberGranted struct {
	Project      string   `json:"project"`
	Subject      string   `json:"subject"`
	Role         string   `json:"role"`
	Environments []string `json:"environments,omitempty"`
	GrantedBy    string   `json:"granted_by"`
}

// SecretProjectMemberRevoked is the payload of secret.project.member_revoked.
type SecretProjectMemberRevoked struct {
	Project   string `json:"project"`
	Subject   string `json:"subject"`
	RevokedBy string `json:"revoked_by"`
}

func init() {
	for _, typ := range []string{EventSecretProjectCreated, EventSecretProjectEnvironmentAdded, EventSecretProjectMemberGranted, EventSecretProjectMemberRevoked} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func storeEnvironment(project string, e SecretProjectEnvironment, at events.Event) store.SecretProjectEnvironment {
	return store.SecretProjectEnvironment{Project: project, Slug: e.Slug, Name: e.Name, Restricted: e.Restricted, Position: e.Position, CreatedAt: at.Time}
}

func (p *Projector) applySecretProjectTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventSecretProjectCreated:
		var pl SecretProjectCreated
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.Slug == "" || e.Time.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		envs := make([]store.SecretProjectEnvironment, 0, len(pl.Environments))
		for _, env := range pl.Environments {
			envs = append(envs, storeEnvironment(pl.Slug, env, e))
		}
		return true, p.store.ApplySecretProjectCreatedTx(ctx, tx, e.TenantID, store.SecretProject{
			Slug: pl.Slug, Name: pl.Name, OwnerID: pl.OwnerID, CreatedBy: pl.CreatedBy, CreatedAt: e.Time,
		}, envs, e.Sequence)
	case EventSecretProjectEnvironmentAdded:
		var pl SecretProjectEnvironmentAdded
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.Project == "" || pl.Environment.Slug == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplySecretProjectEnvironmentTx(ctx, tx, e.TenantID, storeEnvironment(pl.Project, pl.Environment, e), e.Sequence)
	case EventSecretProjectMemberGranted:
		var pl SecretProjectMemberGranted
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		switch {
		case pl.Project == "" || pl.Subject == "":
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		case pl.Role != store.SecretProjectRoleViewer && pl.Role != store.SecretProjectRoleDeveloper && pl.Role != store.SecretProjectRoleAdmin:
			return true, fmt.Errorf("projections: %s role %q is unknown", e.Type, pl.Role)
		}
		return true, p.store.ApplySecretProjectMemberGrantedTx(ctx, tx, e.TenantID, store.SecretProjectMember{
			Project: pl.Project, Subject: pl.Subject, Role: pl.Role, Environments: pl.Environments, GrantedBy: pl.GrantedBy, GrantedAt: e.Time,
		}, e.Sequence)
	case EventSecretProjectMemberRevoked:
		var pl SecretProjectMemberRevoked
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.Project == "" || pl.Subject == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplySecretProjectMemberRevokedTx(ctx, tx, e.TenantID, pl.Project, pl.Subject, e.Sequence)
	default:
		// A237's scoped syncs are part of the same secrets workspace family.
		return p.applySecretScopedSyncTx(ctx, tx, e)
	}
}

// secretProjectPrivacyPolicies are the exact policies of the workspace events:
// subjects and the actors who changed the workspace are identities; slugs,
// names and roles are opaque.
func addSecretProjectPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	env := func(prefix string) []events.PrivacyFieldRule {
		return []events.PrivacyFieldRule{
			privacyRule(prefix+"/slug", opaque), privacyRule(prefix+"/name", opaque),
			privacyRule(prefix+"/restricted", opaque), privacyRule(prefix+"/position", opaque),
		}
	}
	policies[privacyEventPolicyKey{EventSecretProjectCreated, 1}] = privacyRules(append([]events.PrivacyFieldRule{
		privacyRule("/slug", opaque), privacyRule("/name", opaque), privacyRule("/owner_id", opaque), privacyRule("/created_by", exact),
	}, env("/environments/*")...)...)
	policies[privacyEventPolicyKey{EventSecretProjectEnvironmentAdded, 1}] = privacyRules(append([]events.PrivacyFieldRule{
		privacyRule("/project", opaque), privacyRule("/added_by", exact),
	}, env("/environment")...)...)
	policies[privacyEventPolicyKey{EventSecretProjectMemberGranted, 1}] = privacyRules(
		privacyRule("/project", opaque), privacyRule("/subject", exact), privacyRule("/role", opaque),
		privacyRule("/environments/*", opaque), privacyRule("/granted_by", exact))
	policies[privacyEventPolicyKey{EventSecretProjectMemberRevoked, 1}] = privacyRules(
		privacyRule("/project", opaque), privacyRule("/subject", exact), privacyRule("/revoked_by", exact))
	addSecretScopedSyncPrivacyPolicies(policies)
}

// addSecretProjectPrivacyShapes registers the workspace events' payload shapes.
func addSecretProjectPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSecretProjectCreated, 1}] = privacyPayloadShape[SecretProjectCreated]()
	shapes[privacyEventPolicyKey{EventSecretProjectEnvironmentAdded, 1}] = privacyPayloadShape[SecretProjectEnvironmentAdded]()
	shapes[privacyEventPolicyKey{EventSecretProjectMemberGranted, 1}] = privacyPayloadShape[SecretProjectMemberGranted]()
	shapes[privacyEventPolicyKey{EventSecretProjectMemberRevoked, 1}] = privacyPayloadShape[SecretProjectMemberRevoked]()
	addSecretScopedSyncPrivacyShapes(shapes)
}
