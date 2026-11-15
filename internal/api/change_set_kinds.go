// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// More change set kinds (A248-L3): the tenant's lifecycle policy module, its
// notification channels and report schedules, the roles of its agents, and
// its secrets projects with their environments and members (metadata, never
// a value). Each kind plans, binds the plan digest, applies through the
// operator's own command and reads back as the first kinds do, and an apply
// returns the change set that puts back what it updated (its rollback).

// Change set kinds beyond the tenant baseline's.
const (
	ChangeKindAgentRoles    = "agent_roles"
	ChangeKindSecretProject = "secret_project"
)

// ChangeSecretMemberNone is the project role that revokes a member's grant.
const ChangeSecretMemberNone = "none"

// ChangeAgentRoles is the complete role set an agent's next certificate
// carries, as POST /api/v1/agents/{id}/roles records it.
type ChangeAgentRoles struct {
	AgentID string   `json:"agent_id"`
	Roles   []string `json:"roles"`
}

// ChangeSecretProject is a secrets project as a change set holds it: its
// name, the environments it names and the members it names. A name, an owner
// or an environment name left empty is left as the project holds it, and an
// environment or member the entry does not name is left alone.
type ChangeSecretProject struct {
	Slug         string                      `json:"slug"`
	Name         string                      `json:"name,omitempty"`
	OwnerID      string                      `json:"owner_id,omitempty"`
	Environments []ChangeSecretEnvironment   `json:"environments"`
	Members      []ChangeSecretProjectMember `json:"members,omitempty"`
}

// ChangeSecretEnvironment is one environment of a secrets project.
type ChangeSecretEnvironment struct {
	Slug       string `json:"slug"`
	Name       string `json:"name,omitempty"`
	Restricted bool   `json:"restricted,omitempty"`
}

// ChangeSecretProjectMember grants a subject a project role over named
// environments (none named: every environment); role none revokes its grant.
type ChangeSecretProjectMember struct {
	Subject      string   `json:"subject"`
	Role         string   `json:"role"`
	Environments []string `json:"environments,omitempty"`
}

// ChangeNotRestored is what an apply's rollback does not put back, and why:
// an object the apply created (a change set does not remove objects), or one
// whose earlier state a change set could not carry.
type ChangeNotRestored struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	ObjectID string `json:"object_id,omitempty"`
	Reason   string `json:"reason"`
}

// validateChangeSetKinds refuses a malformed agent role grant or secrets
// project before anything is read.
func validateChangeSetKinds(cs ChangeSet) error {
	if err := distinctKeys("agent", len(cs.AgentRoles), func(i int) string { return cs.AgentRoles[i].AgentID }); err != nil {
		return err
	}
	for _, x := range cs.AgentRoles {
		id := strings.TrimSpace(x.AgentID)
		if _, err := googleuuid.Parse(id); err != nil {
			return fmt.Errorf("agent %q: agent_id must be a UUID", x.AgentID)
		}
		if len(x.Roles) == 0 {
			return fmt.Errorf("agent %s: name at least one role", id)
		}
		for _, role := range x.Roles {
			if !mtls.ValidAgentRole(strings.TrimSpace(role)) {
				return fmt.Errorf("agent %s: unknown role %q; expected %s, %s, %s, %s or %s", id, role, mtls.AgentRoleHost,
					mtls.AgentRoleNetwork, mtls.AgentRoleObserver, mtls.AgentRoleGateway, mtls.AgentRoleSessionObserver)
			}
		}
	}
	if err := distinctKeys("secrets project", len(cs.SecretProjects), func(i int) string { return cs.SecretProjects[i].Slug }); err != nil {
		return err
	}
	for _, p := range cs.SecretProjects {
		slug := strings.TrimSpace(p.Slug)
		if !secretProjectSlug.MatchString(slug) || len(strings.TrimSpace(p.Name)) > 128 {
			return fmt.Errorf("secrets project %q: a slug is lowercase letters, digits and hyphens (1-63); a name is at most 128 characters", p.Slug)
		}
		if len(p.Environments) == 0 || len(p.Environments) > secretProjectEnvironmentLimit {
			return fmt.Errorf("secrets project %s: name 1-%d environments", slug, secretProjectEnvironmentLimit)
		}
		listed := map[string]bool{}
		for _, env := range p.Environments {
			if err := validateSecretProjectEnvironment(secretProjectEnvironmentRequest{Slug: strings.TrimSpace(env.Slug), Name: strings.TrimSpace(env.Name)}); err != nil {
				return fmt.Errorf("secrets project %s: %w", slug, err)
			}
			if listed[strings.TrimSpace(env.Slug)] {
				return fmt.Errorf("secrets project %s: environment %s is listed twice", slug, env.Slug)
			}
			listed[strings.TrimSpace(env.Slug)] = true
		}
		if err := distinctKeys("secrets project "+slug+" member", len(p.Members), func(i int) string { return p.Members[i].Subject }); err != nil {
			return err
		}
		for _, m := range p.Members {
			subject := strings.TrimSpace(m.Subject)
			if len(subject) > 256 {
				return fmt.Errorf("secrets project %s: a member subject is at most 256 characters", slug)
			}
			switch m.Role {
			case store.SecretProjectRoleViewer, store.SecretProjectRoleDeveloper, store.SecretProjectRoleAdmin:
			case ChangeSecretMemberNone:
				if len(m.Environments) != 0 {
					return fmt.Errorf("secrets project %s: member %s: role none revokes the grant and names no environment", slug, subject)
				}
			default:
				return fmt.Errorf("secrets project %s: member %s: role is viewer, developer, admin or none", slug, subject)
			}
			for _, env := range m.Environments {
				if !listed[strings.TrimSpace(env)] {
					return fmt.Errorf("secrets project %s: member %s names environment %s, which the entry does not list", slug, subject, env)
				}
			}
		}
	}
	return nil
}

// broadChangeKindName is the first agent, project, environment or member
// written as a pattern rather than one object.
func broadChangeKindName(cs ChangeSet, broad func(string) bool) (string, string) {
	for _, x := range cs.NotificationChannels {
		if broad(x.ChannelType) {
			return "notification channel type", x.ChannelType
		}
	}
	for _, x := range cs.ReportSchedules {
		for field, v := range map[string]string{"report schedule key": x.Key, "report schedule name": x.Name} {
			if broad(v) {
				return field, v
			}
		}
	}
	for _, x := range cs.AgentRoles {
		if broad(x.AgentID) {
			return "agent id", x.AgentID
		}
	}
	for _, p := range cs.SecretProjects {
		if broad(p.Slug) {
			return "secrets project slug", p.Slug
		}
		for _, env := range p.Environments {
			if broad(env.Slug) {
				return "secrets project environment", env.Slug
			}
		}
		for _, m := range p.Members {
			if broad(m.Subject) {
				return "secrets project member", m.Subject
			}
		}
	}
	return "", ""
}

// entryHoldsSecret reports whether an object's earlier state holds a secret
// value, which a change set (a rollback included) never carries.
func entryHoldsSecret(v any) bool {
	raw, err := json.Marshal(v)
	if err != nil {
		return true
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return true
	}
	path, _ := secretIn("rollback", decoded)
	return path != ""
}

const notRestoredSecret = "its earlier state holds a secret value, which a change set never carries: restore it through its own route"

// changePolicyStep reads and applies the tenant's lifecycle policy module as
// a tenant baseline does. Its rollback is the module active before the apply
// (the boot module when the tenant had none of its own).
func (a *API) changePolicyStep(tenantID, name string, p BaselinePolicy) changeStep {
	base := a.baselinePolicyStep(tenantID, changeSetScope, baselineOrigin{label: "change set " + name}, p)
	read := base.read
	var before string
	base.read = func(ctx context.Context) (BaselineObjectState, any, error) {
		state, current, err := read(ctx)
		if err != nil {
			return state, current, err
		}
		live, _ := a.liveLifecyclePolicy()
		module, _, err := live.ActiveModule(ctx, tenantID)
		if err != nil {
			return BaselineObjectState{}, nil, err
		}
		if strings.TrimSpace(module) == "" {
			module, _ = live.BootModule()
		}
		if before == "" {
			// The plan's read, before the apply: the verifying read after
			// it must not replace what the rollback puts back.
			before = module
		}
		return state, current, nil
	}
	return changeStep{perm: authz.PolicyWrite, step: base,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{policyVersionAuthoredEventType, policyVersionActivatedEventType}
			item.Identities = []string{"every lifecycle change in the tenant is decided by this module once it is active"}
			return nil
		},
		restore: func(current any, rb *ChangeSet) string {
			prior := &BaselinePolicy{Module: before, Description: "rollback of change set " + name}
			if entryHoldsSecret(prior) {
				return notRestoredSecret
			}
			rb.Policy = prior
			return ""
		}}
}

// changeChannelStep reads and applies one notification channel as a tenant
// baseline does.
func (a *API) changeChannelStep(tenantID string, x BaselineNotificationChannel) changeStep {
	want, _ := baselineChannel(tenantID, x)
	return changeStep{perm: authz.NotificationsWrite, step: a.baselineChannelStep(tenantID, x),
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{projections.EventNotificationChannelUpserted}
			destination := want.ChannelType + " channel " + want.Label
			if want.EndpointURL != "" {
				destination += " to " + want.EndpointURL
			}
			if !want.Enabled {
				destination += " (disabled)"
			}
			item.Destinations = []string{destination}
			if want.CredentialRef != "" {
				item.Credentials = []string{"credential_ref names the stored secret " + want.CredentialRef}
			}
			return nil
		},
		restore: func(current any, rb *ChangeSet) string {
			got, ok := current.(*store.NotificationChannel)
			if !ok || got == nil {
				return "created by this apply; a change set does not remove objects: DELETE /api/v1/notification-channels/" + want.ID + " removes it"
			}
			enabled := got.Enabled
			prior := BaselineNotificationChannel{ChannelType: got.ChannelType, Label: got.Label, EndpointURL: got.EndpointURL,
				CredentialRef: got.CredentialRef, Enabled: &enabled}
			if entryHoldsSecret(prior) {
				return notRestoredSecret
			}
			rb.NotificationChannels = append(rb.NotificationChannels, prior)
			return ""
		}}
}

// changeScheduleStep reads and applies one scheduled compliance report as a
// tenant baseline does, in the change set's own scope. setChannels are the
// enabled notification channels the same change set holds, which apply
// before its schedules.
func (a *API) changeScheduleStep(tenantID string, x BaselineReportSchedule, setChannels map[string]bool) changeStep {
	id := baselineObjectID(tenantID, changeSetScope, BaselineKindReportSchedule, x.Key)
	return changeStep{perm: authz.AuditWrite, step: a.baselineScheduleStep(tenantID, changeSetScope, x),
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			// What would stop the apply stops the plan: it never lists a
			// schedule its apply would refuse. A channel this change set
			// holds is in place by then.
			var dispatch *store.ComplianceReportDispatch
			if x.Dispatch != nil {
				dispatch = &store.ComplianceReportDispatch{Ticket: x.Dispatch.Ticket}
				for _, channel := range x.Dispatch.Channels {
					if !setChannels[canonicalNotificationChannelID(channel)] {
						dispatch.Channels = append(dispatch.Channels, channel)
					}
				}
			}
			if blockers := append(a.complianceReportBlockers(), a.complianceReportDispatchBlockers(ctx, tenantID, dispatch)...); len(blockers) != 0 {
				return errStatus(http.StatusConflict, "report schedule "+strings.TrimSpace(x.Key)+": "+strings.Join(blockers, " "))
			}
			item.Effects = []string{projections.EventComplianceReportScheduleUpserted}
			item.Destinations = complianceReportDispatchEffects(x.Dispatch)
			if x.Dispatch != nil && x.Dispatch.Ticket != nil {
				item.Credentials = []string{"token_ref names the stored secret " + x.Dispatch.Ticket.TokenRef}
			}
			cadence := fmt.Sprintf("%s report %q (%s) every %d seconds", x.ReportType, x.Name, x.Framework, x.IntervalSeconds)
			if x.Enabled != nil && !*x.Enabled {
				cadence += ", paused"
			}
			item.Identities = []string{cadence}
			return nil
		},
		restore: func(current any, rb *ChangeSet) string {
			got, ok := current.(*store.ComplianceReportSchedule)
			if !ok || got == nil {
				return "created by this apply; a change set does not remove objects: POST /api/v1/compliance/report-schedules/" + id + "/pause stops it"
			}
			enabled := got.Enabled
			prior := BaselineReportSchedule{Key: strings.TrimSpace(x.Key), Name: got.Name, Framework: got.Framework, ReportType: got.ReportType,
				IntervalSeconds: got.IntervalSeconds, Enabled: &enabled, Dispatch: got.Dispatch}
			if entryHoldsSecret(prior) {
				return notRestoredSecret
			}
			rb.ReportSchedules = append(rb.ReportSchedules, prior)
			return ""
		}}
}

// changeAgentRolesCurrent is an agent and the roles it holds now: its
// newest operator grant's, else its certificate's.
type changeAgentRolesCurrent struct {
	agent store.Agent
	roles []string
}

// changeAgentRolesStep records an agent's complete role set through the
// operator's own grant command. A change set does not enroll agents: the
// agent must be one of the tenant's and not offboarded.
func (a *API) changeAgentRolesStep(tenantID, name string, x ChangeAgentRoles) changeStep {
	agentID := strings.TrimSpace(x.AgentID)
	trimmed := make([]string, 0, len(x.Roles))
	for _, role := range x.Roles {
		trimmed = append(trimmed, strings.TrimSpace(role))
	}
	roles := mtls.NormalizeAgentRoles(trimmed)
	expected := baselineDigest(roles)
	step := baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			agent, err := a.store.GetAgent(ctx, tenantID, agentID)
			if store.IsNotFound(err) {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, "agent "+agentID+" is not an agent of this tenant; a change set does not enroll agents")
			}
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if agent.Status == "offboarded" {
				return BaselineObjectState{}, nil, errStatus(http.StatusConflict, "agent "+agent.Name+" is offboarded: it cannot renew, so it cannot take new roles")
			}
			held := mtls.NormalizeAgentRoles(agent.Roles)
			grant, found, err := a.store.AgentRoleGrant(ctx, tenantID, agentID)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if found {
				held = mtls.NormalizeAgentRoles(grant.Roles)
			}
			s := stateOf(ChangeKindAgentRoles, agentID, agentID, expected, baselineDigest(held), false)
			s.Detail = "agent " + agent.Name
			return s, &changeAgentRolesCurrent{agent: agent, roles: held}, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if _, err := a.orch.GrantAgentRoles(ctx, tenantID, agentID, roles, "change set "+name); err != nil {
				switch {
				case errors.Is(err, orchestrator.ErrAgentRolesInvalid):
					return "", "", errStatus(http.StatusBadRequest, strings.TrimPrefix(err.Error(), "orchestrator: "))
				case errors.Is(err, orchestrator.ErrAgentOffboarded):
					return "", "", errStatus(http.StatusConflict, strings.TrimPrefix(err.Error(), "orchestrator: "))
				}
				return "", "", err
			}
			return BaselineUpdated, "", nil
		},
	}
	return changeStep{perm: authz.AgentsGrantRelay, step: step,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			held, _ := current.(*changeAgentRolesCurrent)
			if held == nil {
				return errors.New("api: the agent's roles did not read")
			}
			item.Identities = []string{"agent " + held.agent.Name + " (" + agentID + ")"}
			item.Grants = []string{"roles " + strings.Join(roles, ", ") + " (now " + strings.Join(held.roles, ", ") + ")"}
			item.Credentials = []string{"the agent's next certificate renewal signs these roles; until then its certificate carries the roles it has"}
			item.Effects = []string{projections.EventAgentRolesGranted}
			return nil
		},
		restore: func(current any, rb *ChangeSet) string {
			held, _ := current.(*changeAgentRolesCurrent)
			if held == nil || len(held.roles) == 0 {
				return "the agent held no roles before, and a grant names at least one: grant its roles through POST /api/v1/agents/" + agentID + "/roles"
			}
			rb.AgentRoles = append(rb.AgentRoles, ChangeAgentRoles{AgentID: agentID, Roles: append([]string(nil), held.roles...)})
			return ""
		}}
}

// changeSecretProjectCurrent is a secrets project as it is held.
type changeSecretProjectCurrent struct {
	project store.SecretProject
	envs    []store.SecretProjectEnvironment
	members []store.SecretProjectMember
}

// normalizedSecretProject is a project entry as it is compared and written:
// trimmed, each member's environments sorted, members in subject order.
func normalizedSecretProject(x ChangeSecretProject) ChangeSecretProject {
	out := ChangeSecretProject{Slug: strings.TrimSpace(x.Slug), Name: strings.TrimSpace(x.Name), OwnerID: strings.TrimSpace(x.OwnerID),
		Environments: make([]ChangeSecretEnvironment, 0, len(x.Environments))}
	for _, env := range x.Environments {
		out.Environments = append(out.Environments, ChangeSecretEnvironment{Slug: strings.TrimSpace(env.Slug), Name: strings.TrimSpace(env.Name), Restricted: env.Restricted})
	}
	for _, m := range x.Members {
		envs := make([]string, 0, len(m.Environments))
		for _, env := range m.Environments {
			envs = append(envs, strings.TrimSpace(env))
		}
		sort.Strings(envs)
		out.Members = append(out.Members, ChangeSecretProjectMember{Subject: strings.TrimSpace(m.Subject), Role: m.Role, Environments: envs})
	}
	sort.SliceStable(out.Members, func(i, j int) bool { return out.Members[i].Subject < out.Members[j].Subject })
	return out
}

// heldAsEntry is what the project holds of what the entry names, in the
// entry's shape: its name and owner where the entry names them, each listed
// environment that exists, and each listed member's grant (an ungranted
// member reads as role none). Compared with the entry, it says whether the
// project is in sync.
func heldAsEntry(want ChangeSecretProject, held changeSecretProjectCurrent) ChangeSecretProject {
	out := ChangeSecretProject{Slug: want.Slug, Environments: []ChangeSecretEnvironment{}}
	if want.Name != "" {
		out.Name = strings.TrimSpace(held.project.Name)
	}
	if want.OwnerID != "" {
		out.OwnerID = strings.TrimSpace(held.project.OwnerID)
	}
	byEnv := map[string]store.SecretProjectEnvironment{}
	for _, env := range held.envs {
		byEnv[env.Slug] = env
	}
	for _, env := range want.Environments {
		got, ok := byEnv[env.Slug]
		if !ok {
			continue
		}
		e := ChangeSecretEnvironment{Slug: got.Slug, Restricted: got.Restricted}
		if env.Name != "" {
			e.Name = strings.TrimSpace(got.Name)
		}
		out.Environments = append(out.Environments, e)
	}
	byMember := map[string]store.SecretProjectMember{}
	for _, m := range held.members {
		byMember[m.Subject] = m
	}
	for _, m := range want.Members {
		got, ok := byMember[m.Subject]
		if !ok {
			out.Members = append(out.Members, ChangeSecretProjectMember{Subject: m.Subject, Role: ChangeSecretMemberNone})
			continue
		}
		envs := append([]string(nil), got.Environments...)
		sort.Strings(envs)
		out.Members = append(out.Members, ChangeSecretProjectMember{Subject: got.Subject, Role: got.Role, Environments: envs})
	}
	return out
}

// changeSecretProjectStep creates a secrets project, or brings one to what
// the entry names, through the commands the project routes take: create,
// rename, add or rename an environment, grant or revoke a member. What no
// command changes is refused at plan: a held project's owner and an
// environment's restriction are set when they are created.
func (a *API) changeSecretProjectStep(tenantID string, x ChangeSecretProject) changeStep {
	want := normalizedSecretProject(x)
	expected := baselineDigest(want)
	step := baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			if a.secrets == nil {
				return BaselineObjectState{}, nil, errStatus(http.StatusServiceUnavailable, "the secrets service is not enabled, so a change set cannot hold secrets projects")
			}
			project, envs, members, err := a.store.GetSecretProject(ctx, tenantID, want.Slug)
			if errors.Is(err, store.ErrSecretProjectNotFound) {
				if want.OwnerID != "" {
					if _, err := a.store.GetOwner(ctx, tenantID, want.OwnerID); err != nil {
						if store.IsNotFound(err) {
							return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, "secrets project "+want.Slug+": owner_id must identify an owner in this tenant")
						}
						return BaselineObjectState{}, nil, err
					}
				}
				return stateOf(ChangeKindSecretProject, want.Slug, want.Slug, expected, "", true), nil, nil
			}
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			held := changeSecretProjectCurrent{project: project, envs: envs, members: members}
			if want.OwnerID != "" && want.OwnerID != strings.TrimSpace(project.OwnerID) {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, "secrets project "+want.Slug+
					" is owned by "+firstNonEmpty(project.OwnerID, "nobody")+"; a change set sets a project's owner only when it creates the project")
			}
			added := 0
			for _, env := range want.Environments {
				found := false
				for _, got := range envs {
					if got.Slug == env.Slug {
						found = true
						if got.Restricted != env.Restricted {
							return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
								"secrets project %s: environment %s is held with restricted %v; an environment's restriction is set when it is created", want.Slug, env.Slug, got.Restricted))
						}
					}
				}
				if !found {
					added++
				}
			}
			if len(envs)+added > secretProjectEnvironmentLimit {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("secrets project %s: a project has at most %d environments", want.Slug, secretProjectEnvironmentLimit))
			}
			s := stateOf(ChangeKindSecretProject, want.Slug, want.Slug, expected, baselineDigest(heldAsEntry(want, held)), false)
			s.Detail = fmt.Sprintf("%d environments, %d members", len(envs), len(members))
			return s, &held, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			subject, err := requestPrincipalSubject(ctx)
			if err != nil {
				return "", "", err
			}
			held, _ := current.(*changeSecretProjectCurrent)
			if held == nil {
				created := projections.SecretProjectCreated{Slug: want.Slug, Name: want.Name, OwnerID: want.OwnerID, CreatedBy: subject}
				for i, env := range want.Environments {
					created.Environments = append(created.Environments, projections.SecretProjectEnvironment{Slug: env.Slug, Name: env.Name, Restricted: env.Restricted, Position: i})
				}
				if err := a.orch.CreateSecretProject(ctx, tenantID, created); err != nil {
					return "", "", err
				}
				held = &changeSecretProjectCurrent{}
			} else {
				if want.Name != "" && want.Name != strings.TrimSpace(held.project.Name) {
					if err := a.orch.RenameSecretProject(ctx, tenantID, projections.SecretProjectRenamed{Project: want.Slug, Name: want.Name, RenamedBy: subject}); err != nil {
						return "", "", err
					}
				}
				position := len(held.envs)
				for _, env := range want.Environments {
					i := slices.IndexFunc(held.envs, func(e store.SecretProjectEnvironment) bool { return e.Slug == env.Slug })
					switch {
					case i < 0:
						if err := a.orch.AddSecretProjectEnvironment(ctx, tenantID, projections.SecretProjectEnvironmentAdded{Project: want.Slug, AddedBy: subject,
							Environment: projections.SecretProjectEnvironment{Slug: env.Slug, Name: env.Name, Restricted: env.Restricted, Position: position}}); err != nil {
							return "", "", err
						}
						position++
					case env.Name != "" && env.Name != strings.TrimSpace(held.envs[i].Name):
						if err := a.orch.RenameSecretProjectEnvironment(ctx, tenantID, projections.SecretProjectEnvironmentRenamed{Project: want.Slug,
							Environment: env.Slug, Name: env.Name, RenamedBy: subject}); err != nil {
							return "", "", err
						}
					}
				}
			}
			for _, m := range want.Members {
				i := slices.IndexFunc(held.members, func(g store.SecretProjectMember) bool { return g.Subject == m.Subject })
				if m.Role == ChangeSecretMemberNone {
					if i >= 0 {
						if err := a.orch.RevokeSecretProjectMember(ctx, tenantID, projections.SecretProjectMemberRevoked{Project: want.Slug, Subject: m.Subject, RevokedBy: subject}); err != nil {
							return "", "", err
						}
					}
					continue
				}
				if i >= 0 {
					envs := append([]string(nil), held.members[i].Environments...)
					sort.Strings(envs)
					if held.members[i].Role == m.Role && slices.Equal(envs, m.Environments) {
						continue
					}
				}
				if err := a.orch.GrantSecretProjectMember(ctx, tenantID, projections.SecretProjectMemberGranted{Project: want.Slug, Subject: m.Subject,
					Role: m.Role, Environments: m.Environments, GrantedBy: subject}); err != nil {
					return "", "", err
				}
			}
			return createdOrUpdated(current), "", nil
		},
	}
	return changeStep{perm: authz.AccessWrite, step: step,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			held, _ := current.(*changeSecretProjectCurrent)
			item.Effects = []string{}
			if held == nil {
				item.Effects = append(item.Effects, projections.EventSecretProjectCreated)
				held = &changeSecretProjectCurrent{}
			} else if want.Name != "" && want.Name != strings.TrimSpace(held.project.Name) {
				item.Effects = append(item.Effects, projections.EventSecretProjectRenamed)
			}
			for _, env := range want.Environments {
				access := "open"
				if env.Restricted {
					access = "restricted"
				}
				i := slices.IndexFunc(held.envs, func(e store.SecretProjectEnvironment) bool { return e.Slug == env.Slug })
				switch {
				case i < 0 && len(held.envs) > 0:
					item.Destinations = append(item.Destinations, "adds environment "+env.Slug+" ("+access+")")
					item.Effects = appendOnce(item.Effects, projections.EventSecretProjectEnvironmentAdded)
				case i < 0:
					item.Destinations = append(item.Destinations, "environment "+env.Slug+" ("+access+")")
				case env.Name != "" && env.Name != strings.TrimSpace(held.envs[i].Name):
					item.Destinations = append(item.Destinations, "renames environment "+env.Slug+" to "+env.Name)
					item.Effects = appendOnce(item.Effects, projections.EventSecretProjectEnvironmentRenamed)
				}
			}
			for _, m := range want.Members {
				i := slices.IndexFunc(held.members, func(g store.SecretProjectMember) bool { return g.Subject == m.Subject })
				now := "no grant"
				if i >= 0 {
					now = held.members[i].Role + " on " + environmentsLabel(held.members[i].Environments)
				}
				if m.Role == ChangeSecretMemberNone {
					if i >= 0 {
						item.Grants = append(item.Grants, "revokes "+m.Subject+" (now "+now+")")
						item.Effects = appendOnce(item.Effects, projections.EventSecretProjectMemberRevoked)
					}
					continue
				}
				item.Identities = append(item.Identities, "member "+m.Subject)
				item.Grants = append(item.Grants, m.Subject+" "+m.Role+" on "+environmentsLabel(m.Environments)+" (now "+now+")")
				item.Effects = appendOnce(item.Effects, projections.EventSecretProjectMemberGranted)
			}
			return nil
		},
		restore: func(current any, rb *ChangeSet) string {
			held, _ := current.(*changeSecretProjectCurrent)
			if held == nil {
				return "created by this apply; a change set does not remove a secrets project"
			}
			prior := ChangeSecretProject{Slug: want.Slug}
			var unnamed []string
			if want.Name != "" {
				prior.Name = strings.TrimSpace(held.project.Name)
				if prior.Name == "" && want.Name != "" {
					unnamed = append(unnamed, "the project")
				}
			}
			for _, env := range held.envs {
				prior.Environments = append(prior.Environments, ChangeSecretEnvironment{Slug: env.Slug, Name: strings.TrimSpace(env.Name), Restricted: env.Restricted})
				for _, w := range want.Environments {
					if w.Slug == env.Slug && w.Name != "" && strings.TrimSpace(env.Name) == "" {
						unnamed = append(unnamed, "environment "+env.Slug)
					}
				}
			}
			kept := map[string]bool{}
			for _, env := range held.envs {
				kept[env.Slug] = true
			}
			for _, m := range want.Members {
				i := slices.IndexFunc(held.members, func(g store.SecretProjectMember) bool { return g.Subject == m.Subject })
				if i < 0 {
					prior.Members = append(prior.Members, ChangeSecretProjectMember{Subject: m.Subject, Role: ChangeSecretMemberNone})
					continue
				}
				prior.Members = append(prior.Members, ChangeSecretProjectMember{Subject: m.Subject, Role: held.members[i].Role,
					Environments: append([]string(nil), held.members[i].Environments...)})
			}
			if entryHoldsSecret(prior) {
				return notRestoredSecret
			}
			rb.SecretProjects = append(rb.SecretProjects, prior)
			var notes []string
			var added []string
			for _, env := range want.Environments {
				if !kept[env.Slug] {
					added = append(added, env.Slug)
				}
			}
			if len(added) > 0 {
				notes = append(notes, "environment "+strings.Join(added, ", ")+" added by this apply stays: a change set does not remove environments")
			}
			if len(unnamed) > 0 {
				notes = append(notes, "the name given to "+strings.Join(unnamed, " and ")+" stays: it had none, and a name is never cleared")
			}
			return strings.Join(notes, "; ")
		}}
}

func environmentsLabel(envs []string) string {
	if len(envs) == 0 {
		return "every environment"
	}
	return strings.Join(envs, ", ")
}

func appendOnce(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}
