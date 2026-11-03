// SPDX-License-Identifier: BUSL-1.1

package secretmigrate

import (
	"encoding/binary"
	"encoding/json"
	"sort"
	"strings"
)

// Object actions in an assessment.
const (
	ActionImport  = "import"
	ActionReissue = "reissue"
	ActionBlocked = "blocked"
)

// Permission outcomes.
const (
	PermissionTranslated = "translated"
	PermissionCovered    = "covered"
	PermissionHeld       = "held"
)

// Native member roles a permission translates to.
const (
	RoleViewer    = "viewer"
	RoleDeveloper = "developer"
)

// Destination is what the native store already holds that the assessment
// needs: the project's environments, the current version of each exported
// name, whether a referenced name exists, and the project's members.
type Destination struct {
	Environments map[string]EnvironmentState
	Versions     map[string]int
	Exists       func(name string) bool
	Members      map[string]Member
}

// EnvironmentState is one destination environment.
type EnvironmentState struct {
	Restricted bool
}

// Member is one subject's project membership: a role, for the listed
// environments or (none listed) all of them.
type Member struct {
	Role         string
	Environments []string
}

// Assessment is a migration's value-free plan: what each exported object
// becomes, what the export's permissions translate to, and what is held.
type Assessment struct {
	Project      string            `json:"project"`
	Environments []EnvironmentPlan `json:"environments"`
	Objects      []ObjectPlan      `json:"objects"`
	Unsupported  []Unsupported     `json:"unsupported"`
	Permissions  []PermissionPlan  `json:"permissions"`
	Consumers    []ConsumerPlan    `json:"consumers"`
	Counts       Counts            `json:"counts"`
}

// EnvironmentPlan is one exported environment. SourceRestricted means the
// export listed who may access it; Open means the destination environment is
// open to every secrets reader in the tenant, so importing into it would
// widen access unless the operator accepts that explicitly.
type EnvironmentPlan struct {
	Name             string   `json:"name"`
	Objects          int      `json:"objects"`
	Folders          []string `json:"folders"`
	Exists           bool     `json:"exists"`
	Restricted       bool     `json:"restricted"`
	SourceRestricted bool     `json:"source_restricted"`
	Open             bool     `json:"open"`
	OpenAccepted     bool     `json:"open_accepted"`
}

// ObjectPlan is one exported object's outcome. It never holds a value.
type ObjectPlan struct {
	Name            string   `json:"name"`
	Environment     string   `json:"environment"`
	Folder          string   `json:"folder,omitempty"`
	Key             string   `json:"key"`
	Action          string   `json:"action"`
	Reason          string   `json:"reason,omitempty"`
	ExistingVersion int      `json:"existing_version"`
	Multiline       bool     `json:"multiline"`
	Description     string   `json:"description,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Owner           string   `json:"owner,omitempty"`
	References      []string `json:"references,omitempty"`
	Location        string   `json:"location"`
}

// PermissionPlan is one exported grant's outcome: translated into a member
// role for listed environments, already covered by a membership, or held for
// review because the nearest native grant would give more than the export
// did.
type PermissionPlan struct {
	Subject      string   `json:"subject"`
	Access       string   `json:"access"`
	Environment  string   `json:"environment"`
	Folder       string   `json:"folder,omitempty"`
	Status       string   `json:"status"`
	Role         string   `json:"role,omitempty"`
	Environments []string `json:"environments,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// ConsumerPlan is one consumer with the native names it is expected to read.
type ConsumerPlan struct {
	Name        string   `json:"name"`
	Subject     string   `json:"subject"`
	Environment string   `json:"environment"`
	Secrets     []string `json:"secrets"`
	Problem     string   `json:"problem,omitempty"`
}

// Counts summarize an assessment.
type Counts struct {
	Import      int `json:"import"`
	Reissue     int `json:"reissue"`
	Blocked     int `json:"blocked"`
	Unsupported int `json:"unsupported"`
	Translated  int `json:"permissions_translated"`
	Held        int `json:"permissions_held"`
}

// Assess plans the migration of p into d. acceptOpen lists environments the
// operator accepts importing into although the export restricted them and the
// destination is open.
func Assess(p *Parsed, b *Bundle, d Destination, acceptOpen []string) Assessment {
	if d.Exists == nil {
		d.Exists = func(string) bool { return false }
	}
	a := Assessment{Project: p.Project, Unsupported: append([]Unsupported{}, p.Unsupported...),
		Objects: []ObjectPlan{}, Permissions: []PermissionPlan{}, Consumers: []ConsumerPlan{}}
	sourceRestricted := map[string]bool{}
	for _, perm := range b.Permissions {
		sourceRestricted[perm.Environment] = true
	}
	envs := map[string]*EnvironmentPlan{}
	for _, o := range p.Objects {
		e := envs[o.Environment]
		if e == nil {
			state, exists := d.Environments[o.Environment]
			e = &EnvironmentPlan{Name: o.Environment, Exists: exists, Restricted: state.Restricted,
				SourceRestricted: sourceRestricted[o.Environment], Folders: []string{}}
			e.Open = e.Exists && e.SourceRestricted && !e.Restricted
			e.OpenAccepted = e.Open && contains(acceptOpen, o.Environment)
			envs[o.Environment] = e
		}
		e.Objects++
		if o.Folder != "" && !contains(e.Folders, o.Folder) {
			e.Folders = append(e.Folders, o.Folder)
		}
	}
	problems := referenceProblems(p, d.Exists)
	for _, o := range p.Objects {
		e := envs[o.Environment]
		plan := ObjectPlan{
			Name: o.Name, Environment: o.Environment, Folder: o.Folder, Key: o.Key, Action: ActionImport,
			ExistingVersion: d.Versions[o.Name], Multiline: o.Multiline, Description: o.Description,
			Tags: o.Tags, Owner: o.Owner, Location: o.Location,
		}
		for _, target := range o.References {
			if _, ok := problems[o.Name]; !ok || d.Exists(target) || inExport(p, target) {
				plan.References = append(plan.References, target)
			}
		}
		switch {
		case !o.Exportable:
			plan.Action, plan.Reason = ActionReissue, "the export could not carry this credential; reissue it through an explicit step"
		case !e.Exists:
			plan.Action, plan.Reason = ActionBlocked, "create environment "+o.Environment+" in project "+p.Project+" first"
		case e.Open && !e.OpenAccepted:
			plan.Action, plan.Reason = ActionBlocked, "the export restricted this environment and the destination's is open to every secrets reader: restrict it, or accept that explicitly"
		case problems[o.Name] != "":
			plan.Action, plan.Reason = ActionBlocked, problems[o.Name]
		}
		a.Objects = append(a.Objects, plan)
		switch plan.Action {
		case ActionImport:
			a.Counts.Import++
		case ActionReissue:
			a.Counts.Reissue++
		default:
			a.Counts.Blocked++
		}
	}
	for _, name := range sortedKeys(envs) {
		sort.Strings(envs[name].Folders)
		a.Environments = append(a.Environments, *envs[name])
	}
	a.Permissions = translatePermissions(b.Permissions, d.Members)
	for _, perm := range a.Permissions {
		switch perm.Status {
		case PermissionTranslated:
			a.Counts.Translated++
		case PermissionHeld:
			a.Counts.Held++
		}
	}
	for _, c := range b.Consumers {
		a.Consumers = append(a.Consumers, planConsumer(p, c))
	}
	a.Counts.Unsupported = len(a.Unsupported)
	return a
}

func inExport(p *Parsed, name string) bool {
	for _, o := range p.Objects {
		if o.Name == name {
			return true
		}
	}
	return false
}

// translatePermissions turns the export's grants into native memberships and
// never widens one. The native model grants a role per member for listed
// environments; it has no folder grants and one role per member. So:
// environment-wide read becomes viewer and write becomes developer for that
// environment; a folder grant, admin access, a wildcard subject, or one
// subject given different access in different environments is held for
// review; and a subject whose existing membership already gives at least the
// export's access is covered.
func translatePermissions(perms []Permission, members map[string]Member) []PermissionPlan {
	out := []PermissionPlan{}
	bySubject := map[string][]int{}
	for i, perm := range perms {
		plan := PermissionPlan{Subject: perm.Subject, Access: perm.Access, Environment: perm.Environment, Folder: perm.Folder}
		switch {
		case strings.TrimSpace(perm.Subject) == "" || strings.Contains(perm.Subject, "*"):
			plan.Status, plan.Reason = PermissionHeld, "the subject is empty or a wildcard; name each subject"
		case perm.Access != "read" && perm.Access != "write" && perm.Access != "admin":
			plan.Status, plan.Reason = PermissionHeld, "access is read, write or admin"
		case perm.Access == "admin":
			plan.Status, plan.Reason = PermissionHeld, "admin access includes managing members; review it"
		case perm.Folder != "":
			plan.Status, plan.Reason = PermissionHeld, "the store grants whole environments; granting this folder's environment would open more than the export did"
		default:
			plan.Status = PermissionTranslated
			plan.Role = RoleViewer
			if perm.Access == "write" {
				plan.Role = RoleDeveloper
			}
			bySubject[perm.Subject] = append(bySubject[perm.Subject], i)
		}
		out = append(out, plan)
	}
	for subject, idx := range bySubject {
		role := out[idx[0]].Role
		envs := []string{}
		mixed := false
		for _, i := range idx {
			mixed = mixed || out[i].Role != role
			if !contains(envs, out[i].Environment) {
				envs = append(envs, out[i].Environment)
			}
		}
		sort.Strings(envs)
		existing, isMember := members[subject]
		for _, i := range idx {
			switch {
			case mixed:
				out[i].Status, out[i].Role = PermissionHeld, ""
				out[i].Reason = "the export gives this subject different access in different environments; a member has one role"
			case isMember && covers(existing, role, envs):
				out[i].Status, out[i].Role = PermissionCovered, ""
				out[i].Reason = "the subject's membership already gives this access"
			case isMember:
				out[i].Status, out[i].Role = PermissionHeld, ""
				out[i].Reason = "the subject already has a different membership; changing its one role would change access elsewhere"
			default:
				out[i].Environments = envs
			}
		}
	}
	return out
}

// covers reports whether a membership gives at least role in every one of
// envs.
func covers(m Member, role string, envs []string) bool {
	rank := map[string]int{RoleViewer: 1, RoleDeveloper: 2, "admin": 3}
	if rank[m.Role] < rank[role] {
		return false
	}
	if len(m.Environments) == 0 {
		return true
	}
	for _, e := range envs {
		if !contains(m.Environments, e) {
			return false
		}
	}
	return true
}

func planConsumer(p *Parsed, c Consumer) ConsumerPlan {
	plan := ConsumerPlan{Name: c.Name, Subject: c.Subject, Environment: c.Environment, Secrets: []string{}}
	switch {
	case strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Subject) == "":
		plan.Problem = "a consumer has a name and the subject it reads as"
		return plan
	case !slug.MatchString(c.Environment):
		plan.Problem = "a consumer reads from one exported environment"
		return plan
	}
	if len(c.Secrets) == 0 {
		for _, o := range p.Objects {
			if o.Environment == c.Environment && o.Exportable {
				plan.Secrets = append(plan.Secrets, o.Name)
			}
		}
	}
	for _, key := range c.Secrets {
		parts := strings.Split(strings.Trim(key, "/"), "/")
		name := NativeName(p.Project, c.Environment, strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1])
		if !inExport(p, name) {
			plan.Problem = "it lists " + key + ", which is not in the export"
			continue
		}
		plan.Secrets = append(plan.Secrets, name)
	}
	if len(plan.Secrets) == 0 && plan.Problem == "" {
		plan.Problem = "it reads nothing the export carries"
	}
	return plan
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DigestInput is what a plan's digest covers: the assessment (names,
// actions, translations) and each imported value, length-prefixed. It holds
// values: the caller keys a MAC over it and wipes it. A value changed after
// the assessment changes the digest, so a stale plan is never staged.
func DigestInput(a Assessment, p *Parsed) []byte {
	plan, _ := json.Marshal(a)
	out := append([]byte("trstctl-secret-migration/v1\n"), plan...)
	for _, o := range p.Objects {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(o.Value))) // #nosec G115 -- bounded by MaxValueBytes (CWE-190)
		out = append(out, o.Name...)
		out = append(out, n[:]...)
		out = append(out, o.Value...)
	}
	return out
}
