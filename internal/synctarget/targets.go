// SPDX-License-Identifier: BUSL-1.1

package synctarget

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	herokuApp     = regexp.MustCompile(`^([a-z][a-z0-9-]{1,29}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	renderService = regexp.MustCompile(`^srv-[A-Za-z0-9]{6,64}$`)
	flyApp        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	lowerSlug     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	northflankKey = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
	qoveryKey     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	qoveryScopes  = map[string]bool{"application": true, "container": true, "job": true, "helm": true, "terraform": true, "environment": true, "project": true}
	cloud66Stack  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	forgeOrg      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
)

var (
	circleCIProject = regexp.MustCompile(`^(gh|github|bb|bitbucket|circleci)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	travisRepo      = regexp.MustCompile(`^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[0-9]{1,19})$`)
	bitbucketSlug   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,62}$`)
	teamCityProject = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
	teamCityKey     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
	humanitecKey    = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	rundeckFolder   = regexp.MustCompile(`^keys(/[A-Za-z0-9_.-]+)*$`)
	rundeckKey      = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
)

// circleCIBinding is "project <vcs/org/repo>" or "context <ID>".
func circleCIBinding(f []string) (Binding, error) {
	if len(f) != 2 {
		return nil, errors.New("project <vcs/org/repo> or context <ID>")
	}
	switch f[0] {
	case "project":
		if !circleCIProject.MatchString(f[1]) {
			return nil, errors.New("project must be a project slug such as gh/org/repo")
		}
	case "context":
		if !uuidRule.MatchString(f[1]) {
			return nil, errors.New("context must be a UUID")
		}
	default:
		return nil, errors.New("project <vcs/org/repo> or context <ID>")
	}
	return Binding{f[0]: f[1]}, nil
}

// qoveryBinding is "<scope> <parent ID>": the variables defined at an
// application, container, job, helm, terraform, environment or project.
func qoveryBinding(f []string) (Binding, error) {
	if len(f) != 2 || !qoveryScopes[f[0]] {
		return nil, errors.New("a scope (application, container, job, helm, terraform, environment or project) and its ID")
	}
	if !uuidRule.MatchString(f[1]) {
		return nil, fmt.Errorf("the %s ID must be a UUID", f[0])
	}
	return Binding{"scope": strings.ToUpper(f[0]), "parent": f[1]}, nil
}

// all is every hosted target type (A241).
func all() []Target {
	return []Target{
		{Type: "heroku", Name: "Heroku", Platform: "heroku", Grammar: "<app name or ID>",
			Endpoint: "https://api.heroku.com", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			denyPrefix: []string{"HEROKU_"},
			parse:      one("app", herokuApp, "a Heroku app name or ID")},
		{Type: "render", Name: "Render", Platform: "render", Grammar: "<service ID>",
			Endpoint: "https://api.render.com/v1", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: one("service", renderService, "a Render service ID (srv-...)")},
		{Type: "railway", Name: "Railway", Platform: "railway", Grammar: "project <ID> environment <ID> [service <ID>]",
			Endpoint: "https://backboard.railway.com/graphql/v2", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "project", rule: uuidRule, what: "a UUID"}, pair{word: "environment", rule: uuidRule, what: "a UUID"},
				pair{word: "service", rule: uuidRule, what: "a UUID", optional: true})},
		{Type: "fly", Name: "Fly.io", Platform: "fly", Grammar: "<app name>",
			Endpoint: "https://api.machines.dev", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: one("app", flyApp, "a Fly.io app name")},
		{Type: "digitalocean-app-platform", Name: "DigitalOcean App Platform", Platform: "digitalocean",
			Grammar: "app <ID> [component <name>]", Endpoint: "https://api.digitalocean.com",
			Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "app", rule: uuidRule, what: "a UUID"}, pair{word: "component", rule: lowerSlug, what: "a component name", optional: true})},
		{Type: "northflank", Name: "Northflank", Platform: "northflank", Grammar: "project <ID> secret-group <ID>",
			Endpoint: "https://api.northflank.com/v1", Keys: FlatKeys, keyRule: northflankKey,
			keyHelp: "letters, digits, underscores, dots, hyphens and slashes", maxKey: 255,
			parse: pairs(pair{word: "project", rule: lowerSlug, what: "a project ID"}, pair{word: "secret-group", rule: lowerSlug, what: "a secret group ID"})},
		{Type: "qovery", Name: "Qovery", Platform: "qovery", Grammar: "<scope> <ID>",
			Endpoint: "https://api.qovery.com", Keys: FlatKeys, keyRule: qoveryKey,
			keyHelp: "letters, digits and underscores, starting with a letter", maxKey: 255,
			denyPrefix: []string{"QOVERY_", "__"}, parse: qoveryBinding},
		{Type: "cloud66", Name: "Cloud 66", Platform: "cloud66", Grammar: "<stack UID>",
			Endpoint: "https://app.cloud66.com/api/3", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: one("stack", cloud66Stack, "a Cloud 66 stack UID")},
		{Type: "circleci", Name: "CircleCI", Platform: "circleci", Grammar: "project <vcs/org/repo> | context <ID>",
			Endpoint: "https://circleci.com/api/v2", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 300,
			parse: circleCIBinding},
		{Type: "travis-ci", Name: "Travis CI", Platform: "travis-ci", Grammar: "<owner/repo or repository ID>",
			Endpoint: "https://api.travis-ci.com", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: one("repo", travisRepo, "an owner/repo slug or repository ID")},
		{Type: "bitbucket", Name: "Bitbucket Pipelines", Platform: "bitbucket", Grammar: "workspace <slug> repository <slug>",
			Endpoint: "https://api.bitbucket.org/2.0", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "workspace", rule: bitbucketSlug, what: "a workspace slug"}, pair{word: "repository", rule: bitbucketSlug, what: "a repository slug"})},
		{Type: "teamcity", Name: "TeamCity", Platform: "teamcity", Grammar: "project <external ID>",
			Keys: FlatKeys, keyRule: teamCityKey, keyHelp: "letters, digits, dots, underscores and hyphens, starting with a letter (env. names are build environment variables)", maxKey: 255,
			parse: pairs(pair{word: "project", rule: teamCityProject, what: "a project external ID"})},
		{Type: "spacelift", Name: "Spacelift", Platform: "spacelift", Grammar: "context <ID>", Credential: UserAndToken,
			Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "context", rule: lowerSlug, what: "a context ID"})},
		{Type: "humanitec", Name: "Humanitec", Platform: "humanitec", Grammar: "org <ID> app <ID>",
			Endpoint: "https://api.humanitec.io", Keys: FlatKeys, keyRule: humanitecKey, keyHelp: "letters, digits, dots, underscores and hyphens", maxKey: 255,
			parse: pairs(pair{word: "org", rule: lowerSlug, what: "an organization ID"}, pair{word: "app", rule: lowerSlug, what: "an application ID"})},
		{Type: "rundeck", Name: "Rundeck", Platform: "rundeck", Grammar: "folder <keys/...>",
			Keys: PathKeys, keyRule: rundeckKey, keyHelp: "a path of letters, digits, dots, underscores and hyphens", maxKey: 512,
			parse: pairs(pair{word: "folder", rule: rundeckFolder, what: "a Key Storage folder under keys/"})},
		{Type: "checkly", Name: "Checkly", Platform: "checkly", Grammar: "account <ID>",
			Endpoint: "https://api.checklyhq.com", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "account", rule: uuidRule, what: "a UUID"})},
		{Type: "laravel-forge", Name: "Laravel Forge", Platform: "laravel-forge", Grammar: "org <slug> server <ID> site <ID>",
			Endpoint: "https://forge.laravel.com/api", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "org", rule: forgeOrg, what: "an organization slug"}, pair{word: "server", rule: numeric, what: "a server ID"},
				pair{word: "site", rule: numeric, what: "a site ID"})},
	}
}
