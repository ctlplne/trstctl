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

var (
	windmillWorkspace = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)
	windmillPath      = regexp.MustCompile(`^(u|f)/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)+$`)
	zabbixMacro       = regexp.MustCompile(`^[A-Z0-9_.]+$`)
	devinOrg          = regexp.MustCompile(`^org-[A-Za-z0-9_-]{1,64}$`)
	daytonaName       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	onaName           = regexp.MustCompile(`^[0-9a-zA-Z_]{3,127}$`)
	onaScopes         = map[string]bool{"organization": true, "project": true, "user": true}
	triggerProject    = regexp.MustCompile(`^proj_[A-Za-z0-9]{4,40}$`)
	triggerEnv        = regexp.MustCompile(`^(dev|staging|prod)$`)
)

var (
	cloudflareAccount = regexp.MustCompile(`^[0-9a-f]{32}$`)
	cloudflareScript  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	pagesEnvironment  = regexp.MustCompile(`^(production|preview)$`)
	secretsStoreName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	appConfigLabel    = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)
	appConfigKey      = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
	ociID             = regexp.MustCompile(`^ocid1\.[a-z0-9]+\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9]{8,}$`)
	ociName           = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	ovhPath           = regexp.MustCompile(`^[a-zA-Z0-9_.:=@-]+(/[a-zA-Z0-9_.:=@-]+)*$`)
	databricksName    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	supabaseProject   = regexp.MustCompile(`^[a-z]{20}$`)
	camundaName       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// zabbixBinding is "global" (global macros) or "host <ID>" (one host's).
func zabbixBinding(f []string) (Binding, error) {
	switch {
	case len(f) == 1 && f[0] == "global":
		return Binding{}, nil
	case len(f) == 2 && f[0] == "host" && numeric.MatchString(f[1]):
		return Binding{"host": f[1]}, nil
	}
	return nil, errors.New("global, or host <numeric ID>")
}

// daytonaBinding is empty (the token's organization) or "organization <ID>".
func daytonaBinding(f []string) (Binding, error) {
	switch {
	case len(f) == 0:
		return Binding{}, nil
	case len(f) == 2 && f[0] == "organization" && uuidRule.MatchString(f[1]):
		return Binding{"organization": f[1]}, nil
	}
	return nil, errors.New("empty, or organization <ID>")
}

// onaBinding is "<organization|project|user> <ID>": the secrets' scope.
func onaBinding(f []string) (Binding, error) {
	if len(f) != 2 || !onaScopes[f[0]] || !uuidRule.MatchString(f[1]) {
		return nil, errors.New("organization, project or user, and its UUID")
	}
	return Binding{"scope": f[0], "id": f[1]}, nil
}

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
		{Type: "windmill", Name: "Windmill", Platform: "windmill", Grammar: "workspace <ID>",
			Endpoint: "https://app.windmill.dev/api", Keys: PathKeys, keyRule: windmillPath,
			keyHelp: "a variable path, u/<user>/<name> or f/<folder>/<name>", maxKey: 255,
			parse: pairs(pair{word: "workspace", rule: windmillWorkspace, what: "a workspace ID"})},
		{Type: "zabbix", Name: "Zabbix", Platform: "zabbix", Grammar: "global | host <ID>",
			Keys: FlatKeys, keyRule: zabbixMacro, keyHelp: "a macro name of upper-case letters, digits, underscores and dots (stored as {$NAME})", maxKey: 251,
			parse: zabbixBinding},
		{Type: "portainer", Name: "Portainer", Platform: "portainer", Grammar: "stack <ID> environment <ID>",
			Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "stack", rule: numeric, what: "a stack ID"}, pair{word: "environment", rule: numeric, what: "an environment (endpoint) ID"})},
		{Type: "devin", Name: "Devin", Platform: "devin", Grammar: "org <org-...>",
			Endpoint: "https://api.devin.ai", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "org", rule: devinOrg, what: "an organization ID (org-...)"})},
		{Type: "daytona", Name: "Daytona", Platform: "daytona", Grammar: "[organization <ID>]",
			Endpoint: "https://app.daytona.io/api", Keys: FlatKeys, keyRule: daytonaName, keyHelp: "letters, digits, hyphens and underscores", maxKey: 255,
			parse: daytonaBinding},
		{Type: "ona", Name: "Ona", Platform: "ona", Grammar: "<organization|project|user> <ID>",
			Endpoint: "https://app.ona.com/api", Keys: FlatKeys, keyRule: onaName, keyHelp: "3 to 127 letters, digits and underscores", maxKey: 127,
			parse: onaBinding},
		{Type: "trigger-dev", Name: "Trigger.dev", Platform: "trigger-dev", Grammar: "project <proj_...> env <dev|staging|prod>",
			Endpoint: "https://api.trigger.dev", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "project", rule: triggerProject, what: "a project ref (proj_...)"}, pair{word: "env", rule: triggerEnv, what: "dev, staging or prod"})},
		{Type: "cloudflare-workers", Name: "Cloudflare Workers", Platform: "cloudflare", Grammar: "account <ID> script <name>",
			Endpoint: "https://api.cloudflare.com/client/v4", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "account", rule: cloudflareAccount, what: "a 32-character account ID"}, pair{word: "script", rule: cloudflareScript, what: "a Worker script name"})},
		{Type: "cloudflare-pages", Name: "Cloudflare Pages", Platform: "cloudflare", Grammar: "account <ID> project <name> [environment production|preview]",
			Endpoint: "https://api.cloudflare.com/client/v4", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "account", rule: cloudflareAccount, what: "a 32-character account ID"}, pair{word: "project", rule: cloudflareScript, what: "a Pages project name"},
				pair{word: "environment", rule: pagesEnvironment, what: "production or preview", optional: true})},
		{Type: "cloudflare-secrets-store", Name: "Cloudflare Secrets Store", Platform: "cloudflare", Grammar: "account <ID> store <ID>",
			Endpoint: "https://api.cloudflare.com/client/v4", Keys: FlatKeys, keyRule: secretsStoreName, keyHelp: "letters, digits, underscores, dots and hyphens", maxKey: 255,
			parse: pairs(pair{word: "account", rule: cloudflareAccount, what: "a 32-character account ID"}, pair{word: "store", rule: cloudflareAccount, what: "a 32-character store ID"})},
		{Type: "azure-app-configuration", Name: "Azure App Configuration", Platform: "azure", Grammar: "[label <label>]", Credential: UserAndToken,
			Keys: FlatKeys, keyRule: appConfigKey, keyHelp: "letters, digits, underscores, dots, colons, slashes and hyphens", maxKey: 1024,
			parse: pairs(pair{word: "label", rule: appConfigLabel, what: "a label", optional: true})},
		{Type: "oci-vault", Name: "OCI Vault", Platform: "oci", Grammar: "compartment <OCID> vault <OCID> key <OCID>", Credential: UserAndToken,
			Keys: FlatKeys, keyRule: ociName, keyHelp: "letters, digits, dots, underscores and hyphens", maxKey: 255,
			parse: pairs(pair{word: "compartment", rule: ociID, what: "a compartment OCID"}, pair{word: "vault", rule: ociID, what: "a vault OCID"},
				pair{word: "key", rule: ociID, what: "a key OCID in that vault"})},
		{Type: "ovh-secret-manager", Name: "OVHcloud Secret Manager", Platform: "ovhcloud", Grammar: "okms <ID>",
			Keys: PathKeys, keyRule: ovhPath, keyHelp: "a path of letters, digits and _ . : = @ -", maxKey: 255,
			parse: pairs(pair{word: "okms", rule: uuidRule, what: "the OKMS domain UUID"})},
		{Type: "databricks-secrets", Name: "Databricks secrets", Platform: "databricks", Grammar: "scope <name>",
			Keys: FlatKeys, keyRule: databricksName, keyHelp: "up to 128 letters, digits, dots, underscores and hyphens", maxKey: 128,
			parse: pairs(pair{word: "scope", rule: databricksName, what: "a secret scope name"})},
		{Type: "supabase-secrets", Name: "Supabase Edge Function secrets", Platform: "supabase", Grammar: "project <ref>",
			Endpoint: "https://api.supabase.com", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 256, denyPrefix: []string{"SUPABASE_"},
			parse: pairs(pair{word: "project", rule: supabaseProject, what: "a 20-letter project ref"})},
		{Type: "camunda", Name: "Camunda", Platform: "camunda", Grammar: "cluster <ID>", Credential: UserAndToken,
			Endpoint: "https://api.cloud.camunda.io", Keys: FlatKeys, keyRule: camundaName, keyHelp: "letters, digits, underscores and hyphens", maxKey: 49,
			parse: pairs(pair{word: "cluster", rule: uuidRule, what: "a cluster UUID"})},
		{Type: "laravel-forge", Name: "Laravel Forge", Platform: "laravel-forge", Grammar: "org <slug> server <ID> site <ID>",
			Endpoint: "https://forge.laravel.com/api", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "org", rule: forgeOrg, what: "an organization slug"}, pair{word: "server", rule: numeric, what: "a server ID"},
				pair{word: "site", rule: numeric, what: "a site ID"})},
	}
}
