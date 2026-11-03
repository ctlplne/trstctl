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
		{Type: "laravel-forge", Name: "Laravel Forge", Platform: "laravel-forge", Grammar: "org <slug> server <ID> site <ID>",
			Endpoint: "https://forge.laravel.com/api", Keys: FlatKeys, keyRule: envName, keyHelp: envNameHelp, maxKey: 255,
			parse: pairs(pair{word: "org", rule: forgeOrg, what: "an organization slug"}, pair{word: "server", rule: numeric, what: "a server ID"},
				pair{word: "site", rule: numeric, what: "a site ID"})},
	}
}
