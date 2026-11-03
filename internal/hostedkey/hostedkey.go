// SPDX-License-Identifier: BUSL-1.1

// Package hostedkey holds the role-binding grammar of the hosted API key
// providers (A240), shared by configuration validation and the providers: a
// binding names what a role's keys are created under (a project, an account,
// a deployment) and the least authority they get there, and its canonical
// form is the target a revocation reference carries.
package hostedkey

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Provider is one hosted API key provider's configuration surface.
type Provider struct {
	// Endpoint describes the URL the provider's endpoint is.
	Endpoint string
	// AdminKey describes the credential api_key_ref names.
	AdminKey string
	// Binding describes the role binding, for errors and the catalog.
	Binding string
	parse   func(string) (string, error)
}

// Providers are the hosted API key providers by type.
var Providers = map[string]Provider{
	"openrouter": {
		Endpoint: "the API, https://openrouter.ai/api/v1",
		AdminKey: "a management key, allowed to create, list and delete the account's API keys",
		Binding:  `"unlimited" or "limit <USD>", the credit limit its keys are created with`,
		parse:    openRouter,
	},
	"fireworks": {
		Endpoint: "the API, https://api.fireworks.ai",
		AdminKey: "an account administrator's API key, allowed to create, list and delete the bound users' API keys",
		Binding:  `"<account-id>/<user-id>", the user its keys are created for`,
		parse:    fireworks,
	},
	"litellm": {
		Endpoint: "the LiteLLM proxy's URL",
		AdminKey: "the proxy's master key",
		Binding:  `"all-models" or "models <name>,<name>", the models its keys may call`,
		parse:    liteLLM,
	},
	"supabase": {
		Endpoint: "the Management API, https://api.supabase.com",
		AdminKey: "an access token allowed to create, read and delete the bound projects' API keys",
		Binding:  "a project reference (twenty lower-case letters), the project its secret API keys are created in",
		parse:    supabase,
	},
	"convex": {
		Endpoint: "the Platform API, https://api.convex.dev/v1",
		AdminKey: "a team or personal access token allowed to manage the bound deployments' deploy keys",
		Binding:  `"<deployment>" or "<deployment> <action>,<action>", the deployment its deploy keys are for and the actions they are limited to`,
		parse:    convex,
	},
	"cloudflare": {
		Endpoint: "the API, https://api.cloudflare.com/client/v4",
		AdminKey: "a token allowed to read the template token and create, list and delete tokens (API Tokens Write, or Account API Tokens Write for account tokens)",
		Binding:  `"template <token-id>" (user tokens) or "account <account-id> template <token-id>" (account tokens): each key copies that template token's policies and condition`,
		parse:    cloudflare,
	},
	"cloudflare-r2": {
		Endpoint: "the API, https://api.cloudflare.com/client/v4",
		AdminKey: "a token allowed to read the template token and create, list and delete the account's tokens (Account API Tokens Write)",
		Binding:  `"account <account-id> template <token-id>": each key pair derives from a new account token that copies the template's R2 policies`,
		parse:    cloudflareR2,
	},
	"dbt": {
		Endpoint: "the account's access URL, https://cloud.getdbt.com or a regional host",
		AdminKey: "an administrator's service token (dbt refuses to create service tokens with a personal access token)",
		Binding:  `"<account-id> <permission-set>" or "<account-id> <permission-set> project <project-id>", the one grant its service tokens get`,
		parse:    dbt,
	},
}

// Types returns the provider types, sorted.
func Types() []string {
	types := make([]string, 0, len(Providers))
	for name := range Providers {
		types = append(types, name)
	}
	sort.Strings(types)
	return types
}

// ParseBinding validates a role binding of provider and returns its canonical
// form, the target keys are created under. A revocation reference is the
// canonical binding, "/" and the vendor's key ID (which never contains "/").
func ParseBinding(provider, binding string) (string, error) {
	spec, ok := Providers[provider]
	if !ok {
		return "", fmt.Errorf("hostedkey: %q is not a hosted API key provider", provider)
	}
	canonical, err := spec.parse(strings.TrimSpace(binding))
	if err != nil {
		return "", fmt.Errorf("expected %s: %w", spec.Binding, err)
	}
	return canonical, nil
}

var errShape = errors.New("the binding does not have that shape")

// openRouter reads "unlimited" or "limit <USD>" (a positive amount of at most
// one million) and returns "unlimited" or "limit-<USD>".
func openRouter(binding string) (string, error) {
	if binding == "unlimited" {
		return binding, nil
	}
	fields := strings.Fields(binding)
	if len(fields) != 2 || fields[0] != "limit" {
		return "", errShape
	}
	amount, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || amount <= 0 || amount > 1e6 {
		return "", errors.New("the limit is a positive amount of at most 1000000")
	}
	return "limit-" + strconv.FormatFloat(amount, 'f', -1, 64), nil
}

// fireworksID is an account or user ID in a Fireworks resource name.
var fireworksID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// fireworks reads "<account-id>/<user-id>" and returns
// "<account-id>:<user-id>".
func fireworks(binding string) (string, error) {
	account, user, ok := strings.Cut(binding, "/")
	if !ok || !fireworksID.MatchString(account) || !fireworksID.MatchString(user) {
		return "", errShape
	}
	return account + ":" + user, nil
}

// liteLLMModel is a model name a LiteLLM key may be limited to.
var liteLLMModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)

// liteLLM reads "all-models" or "models <name>,<name>" and returns
// "all-models" or "models:<name>,<name>".
func liteLLM(binding string) (string, error) {
	if binding == "all-models" {
		return binding, nil
	}
	fields := strings.Fields(binding)
	if len(fields) != 2 || fields[0] != "models" {
		return "", errShape
	}
	for _, model := range strings.Split(fields[1], ",") {
		if !liteLLMModel.MatchString(model) {
			return "", fmt.Errorf("%q is not a model name", model)
		}
	}
	return "models:" + fields[1], nil
}

// supabaseProjectRef is a project's reference ID.
var supabaseProjectRef = regexp.MustCompile(`^[a-z]{20}$`)

func supabase(binding string) (string, error) {
	if !supabaseProjectRef.MatchString(binding) {
		return "", errShape
	}
	return binding, nil
}

var (
	// convexDeployment is a deployment name (happy-animal-123).
	convexDeployment = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// convexAction is a deploy key's allowed action (deployment:deploy).
	convexAction = regexp.MustCompile(`^deployment(:[A-Za-z]+){1,3}$`)
)

// convex reads "<deployment>" or "<deployment> <action>,<action>" and
// returns "<deployment>" or "<deployment>:<action>,<action>".
func convex(binding string) (string, error) {
	fields := strings.Fields(binding)
	if len(fields) == 0 || len(fields) > 2 || !convexDeployment.MatchString(fields[0]) {
		return "", errShape
	}
	if len(fields) == 1 {
		return fields[0], nil
	}
	for _, action := range strings.Split(fields[1], ",") {
		if !convexAction.MatchString(action) {
			return "", fmt.Errorf("%q is not a deploy key action (deployment:deploy, say)", action)
		}
	}
	return fields[0] + ":" + fields[1], nil
}

// dbtPermissionSets are the predefined permission sets a dbt service token's
// grant may name (the v3 API's PredefinedPermissionSet).
var dbtPermissionSets = map[string]bool{
	"account_admin": true, "account_viewer": true, "admin": true, "analyst": true, "analyst_read": true,
	"billing_admin": true, "cost_insights_admin": true, "cost_insights_viewer": true, "cost_management_admin": true,
	"cost_management_viewer": true, "database_admin": true, "developer": true, "fusion_admin": true, "git_admin": true,
	"job_admin": true, "job_creator": true, "job_runner": true, "job_viewer": true, "manage_marketplace_apps": true,
	"member": true, "metadata_only": true, "notification_manager": true, "owner": true, "project_creator": true,
	"readonly": true, "scim_only": true, "security_admin": true, "semantic_layer_only": true, "stakeholder": true,
	"team_admin": true, "webhooks_only": true,
}

// dbt reads "<account-id> <permission-set>" or "<account-id> <permission-set>
// project <project-id>" and returns "<account-id>:<permission-set>" or
// "<account-id>:<permission-set>:<project-id>".
func dbt(binding string) (string, error) {
	fields := strings.Fields(binding)
	if (len(fields) != 2 && len(fields) != 4) || !NumericID(fields[0]) {
		return "", errShape
	}
	if !dbtPermissionSets[fields[1]] {
		return "", fmt.Errorf("%q is not one of dbt's predefined permission sets", fields[1])
	}
	if len(fields) == 2 {
		return fields[0] + ":" + fields[1], nil
	}
	if fields[2] != "project" || !NumericID(fields[3]) {
		return "", errShape
	}
	return fields[0] + ":" + fields[1] + ":" + fields[3], nil
}

// NumericID reports whether v is a positive decimal ID in canonical form.
func NumericID(v string) bool {
	id, err := strconv.ParseInt(v, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == v
}

// cloudflareID is a Cloudflare account or token ID.
var cloudflareID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// cloudflare reads "template <token-id>" or "account <account-id> template
// <token-id>" and returns "user:<token-id>" or "account:<account-id>:<token-id>".
func cloudflare(binding string) (string, error) {
	fields := strings.Fields(binding)
	switch {
	case len(fields) == 2 && fields[0] == "template" && cloudflareID.MatchString(fields[1]):
		return "user:" + fields[1], nil
	case len(fields) == 4 && fields[0] == "account" && fields[2] == "template" && cloudflareID.MatchString(fields[1]) && cloudflareID.MatchString(fields[3]):
		return "account:" + fields[1] + ":" + fields[3], nil
	}
	return "", errShape
}

// cloudflareR2 reads "account <account-id> template <token-id>": R2's S3
// endpoint is the account's own host.
func cloudflareR2(binding string) (string, error) {
	canonical, err := cloudflare(binding)
	if err != nil || !strings.HasPrefix(canonical, "account:") {
		return "", errShape
	}
	return canonical, nil
}
