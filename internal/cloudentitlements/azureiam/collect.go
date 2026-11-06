// SPDX-License-Identifier: BUSL-1.1
package azureiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
)

type collector struct {
	graph, arm *bearerhttp.Client
	calls      int
	roles      map[string]roleDocument
	resources  map[string]resourceDocument
}
type roleDocument struct {
	ID         string `json:"id"`
	Properties struct {
		Permissions []Permission `json:"permissions"`
	} `json:"properties"`
}
type resourceDocument struct {
	ID    string `json:"id"`
	Roles []struct {
		ID      string   `json:"id"`
		Value   string   `json:"value"`
		Members []string `json:"allowedMemberTypes"`
		Enabled bool     `json:"isEnabled"`
	} `json:"appRoles"`
}

func (c *collector) read(ctx context.Context, client *bearerhttp.Client, path string, out any) error {
	if c.calls >= 500 {
		return errors.New("azure inventory call budget exceeded")
	}
	c.calls++
	return client.ReadJSON(ctx, http.MethodGet, path, nil, out)
}

// Collection cursors may change only pagination parameters. Both origin and
// exact collection path/filter/select/version remain frozen before token borrow.
func nextPage(origin, initial, next string) (string, error) {
	base, err := url.Parse(origin)
	if err != nil {
		return "", errors.New("invalid Azure origin")
	}
	first, err := url.Parse(initial)
	if err != nil {
		return "", errors.New("invalid Azure collection")
	}
	n, err := url.Parse(next)
	if err != nil || len(next) > 16384 || !n.IsAbs() || n.Scheme != base.Scheme || n.Host != base.Host || n.User != nil || n.Fragment != "" || n.Path != first.Path || n.RawPath != "" {
		return "", errors.New("azure pagination escaped its fixed origin or collection")
	}
	nq, err := url.ParseQuery(n.RawQuery)
	if err != nil {
		return "", errors.New("invalid Azure pagination query")
	}
	fq := first.Query()
	for name, values := range fq {
		if !slices.Equal(nq[name], values) {
			return "", errors.New("azure pagination changed the original selection")
		}
	}
	for name, values := range nq {
		if len(values) != 1 || len(values[0]) > 8192 {
			return "", errors.New("invalid Azure pagination value")
		}
		if _, ok := fq[name]; !ok && name != "$skiptoken" && name != "$skip" && name != "skiptoken" {
			return "", errors.New("unapproved Azure pagination parameter")
		}
	}
	return n.RequestURI(), nil
}
func list[T any](ctx context.Context, c *collector, client *bearerhttp.Client, origin, path string, max int) ([]T, error) {
	current := path
	seen := map[string]bool{}
	var out []T
	for n := 0; n < 10; n++ {
		var page struct {
			Items     []T    `json:"value"`
			GraphNext string `json:"@odata.nextLink"`
			ARMNext   string `json:"nextLink"`
		}
		if err := c.read(ctx, client, current, &page); err != nil {
			return nil, err
		}
		if len(page.Items) > 1000 || len(out)+len(page.Items) > max {
			return nil, errors.New("azure collection exceeds item budget")
		}
		out = append(out, page.Items...)
		next := page.GraphNext
		if next == "" {
			next = page.ARMNext
		} else if page.ARMNext != "" {
			return nil, errors.New("ambiguous Azure pagination")
		}
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, errors.New("repeated Azure cursor")
		}
		seen[next] = true
		var err error
		current, err = nextPage(origin, path, next)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("azure pagination budget reached")
}
func query(path string, values url.Values) string { return path + "?" + values.Encode() }
func selected(path, fields string) string         { return query(path, url.Values{"$select": {fields}}) }
func Collect(ctx context.Context, cfg Config, graphBorrow, armBorrow bearerhttp.Borrow, now time.Time) ([]Inventory, error) {
	raw, _ := json.Marshal(cfg)
	var err error
	cfg, err = DecodeConfig(raw)
	if err != nil {
		return nil, err
	}
	hash, err := SourceFingerprint(cfg)
	if err != nil {
		return nil, err
	}
	c := collector{roles: map[string]roleDocument{}, resources: map[string]resourceDocument{}}
	c.graph, err = bearerhttp.New(bearerhttp.Config{Endpoint: cfg.GraphEndpoint, CAPEM: []byte(cfg.CAPEM), AllowInsecureLoopback: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes(cfg), UseToken: graphBorrow})
	if err != nil {
		return nil, err
	}
	c.arm, err = bearerhttp.New(bearerhttp.Config{Endpoint: cfg.ARMEndpoint, CAPEM: []byte(cfg.CAPEM), AllowInsecureLoopback: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes(cfg), UseToken: armBorrow})
	if err != nil {
		return nil, err
	}
	organizations, err := list[struct {
		ID string `json:"id"`
	}](ctx, &c, c.graph, cfg.GraphEndpoint, selected("/v1.0/organization", "id"), 1)
	if err != nil || len(organizations) != 1 || organizations[0].ID != cfg.TenantID {
		return nil, errors.New("native Graph organization is unavailable or does not match the selected tenant")
	}
	var subscription struct {
		ID     string `json:"subscriptionId"`
		Tenant string `json:"tenantId"`
	}
	if err := c.read(ctx, c.arm, "/subscriptions/"+cfg.SubscriptionID+"?api-version=2022-12-01", &subscription); err != nil || subscription.ID != cfg.SubscriptionID || subscription.Tenant != cfg.TenantID {
		return nil, errors.New("native ARM subscription is unavailable or does not match the selected tenant/subscription")
	}
	var out []Inventory
	var failures []string
	total := 0
	for _, id := range cfg.PrincipalIDs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		v := Inventory{Version: 1, Provider: "azure-entra", TenantID: cfg.TenantID, SubscriptionID: cfg.SubscriptionID, SourceOrigin: cfg.GraphEndpoint, SourceFingerprint: hash, CollectedAt: now.UTC(), AppRoleCoverage: "unavailable", FederationCoverage: "unavailable", RBACCoverage: "unavailable", ManagedIdentityCoverage: "unavailable", ActivityCoverage: "unavailable", Limitations: []string{"Selected workload principals, captured app roles and subscription-scoped RBAC only; inherited guards, deny assignments, PIM activation, resource constraints and conditional access are not evaluated. Effective access is unknown."}}
		base := "/v1.0/servicePrincipals/" + id
		var native struct {
			ID      string `json:"id"`
			AppID   string `json:"appId"`
			Name    string `json:"displayName"`
			Type    string `json:"servicePrincipalType"`
			Enabled bool   `json:"accountEnabled"`
			Keys    []struct {
				ID    string    `json:"keyId"`
				Start time.Time `json:"startDateTime"`
				End   time.Time `json:"endDateTime"`
			} `json:"keyCredentials"`
			Passwords []struct {
				ID    string    `json:"keyId"`
				Start time.Time `json:"startDateTime"`
				End   time.Time `json:"endDateTime"`
			} `json:"passwordCredentials"`
		}
		if err := c.read(ctx, c.graph, selected(base, "id,appId,displayName,servicePrincipalType,accountEnabled,keyCredentials,passwordCredentials"), &native); err != nil {
			failures = append(failures, "selected service-principal read unavailable")
			continue
		}
		v.Identity = Identity{ID: native.ID, AppID: native.AppID, Name: native.Name, Type: native.Type, Enabled: native.Enabled}
		for _, key := range native.Keys {
			v.Identity.Keys = append(v.Identity.Keys, Credential{ID: key.ID, Start: key.Start, End: key.End})
		}
		for _, key := range native.Passwords {
			v.Identity.Passwords = append(v.Identity.Passwords, Credential{ID: key.ID, Start: key.Start, End: key.End})
		}
		if v.Identity.ID != id || !uuid.MatchString(v.Identity.AppID) || (v.Identity.Type != "Application" && v.Identity.Type != "ManagedIdentity") {
			failures = append(failures, "native selected service-principal identity mismatch")
			continue
		}
		if err := validateCredentials(v.Identity.Keys, v.Identity.Passwords, now); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, keys := range [][]Credential{v.Identity.Keys, v.Identity.Passwords} {
			for i := range keys {
				keys[i].AgeDays = max(0, int(now.Sub(keys[i].Start)/(24*time.Hour)))
				keys[i].LongLived = keys[i].AgeDays >= 90
				keys[i].LastUseCoverage = "unavailable"
				keys[i].Kind = "certificate"
				if keys[i].LongLived {
					v.RiskScore = 30
				}
			}
		}
		for i := range v.Identity.Passwords {
			v.Identity.Passwords[i].Kind = "client_secret"
		}
		if err := c.appRoles(ctx, cfg, base, &v); err != nil {
			v.Limitations = append(v.Limitations, "App-role assignments or referenced definitions unavailable or invalid.")
		}
		if v.Identity.Type == "Application" {
			federation, err := list[Federation](ctx, &c, c.graph, cfg.GraphEndpoint, selected("/v1.0/applications(appId='"+v.Identity.AppID+"')/federatedIdentityCredentials", "id,name,issuer,subject,audiences"), 100)
			if err == nil {
				v.Federation = federation
				v.FederationCoverage = "application_registration_only"
			} else {
				v.Limitations = append(v.Limitations, "Application federation unavailable; application ownership and permissions may differ from service-principal visibility.")
			}
			v.ManagedIdentityCoverage = "not_applicable"
		} else {
			v.FederationCoverage = "unavailable"
			c.managed(ctx, cfg, &v)
		}
		if err := c.rbac(ctx, cfg, &v); err != nil {
			v.Limitations = append(v.Limitations, "Subscription RBAC assignments or role definitions unavailable or invalid.")
		}
		if cfg.ReadBetaSignins {
			c.activity(ctx, cfg, now, &v)
		} else {
			v.Limitations = append(v.Limitations, "Workload sign-in beta reads disabled; credential last use is unknown.")
		}
		if err := validateInventory(v); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		encoded, err := json.Marshal(v)
		total += len(encoded)
		if err != nil || len(encoded) > 512<<10 || total > 16<<20 {
			return out, errors.New("azure captured public metadata exceeds event or run budget")
		}
		out = append(out, v)
	}
	if len(failures) > 0 {
		return out, errors.New(strings.Join(failures, "; "))
	}
	return out, nil
}
func validateCredentials(keys, passwords []Credential, now time.Time) error {
	if len(keys)+len(passwords) > 200 {
		return errors.New("azure credential metadata exceeds bound")
	}
	seen := map[string]bool{}
	for _, group := range [][]Credential{keys, passwords} {
		for _, key := range group {
			if !uuid.MatchString(key.ID) || seen[key.ID] || key.Start.IsZero() || key.End.IsZero() || key.End.Before(key.Start) || key.Start.After(now.AddDate(10, 0, 0)) {
				return errors.New("native Azure credential identity or dates invalid")
			}
			seen[key.ID] = true
		}
	}
	return nil
}
func (c *collector) appRoles(ctx context.Context, cfg Config, base string, v *Inventory) error {
	assignments, err := list[AppRole](ctx, c, c.graph, cfg.GraphEndpoint, selected(base+"/appRoleAssignments", "id,principalId,resourceId,appRoleId"), 2000)
	if err != nil {
		return err
	}
	for i := range assignments {
		a := &assignments[i]
		if a.PrincipalID != v.Identity.ID || !uuid.MatchString(a.ResourceID) || !uuid.MatchString(a.RoleID) {
			return errors.New("foreign app-role binding")
		}
		a.Coverage = "unavailable"
		a.Value = ""
		a.AllowedMemberTypes = nil
		a.Enabled = false
		resource, ok := c.resources[a.ResourceID]
		if !ok {
			if len(c.resources) >= 128 {
				return errors.New("azure app-resource budget exceeded")
			}
			err := c.read(ctx, c.graph, selected("/v1.0/servicePrincipals/"+a.ResourceID, "id,appRoles"), &resource)
			if err == nil && resource.ID == a.ResourceID && len(resource.Roles) <= 1000 {
				c.resources[a.ResourceID] = resource
				ok = true
			}
		}
		if ok {
			for _, r := range resource.Roles {
				if r.ID == a.RoleID {
					a.Value = r.Value
					a.AllowedMemberTypes = r.Members
					a.Enabled = r.Enabled
					a.Coverage = "resource_app_role_definition"
					break
				}
			}
		}
	}
	v.AppRoles = assignments
	v.AppRoleCoverage = "selected_principal_assignments_only"
	return nil
}
func (c *collector) rbac(ctx context.Context, cfg Config, v *Inventory) error {
	path := query("/subscriptions/"+cfg.SubscriptionID+"/providers/Microsoft.Authorization/roleAssignments", url.Values{"api-version": {"2022-04-01"}, "$filter": {"principalId eq '" + v.Identity.ID + "'"}})
	assignments, err := list[RoleAssignment](ctx, c, c.arm, cfg.ARMEndpoint, path, 2000)
	if err != nil {
		return err
	}
	for i := range assignments {
		a := &assignments[i]
		if a.Properties.PrincipalID != v.Identity.ID || !validScope(a.Properties.Scope, cfg.SubscriptionID) || !roleDefinition(a.Properties.RoleDefinitionID) {
			return errors.New("foreign or invalid RBAC binding")
		}
		a.DefinitionCoverage = "unavailable"
		a.Permissions = nil
		role, ok := c.roles[a.Properties.RoleDefinitionID]
		if !ok {
			if len(c.roles) >= 128 {
				return errors.New("azure role-definition budget exceeded")
			}
			err := c.read(ctx, c.arm, a.Properties.RoleDefinitionID+"?api-version=2022-04-01", &role)
			if err == nil && strings.EqualFold(role.ID, a.Properties.RoleDefinitionID) && len(role.Properties.Permissions) <= 100 {
				c.roles[a.Properties.RoleDefinitionID] = role
				ok = true
			}
		}
		if ok {
			a.Permissions = role.Properties.Permissions
			a.DefinitionCoverage = "role_definition_only"
		}
	}
	v.RBAC = assignments
	v.RBACCoverage = "subscription_principal_filter_only"
	return nil
}
func (c *collector) managed(ctx context.Context, cfg Config, v *Inventory) {
	path := cfg.ManagedIdentityResources[v.Identity.ID]
	if path == "" {
		v.Limitations = append(v.Limitations, "ManagedIdentity Graph type observed; native ARM resource linkage and system-assigned identity federation are unknown.")
		return
	}
	var document struct {
		ID         string `json:"id"`
		Properties struct {
			Principal string `json:"principalId"`
			Tenant    string `json:"tenantId"`
			Client    string `json:"clientId"`
		} `json:"properties"`
	}
	if err := c.read(ctx, c.arm, path+"?api-version=2023-01-31", &document); err != nil || !strings.EqualFold(document.ID, path) || document.Properties.Principal != v.Identity.ID || document.Properties.Tenant != cfg.TenantID || document.Properties.Client != v.Identity.AppID {
		v.Limitations = append(v.Limitations, "Configured managed-identity ARM resource could not be bound to this native principal/tenant/client.")
		return
	}
	v.ManagedIdentityResource = path
	v.ManagedIdentityCoverage = "native_user_assigned_resource"
	records, err := list[struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Properties Federation `json:"properties"`
	}](ctx, c, c.arm, cfg.ARMEndpoint, path+"/federatedIdentityCredentials?api-version=2023-01-31", 100)
	if err != nil {
		v.Limitations = append(v.Limitations, "User-assigned identity federation read unavailable.")
		return
	}
	for _, r := range records {
		if !strings.HasPrefix(r.ID, path+"/federatedIdentityCredentials/") || len(r.Name) > 256 {
			return
		}
		f := r.Properties
		f.ID = r.ID
		f.Name = r.Name
		v.Federation = append(v.Federation, f)
	}
	v.FederationCoverage = "user_assigned_identity_resource_only"
}
func (c *collector) activity(ctx context.Context, cfg Config, now time.Time, v *Inventory) {
	start, end := now.Add(-time.Duration(cfg.ActivityLookbackDays)*24*time.Hour).UTC(), now.UTC()
	v.ActivityStart = &start
	v.ActivityEnd = &end
	v.Limitations = append(v.Limitations, "Workload sign-in API is beta, observed-only and subject to tenant permissions/license/retention; missing credential IDs and events do not prove non-use.")
	filter := "(createdDateTime ge " + start.Format(time.RFC3339) + " and createdDateTime le " + end.Format(time.RFC3339) + ") and servicePrincipalId eq '" + v.Identity.ID + "' and signInEventTypes/any(t: t eq 'servicePrincipal' or t eq 'managedIdentity')"
	path := query("/beta/auditLogs/signIns", url.Values{"$filter": {filter}, "$top": {"1000"}, "$select": {"createdDateTime,servicePrincipalId,appId,servicePrincipalCredentialKeyId,signInEventTypes,status"}})
	type entry struct {
		At        time.Time `json:"createdDateTime"`
		Principal string    `json:"servicePrincipalId"`
		App       string    `json:"appId"`
		Key       string    `json:"servicePrincipalCredentialKeyId"`
		Types     []string  `json:"signInEventTypes"`
		Status    struct {
			Code *int `json:"errorCode"`
		} `json:"status"`
	}
	entries, err := list[entry](ctx, c, c.graph, cfg.GraphEndpoint, path, 10000)
	if err != nil {
		v.Limitations = append(v.Limitations, "Beta workload sign-ins unavailable or incomplete.")
		return
	}
	v.ActivityCoverage = "beta_observed_only"
	for _, group := range [][]Credential{v.Identity.Keys, v.Identity.Passwords} {
		for i := range group {
			group[i].LastUseCoverage = "beta_observed_only"
		}
	}
	for _, e := range entries {
		if e.Principal != v.Identity.ID || e.App != v.Identity.AppID || e.Status.Code == nil || *e.Status.Code != 0 || e.At.Before(start) || e.At.After(end) || (!slices.Contains(e.Types, "servicePrincipal") && !slices.Contains(e.Types, "managedIdentity")) {
			continue
		}
		for _, group := range [][]Credential{v.Identity.Keys, v.Identity.Passwords} {
			for i := range group {
				if group[i].ID == e.Key && (group[i].LastObservedUse == nil || e.At.After(*group[i].LastObservedUse)) {
					at := e.At.UTC()
					group[i].LastObservedUse = &at
				}
			}
		}
	}
}
