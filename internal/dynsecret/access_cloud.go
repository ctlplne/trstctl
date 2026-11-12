// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/cloudhttp"
)

// Access target kinds for cluster and cloud identities (G2-L2).
const (
	AccessTargetKubernetesNamespace = "kubernetes_namespace"
	AccessTargetGCPServiceAccount   = "gcp_service_account"
	AccessTargetAzureApplication    = "azure_application"
)

// httpAccessError classifies a cloud API error without keeping its text:
// 401/403 is denied, missing is a login the target no longer has, another
// 4xx is unreadable, a timeout is a timeout, and anything else unreachable.
func httpAccessError(err error, missing bool) error {
	var status *cloudhttp.StatusError
	switch {
	case missing:
		return ErrAccessLoginMissing
	case errors.As(err, &status) && (status.StatusCode == 401 || status.StatusCode == 403):
		return ErrAccessDenied
	case errors.As(err, &status) && status.StatusCode < 500:
		return ErrAccessUnreadable
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrAccessUnreachable
	}
}

type kubernetesSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type kubernetesBinding struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Subjects []kubernetesSubject `json:"subjects"`
	RoleRef  struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
}

type kubernetesRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

// ResolveAccess reads what the lease's ServiceAccount may do, as the cluster's
// RBAC states it: every RoleBinding in the provider's namespace and every
// ClusterRoleBinding whose subjects name the account, each with the rules of
// the role it binds. A replaced account (another UID under the lease's name)
// is not the lease's login.
func (b *KubernetesBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetKubernetesNamespace, TargetRef: kubernetesTargetRef(b.endpoint, b.namespace)}
	var ref kubernetesProviderRef
	if err := json.Unmarshal([]byte(backendRef), &ref); err != nil || ref.Name == "" {
		return access, fmt.Errorf("%w: the lease names no service account", ErrAccessLoginMissing)
	}
	access.Login = "system:serviceaccount:" + b.namespace + ":" + ref.Name
	var account kubernetesObject
	if err := b.json(ctx, "GET", "/api/v1/namespaces/"+pathEscape(b.namespace)+"/serviceaccounts/"+pathEscape(ref.Name), nil, &account); err != nil {
		return access, httpAccessError(err, statusIs(err, 404))
	}
	if ref.ServiceAccountUID != "" && account.Metadata.UID != ref.ServiceAccountUID {
		return access, ErrAccessLoginMissing
	}
	subject := kubernetesSubject{Kind: "ServiceAccount", Name: ref.Name, Namespace: b.namespace}
	var grants []string
	for _, scope := range []struct {
		list, roleKind string
		namespaced     bool
	}{
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + pathEscape(b.namespace) + "/rolebindings", "", true},
		{"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "", false},
	} {
		var bindings struct {
			Items []kubernetesBinding `json:"items"`
		}
		if err := b.json(ctx, "GET", scope.list, nil, &bindings); err != nil {
			return access, httpAccessError(err, false)
		}
		for _, binding := range bindings.Items {
			if !kubernetesBindingNames(binding, subject) {
				continue
			}
			rules, err := b.kubernetesRoleRules(ctx, binding.RoleRef.Kind, binding.RoleRef.Name)
			if err != nil {
				return access, err
			}
			where := "cluster-wide"
			if scope.namespaced {
				where = "in namespace " + b.namespace
			}
			for _, rule := range rules {
				grants = append(grants, binding.RoleRef.Kind+" "+binding.RoleRef.Name+" "+where+": "+kubernetesRuleText(rule))
			}
		}
	}
	return boundGrants(access, grants), nil
}

func (b *KubernetesBackend) kubernetesRoleRules(ctx context.Context, kind, name string) ([]kubernetesRule, error) {
	var path string
	switch kind {
	case "Role":
		path = "/apis/rbac.authorization.k8s.io/v1/namespaces/" + pathEscape(b.namespace) + "/roles/" + pathEscape(name)
	case "ClusterRole":
		path = "/apis/rbac.authorization.k8s.io/v1/clusterroles/" + pathEscape(name)
	default:
		return nil, ErrAccessUnreadable
	}
	var role struct {
		Rules []kubernetesRule `json:"rules"`
	}
	if err := b.json(ctx, "GET", path, nil, &role); err != nil {
		if statusIs(err, 404) {
			return nil, nil // a binding to a role that does not exist grants nothing
		}
		return nil, httpAccessError(err, false)
	}
	return role.Rules, nil
}

// kubernetesBindingNames reports whether a binding's subjects name the
// account. A ServiceAccount subject without a namespace is in the binding's
// own namespace, which for a RoleBinding is the provider's.
func kubernetesBindingNames(binding kubernetesBinding, account kubernetesSubject) bool {
	for _, s := range binding.Subjects {
		if s.Kind == "ServiceAccount" && s.Name == account.Name && (s.Namespace == account.Namespace || s.Namespace == "") {
			return true
		}
	}
	return false
}

// kubernetesRuleText states one RBAC rule: "get, list on pods, services",
// with its API groups and resource names when it has them, or the
// non-resource URLs it allows.
func kubernetesRuleText(rule kubernetesRule) string {
	verbs := strings.Join(rule.Verbs, ", ")
	if len(rule.NonResourceURLs) > 0 {
		return verbs + " on " + strings.Join(rule.NonResourceURLs, ", ")
	}
	text := verbs + " on " + strings.Join(rule.Resources, ", ")
	var groups []string
	for _, g := range rule.APIGroups {
		if g != "" {
			groups = append(groups, g)
		}
	}
	if len(groups) > 0 {
		text += " (" + strings.Join(groups, ", ") + ")"
	}
	if len(rule.ResourceNames) > 0 {
		text += " named " + strings.Join(rule.ResourceNames, ", ")
	}
	return text
}

// kubernetesTargetRef names the cluster API and namespace, without the
// credentials: kubernetes://host[:port]/namespaces/<namespace>.
func kubernetesTargetRef(endpoint, namespace string) string {
	host := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	return "kubernetes://" + host + "/namespaces/" + namespace
}

// GCPPolicyEndpoint is where a gcp-iam provider reads its project's IAM
// policy by default (Resource Manager).
const GCPPolicyEndpoint = "https://cloudresourcemanager.googleapis.com"

// ResolveAccess reads the roles the provider's project grants the service
// account the lease's key belongs to: the project IAM policy's bindings whose
// members name serviceAccount:<email>, read from Resource Manager. The key
// must still exist; a deleted key is not the lease's login. Grants on
// folders, the organization or single resources are not read.
func (b *GCPIAMBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetGCPServiceAccount, TargetRef: "gcp://projects/" + b.project + "/serviceAccounts/" + b.serviceAccountEmail,
		Login: strings.TrimSpace(backendRef)}
	keyID, ok := strings.CutPrefix(access.Login, "projects/"+b.project+"/serviceAccounts/"+b.serviceAccountEmail+"/keys/")
	if !ok || !gcpKeyID.MatchString(keyID) {
		return access, fmt.Errorf("%w: the lease names no key of the bound service account", ErrAccessLoginMissing)
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET", "/v1/"+access.Login, nil, &struct{}{}); err != nil {
		return access, httpAccessError(err, statusIs(err, 404))
	}
	var policy struct {
		Bindings []struct {
			Role      string   `json:"role"`
			Members   []string `json:"members"`
			Condition *struct {
				Title string `json:"title"`
			} `json:"condition"`
		} `json:"bindings"`
	}
	body := map[string]any{"options": map[string]int{"requestedPolicyVersion": 3}}
	if err := gcpJSON(ctx, b.policyDoer, b.policyEndpoint, b.tokenBytes(), "POST", "/v1/projects/"+url.PathEscape(b.project)+":getIamPolicy", body, &policy); err != nil {
		return access, httpAccessError(err, false)
	}
	member := "serviceAccount:" + b.serviceAccountEmail
	var grants []string
	for _, binding := range policy.Bindings {
		for _, m := range binding.Members {
			if m != member {
				continue
			}
			grant := "role " + binding.Role + " on project " + b.project
			if binding.Condition != nil && binding.Condition.Title != "" {
				grant += " when " + binding.Condition.Title
			}
			grants = append(grants, grant)
		}
	}
	return boundGrants(access, grants), nil
}

// ResolveAccess reads what the application the lease's client secret belongs
// to may do in the directory: its service principal's app role assignments
// (each role's value on the API that defines it) and the directory roles it
// is a member of, from Microsoft Graph. The secret must still be on the
// application. Azure resource (ARM) role assignments are not read.
func (b *AzureEntraBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetAzureApplication, TargetRef: "azure://applications/" + b.applicationObjectID, Login: strings.TrimSpace(backendRef)}
	if access.Login == "" {
		return access, fmt.Errorf("%w: the lease names no client secret", ErrAccessLoginMissing)
	}
	var app struct {
		AppID               string `json:"appId"`
		PasswordCredentials []struct {
			KeyID string `json:"keyId"`
		} `json:"passwordCredentials"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET",
		"/v1.0/applications/"+pathEscape(b.applicationObjectID)+"?$select=appId,passwordCredentials", nil, &app); err != nil {
		return access, httpAccessError(err, statusIs(err, 404))
	}
	present := false
	for _, p := range app.PasswordCredentials {
		present = present || p.KeyID == access.Login
	}
	if !present {
		return access, ErrAccessLoginMissing
	}
	appID := firstNonEmptyString(b.applicationClientID, app.AppID)
	var principals struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET",
		"/v1.0/servicePrincipals?$filter="+url.QueryEscape("appId eq '"+strings.ReplaceAll(appID, "'", "''")+"'")+"&$select=id", nil, &principals); err != nil {
		return access, httpAccessError(err, false)
	}
	if len(principals.Value) == 0 {
		return boundGrants(access, nil), nil // no service principal: the application holds no role in this directory
	}
	principal := principals.Value[0].ID
	var assignments struct {
		Value []struct {
			ResourceID          string `json:"resourceId"`
			ResourceDisplayName string `json:"resourceDisplayName"`
			AppRoleID           string `json:"appRoleId"`
		} `json:"value"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET", "/v1.0/servicePrincipals/"+pathEscape(principal)+"/appRoleAssignments", nil, &assignments); err != nil {
		return access, httpAccessError(err, false)
	}
	roleValues := map[string]map[string]string{} // resource → app role ID → value
	var grants []string
	for _, a := range assignments.Value {
		values, ok := roleValues[a.ResourceID]
		if !ok {
			var resource struct {
				AppRoles []struct {
					ID    string `json:"id"`
					Value string `json:"value"`
				} `json:"appRoles"`
			}
			if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET", "/v1.0/servicePrincipals/"+pathEscape(a.ResourceID)+"?$select=appRoles", nil, &resource); err != nil {
				return access, httpAccessError(err, false)
			}
			values = map[string]string{}
			for _, r := range resource.AppRoles {
				values[r.ID] = r.Value
			}
			roleValues[a.ResourceID] = values
		}
		grants = append(grants, "app role "+firstNonEmptyString(values[a.AppRoleID], a.AppRoleID)+" on "+a.ResourceDisplayName)
	}
	var memberOf struct {
		Value []struct {
			ODataType   string `json:"@odata.type"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), "GET", "/v1.0/servicePrincipals/"+pathEscape(principal)+"/memberOf", nil, &memberOf); err != nil {
		return access, httpAccessError(err, false)
	}
	for _, m := range memberOf.Value {
		switch m.ODataType {
		case "#microsoft.graph.directoryRole":
			grants = append(grants, "directory role "+m.DisplayName)
		case "#microsoft.graph.group":
			grants = append(grants, "member of group "+m.DisplayName)
		}
	}
	return boundGrants(access, grants), nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
