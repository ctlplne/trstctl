// SPDX-License-Identifier: BUSL-1.1
package gcpiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
)

type collector struct {
	iam, resource, logs *bearerhttp.Client
	calls               int
	roles               map[string]roleDefinition
}
type roleDefinition struct {
	Name        string   `json:"name"`
	Permissions []string `json:"includedPermissions"`
	Deleted     bool     `json:"deleted"`
}

func (c *collector) read(ctx context.Context, client *bearerhttp.Client, method, path string, body []byte, out any) error {
	if c.calls >= 500 {
		return errors.New("GCP inventory call budget exceeded")
	}
	c.calls++
	return client.ReadJSON(ctx, method, path, body, out)
}
func Collect(ctx context.Context, cfg Config, borrow bearerhttp.Borrow, now time.Time) ([]Inventory, error) {
	configuration, _ := json.Marshal(cfg)
	var err error
	cfg, err = DecodeConfig(configuration)
	if err != nil {
		return nil, err
	}
	sourceHash, err := SourceFingerprint(cfg)
	if err != nil {
		return nil, err
	}
	c := collector{roles: map[string]roleDefinition{}}
	for _, target := range []struct {
		endpoint string
		client   **bearerhttp.Client
	}{{cfg.IAMEndpoint, &c.iam}, {cfg.ResourceManagerEndpoint, &c.resource}, {cfg.LoggingEndpoint, &c.logs}} {
		client, err := bearerhttp.New(bearerhttp.Config{Endpoint: target.endpoint, CAPEM: []byte(cfg.CAPEM), AllowInsecureLoopback: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes(cfg), UseToken: borrow})
		if err != nil {
			return nil, err
		}
		*target.client = client
	}
	var projectPolicy Policy
	projectErr := c.read(ctx, c.resource, http.MethodPost, metadataFields("/v1/projects/"+url.PathEscape(cfg.Project)+":getIamPolicy", "version,etag,bindings(role,members,condition)"), []byte(`{"options":{"requestedPolicyVersion":3}}`), &projectPolicy)
	if projectErr == nil {
		projectErr = validatePolicy(projectPolicy)
	}
	var out []Inventory
	var failures []string
	for _, email := range cfg.ServiceAccounts {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		base := "/v1/projects/" + url.PathEscape(cfg.Project) + "/serviceAccounts/" + url.PathEscape(email)
		v := Inventory{Version: 1, Provider: "gcp-iam", SourceOrigin: cfg.IAMEndpoint, SourceFingerprint: sourceHash, CollectedAt: now.UTC(), KeysCoverage: "unavailable", TrustCoverage: "unavailable", PolicyCoverage: "unavailable", ActivityCoverage: "unavailable", Limitations: []string{"Selected service accounts and project policy only; inherited organization/folder/resource policies, deny rules and principal-access boundaries are not evaluated. Captured bindings do not establish effective permissions."}}
		if err := c.read(ctx, c.iam, http.MethodGet, metadataFields(base, "name,projectId,uniqueId,email,displayName,disabled"), nil, &v.Identity); err != nil {
			failures = append(failures, "selected account read unavailable")
			continue
		}
		if v.Identity.Email != email || v.Identity.Project != cfg.Project || !digits(v.Identity.NativeID) || (v.Identity.Name != "projects/"+cfg.Project+"/serviceAccounts/"+email && v.Identity.Name != "projects/"+cfg.Project+"/serviceAccounts/"+v.Identity.NativeID) {
			failures = append(failures, "native selected service-account identity mismatch")
			continue
		}
		var keys struct {
			Keys []Key `json:"keys"`
		}
		if err := c.read(ctx, c.iam, http.MethodGet, metadataFields(base+"/keys?keyTypes=USER_MANAGED", "keys(name,keyType,keyOrigin,validAfterTime,validBeforeTime,disabled)"), nil, &keys); err != nil {
			v.Limitations = append(v.Limitations, "User-managed key metadata unavailable.")
		} else if err := validateKeys(keys.Keys, cfg.Project, email, v.Identity.NativeID, now); err != nil {
			failures = append(failures, err.Error())
			continue
		} else {
			v.Keys = keys.Keys
			v.KeysCoverage = "complete_selected_account_user_managed"
			for i := range v.Keys {
				age := int(now.Sub(v.Keys[i].ValidAfter) / (24 * time.Hour))
				if age < 0 {
					age = 0
				}
				v.Keys[i].AgeDays = age
				v.Keys[i].LongLived = age >= 90
				v.Keys[i].LastUseCoverage = "unavailable"
				if v.Keys[i].LongLived && !v.Keys[i].Disabled {
					v.RiskScore = 30
				}
			}
		}
		if err := c.read(ctx, c.iam, http.MethodPost, metadataFields(base+":getIamPolicy?options.requestedPolicyVersion=3", "version,etag,bindings(role,members,condition)"), nil, &v.TrustPolicy); err != nil {
			v.Limitations = append(v.Limitations, "Service-account trust/delegation policy unavailable.")
		} else if err := validatePolicy(v.TrustPolicy); err != nil {
			failures = append(failures, err.Error())
			continue
		} else {
			v.TrustCoverage = "complete_account_policy_only"
		}
		if projectErr != nil {
			v.Limitations = append(v.Limitations, "Project IAM policy unavailable; resource role bindings are unknown.")
		} else {
			v.PolicyCoverage = "project_policy_only"
			for _, binding := range projectPolicy.Bindings {
				if !contains(binding.Members, "serviceAccount:"+email) {
					continue
				}
				item := RoleBinding{Role: binding.Role, Scope: "projects/" + cfg.Project, Condition: binding.Condition, PolicyETag: projectPolicy.ETag, PermissionCoverage: "unavailable"}
				role, found := c.roles[binding.Role]
				if !found {
					if len(c.roles) >= 128 {
						return out, errors.New("GCP role-definition budget exceeded")
					}
					err := c.read(ctx, c.iam, http.MethodGet, metadataFields("/v1/"+binding.Role, "name,includedPermissions,deleted"), nil, &role)
					if err == nil && role.Name == binding.Role && !role.Deleted && len(role.Permissions) <= 10000 {
						c.roles[binding.Role] = role
						found = true
					}
				}
				if found {
					item.Permissions = role.Permissions
					item.PermissionCoverage = "role_definition_only"
				} else {
					v.Limitations = append(v.Limitations, "Referenced role definition unavailable; its permissions are unknown.")
				}
				v.PolicyBindings = append(v.PolicyBindings, item)
			}
		}
		if cfg.ActivityLookbackDays > 0 {
			c.activity(ctx, cfg, email, now, &v)
		} else {
			v.Limitations = append(v.Limitations, "Audit activity read disabled; last use is unknown.")
		}
		raw, err := json.Marshal(v)
		if err != nil || len(raw) > 512<<10 {
			return out, errors.New("GCP selected-account inventory exceeds event bound")
		}
		out = append(out, v)
	}
	if len(failures) > 0 {
		return out, errors.New(strings.Join(failures, "; "))
	}
	return out, nil
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func validatePolicy(p Policy) error {
	if p.Version != 0 && p.Version != 1 && p.Version != 3 || len(p.Bindings) > 2000 || len(p.ETag) > 1024 {
		return errors.New("invalid bounded GCP IAM policy")
	}
	for _, b := range p.Bindings {
		if !roleName.MatchString(b.Role) || len(b.Members) > 2000 {
			return errors.New("invalid bounded GCP policy binding")
		}
		if b.Condition != nil && (p.Version != 3 || len(b.Condition.Expression) > 8192) {
			return errors.New("conditional GCP policy lacks version 3 or exceeds bound")
		}
	}
	return nil
}
func validateKeys(keys []Key, project, email, nativeID string, now time.Time) error {
	if len(keys) > 100 {
		return errors.New("GCP key metadata exceeds bound")
	}
	seen := map[string]bool{}
	for _, key := range keys {
		parts := strings.Split(key.Name, "/")
		if len(parts) != 6 || parts[0] != "projects" || (parts[1] != project && parts[1] != "-") || parts[2] != "serviceAccounts" || (parts[3] != email && parts[3] != nativeID) || parts[4] != "keys" || len(parts[5]) < 1 || len(parts[5]) > 128 || strings.ContainsAny(parts[5], "?#%\\\x00") || seen[key.Name] || key.Type != "USER_MANAGED" || key.ValidAfter.IsZero() || key.ValidBefore.IsZero() || key.ValidBefore.Before(key.ValidAfter) || key.ValidAfter.After(now.Add(time.Minute)) {
			return errors.New("native GCP key identity or time bound mismatch")
		}
		seen[key.Name] = true
	}
	return nil
}
func (c *collector) activity(ctx context.Context, cfg Config, email string, now time.Time, v *Inventory) {
	start, end := now.Add(-time.Duration(cfg.ActivityLookbackDays)*24*time.Hour).UTC(), now.UTC()
	v.ActivityStart = &start
	v.ActivityEnd = &end
	v.Limitations = append(v.Limitations, "Audit activity is observed-only: retention, service coverage and omitted key names prevent proof of non-use.")
	page := ""
	seen := map[string]bool{}
	for n := 0; n < 10; n++ {
		body, _ := json.Marshal(map[string]any{"resourceNames": []string{"projects/" + cfg.Project}, "filter": fmt.Sprintf("protoPayload.authenticationInfo.principalEmail=%q AND timestamp >= %q AND timestamp <= %q", email, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)), "orderBy": "timestamp desc", "pageSize": 1000, "pageToken": page})
		var response struct {
			Entries []struct {
				At      time.Time `json:"timestamp"`
				Payload struct {
					Authentication struct {
						Email   string `json:"principalEmail"`
						KeyName string `json:"serviceAccountKeyName"`
					} `json:"authenticationInfo"`
					Status struct {
						Code int `json:"code"`
					} `json:"status"`
				} `json:"protoPayload"`
			} `json:"entries"`
			Next string `json:"nextPageToken"`
		}
		if err := c.read(ctx, c.logs, http.MethodPost, metadataFields("/v2/entries:list", "entries(timestamp,protoPayload(authenticationInfo(principalEmail,serviceAccountKeyName),status(code))),nextPageToken"), body, &response); err != nil {
			v.Limitations = append(v.Limitations, "Audit entries read unavailable or incomplete.")
			return
		}
		if len(response.Entries) > 1000 {
			v.Limitations = append(v.Limitations, "Audit page exceeds its declared bound.")
			return
		}
		v.ActivityCoverage = "observed_only"
		for _, entry := range response.Entries {
			if entry.Payload.Authentication.Email != email || entry.Payload.Status.Code != 0 || entry.At.Before(start) || entry.At.After(end) {
				continue
			}
			for i := range v.Keys {
				keyName := strings.TrimPrefix(entry.Payload.Authentication.KeyName, "//iam.googleapis.com/")
				observedID, valid := boundKeyID(keyName, cfg.Project, email, v.Identity.NativeID)
				ownID, ownValid := boundKeyID(v.Keys[i].Name, cfg.Project, email, v.Identity.NativeID)
				if valid && ownValid && observedID == ownID {
					at := entry.At.UTC()
					if v.Keys[i].LastObservedUse == nil || at.After(*v.Keys[i].LastObservedUse) {
						v.Keys[i].LastObservedUse = &at
					}
				}
			}
		}
		for i := range v.Keys {
			v.Keys[i].LastUseCoverage = "observed_only"
		}
		if response.Next == "" {
			return
		}
		if len(response.Next) > 4096 || seen[response.Next] {
			v.Limitations = append(v.Limitations, "Audit pagination token invalid or repeated.")
			return
		}
		seen[response.Next] = true
		page = response.Next
	}
	v.Limitations = append(v.Limitations, "Audit pagination budget reached; additional activity may exist.")
}

func boundKeyID(name, project, email, nativeID string) (string, bool) {
	p := strings.Split(name, "/")
	if len(p) != 6 || p[0] != "projects" || (p[1] != project && p[1] != "-" && !digits(p[1])) || p[2] != "serviceAccounts" || (p[3] != email && p[3] != nativeID) || p[4] != "keys" || len(p[5]) < 1 || len(p[5]) > 128 || strings.ContainsAny(p[5], "?#%\\\x00") {
		return "", false
	}
	return p[5], true
}

func metadataFields(path, fields string) string {
	join := "?"
	if strings.Contains(path, "?") {
		join = "&"
	}
	return path + join + "fields=" + url.QueryEscape(fields)
}
