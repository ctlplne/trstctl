// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

type cr831Member struct {
	Subject string   `json:"subject"`
	Status  string   `json:"status"`
	Source  string   `json:"source"`
	Roles   []string `json:"roles"`
}

func TestCR831SCIMCannotAdoptOrOffboardLocalAndTokenOnlySubjects(t *testing.T) {
	const token = "cr831-scim-fixture-token" // #nosec G101 -- fabricated test credential (CWE-798)
	d := newA207Deployment(t, token, nil, authz.BuiltinRoles()["viewer"].Permissions...)
	local := []string{"cr831-delete@local", "cr831-inactive@local", "cr831-group@local"}
	for _, subject := range local {
		status, body := doBearer(t, d.ts, http.MethodPut, "/api/v1/access/members/"+url.PathEscape(subject), d.admin,
			"cr831-seed-"+subject, map[string]any{"display_name": subject, "roles": []string{"viewer"}, "source": "local"})
		if status != http.StatusOK {
			t.Fatalf("seed local member %s: %d %s", subject, status, body)
		}
	}
	user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "cr831-managed@scim", "active": true}
	if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", token, "cr831-create-owned", user); got.Code != http.StatusCreated {
		t.Fatalf("SCIM-owned user creation = %d %s", got.Code, got.Body)
	}
	if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", token, "cr831-grant-owned", a207Group("viewer", "cr831-managed@scim")); got.Code != http.StatusCreated {
		t.Fatalf("SCIM-owned group grant = %d %s", got.Code, got.Body)
	}
	deleteGroup := doSCIM(t, d.ts, http.MethodDelete, "/scim/v2/Groups/viewer", token, "cr831-delete-owned-group", nil)
	list := doSCIM(t, d.ts, http.MethodGet, "/scim/v2/Users?count=100", token, "", nil)
	listedLocal := false
	for _, subject := range local {
		listedLocal = listedLocal || strings.Contains(list.Body.String(), subject)
	}
	listedOwned := strings.Contains(list.Body.String(), "cr831-managed@scim")
	get := doSCIM(t, d.ts, http.MethodGet, "/scim/v2/Users/"+url.PathEscape(local[0]), token, "", nil)
	add := map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]string{{"value": local[2]}}}}}
	group := doSCIM(t, d.ts, http.MethodPatch, "/scim/v2/Groups/admin", token, "cr831-group-local", add)
	inactive := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", token, "cr831-inactive-local",
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": local[1], "active": false})
	deleted := doSCIM(t, d.ts, http.MethodDelete, "/scim/v2/Users/"+url.PathEscape(local[0]), token, "cr831-delete-local", nil)
	status, body := doBearer(t, d.ts, http.MethodGet, "/api/v1/access/members?limit=100&include_offboarded=true", d.admin, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list local members: %d %s", status, body)
	}
	var page struct {
		Members []cr831Member `json:"members"`
		Items   []cr831Member `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	unchanged := true
	for _, subject := range local {
		found := false
		for _, member := range append(page.Members, page.Items...) {
			if member.Subject == subject {
				found = true
				unchanged = unchanged && member.Source == "local" && member.Status == "active" && slices.Equal(member.Roles, []string{"viewer"})
			}
		}
		unchanged = unchanged && found
	}
	tokenOnly := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", token, "cr831-inactive-token-only",
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "platform-admin", "active": false})
	adminStatus, _ := doBearer(t, d.ts, http.MethodGet, "/api/v1/access/oidc-mapping", d.admin, "", nil)
	if list.Code != http.StatusOK || !listedOwned || listedLocal || deleteGroup.Code != http.StatusNoContent || get.Code != http.StatusNotFound ||
		group.Code != http.StatusNotFound || (inactive.Code != http.StatusNotFound && inactive.Code != http.StatusConflict) ||
		deleted.Code != http.StatusNotFound || !unchanged || tokenOnly.Code != http.StatusNotFound || adminStatus != http.StatusOK {
		t.Fatalf("SCIM crossed its provisioned-user boundary: list=%d owned=%t local=%t delete-group=%d get=%d group=%d inactive=%d delete=%d unchanged=%t token-only=%d admin-token=%d",
			list.Code, listedOwned, listedLocal, deleteGroup.Code, get.Code, group.Code, inactive.Code, deleted.Code, unchanged, tokenOnly.Code, adminStatus)
	}
}

func TestCR831SCIMCannotRemoveLastAdminMember(t *testing.T) {
	for _, action := range []string{"delete-user", "remove-admin-group", "inactive-user"} {
		t.Run(action, func(t *testing.T) {
			const token = "cr831-last-admin-fixture-token" // #nosec G101 -- fabricated test credential (CWE-798)
			d := newA207Deployment(t, token, nil)
			const subject = "cr831-last-admin@scim"
			user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": subject, "active": true}
			if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", token, "cr831-last-create", user); got.Code != http.StatusCreated {
				t.Fatalf("create last admin candidate = %d %s", got.Code, got.Body)
			}
			if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", token, "cr831-last-group", a207Group("admin", subject)); got.Code != http.StatusCreated {
				t.Fatalf("grant admin role = %d %s", got.Code, got.Body)
			}
			var got *scimTestResponse
			switch action {
			case "delete-user":
				got = doSCIM(t, d.ts, http.MethodDelete, "/scim/v2/Users/"+url.PathEscape(subject), token, "cr831-last-delete", nil)
			case "inactive-user":
				user["active"] = false
				got = doSCIM(t, d.ts, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(subject), token, "cr831-last-inactive", user)
			case "remove-admin-group":
				remove := map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
					"Operations": []map[string]any{{"op": "remove", "path": "members", "value": []map[string]string{{"value": subject}}}}}
				got = doSCIM(t, d.ts, http.MethodPatch, "/scim/v2/Groups/admin", token, "cr831-last-remove", remove)
			}
			status, body := doBearer(t, d.ts, http.MethodGet, "/api/v1/access/members?limit=100&include_offboarded=true", d.admin, "", nil)
			if status != http.StatusOK {
				t.Fatalf("list members = %d %s", status, body)
			}
			var page struct {
				Members []cr831Member `json:"members"`
				Items   []cr831Member `json:"items"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			retained := false
			for _, member := range append(page.Members, page.Items...) {
				if member.Subject == subject {
					retained = member.Status == "active" && slices.Contains(member.Roles, "admin")
				}
			}
			if got.Code != http.StatusConflict || !retained {
				t.Fatalf("SCIM %s removed the last admin: status=%d retained=%t body=%s", action, got.Code, retained, got.Body)
			}
		})
	}
}

func TestCR831ConcurrentSCIMDeletesKeepOneAdmin(t *testing.T) {
	const token = "cr831-concurrent-admin-fixture-token" // #nosec G101 -- fabricated test credential (CWE-798)
	d := newA207Deployment(t, token, nil)
	subjects := []string{"cr831-admin-a@scim", "cr831-admin-b@scim"}
	for _, subject := range subjects {
		user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": subject, "active": true}
		if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", token, "cr831-create-"+subject, user); got.Code != http.StatusCreated {
			t.Fatalf("create %s = %d %s", subject, got.Code, got.Body)
		}
	}
	if got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", token, "cr831-two-admins",
		a207Group("admin", subjects...)); got.Code != http.StatusCreated {
		t.Fatalf("grant two admins = %d %s", got.Code, got.Body)
	}
	type result struct {
		status int
		err    error
	}
	results := make(chan result, len(subjects))
	var ready sync.WaitGroup
	ready.Add(len(subjects))
	start := make(chan struct{})
	for _, subject := range subjects {
		go func() {
			ready.Done()
			<-start
			req, err := http.NewRequest(http.MethodDelete, d.ts.URL+"/scim/v2/Users/"+url.PathEscape(subject), nil)
			if err != nil {
				results <- result{err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Idempotency-Key", "cr831-delete-"+subject)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			results <- result{status: resp.StatusCode}
		}()
	}
	ready.Wait()
	close(start)
	statuses := make([]int, 0, len(subjects))
	for range subjects {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		statuses = append(statuses, got.status)
	}
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{http.StatusNoContent, http.StatusConflict}) {
		t.Fatalf("concurrent SCIM deletes = %v, want one completed and one last-admin refusal", statuses)
	}
	status, body := doBearer(t, d.ts, http.MethodGet, "/api/v1/access/members?limit=100&include_offboarded=true", d.admin, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list members = %d %s", status, body)
	}
	var page struct {
		Members []cr831Member `json:"members"`
		Items   []cr831Member `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	activeAdmins := 0
	for _, member := range append(page.Members, page.Items...) {
		if slices.Contains(subjects, member.Subject) && member.Status == "active" && slices.Contains(member.Roles, "admin") {
			activeAdmins++
		}
	}
	if activeAdmins != 1 {
		t.Fatalf("concurrent deletion left %d active admins, want one", activeAdmins)
	}
}
