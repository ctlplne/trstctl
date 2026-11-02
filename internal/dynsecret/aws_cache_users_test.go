// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/redisacl"
)

// awsCacheStandIn follows the ElastiCache Query API and the MemoryDB JSON API
// for RBAC users as AWS documents them: SigV4-signed requests scoped to the
// service; creating an existing user is UserAlreadyExists; a new user is still
// settling on the first group change (InvalidUserState); deleting a user
// removes it from its group, and a missing user is UserNotFound.
type awsCacheStandIn struct {
	mu       sync.Mutex
	service  AWSCacheService
	users    map[string]map[string]string // id -> password, access
	group    []string
	settling map[string]bool
}

func newAWSCacheStandIn(t *testing.T, service AWSCacheService) (*awsCacheStandIn, *httptest.Server) {
	t.Helper()
	lab := &awsCacheStandIn{service: service, users: map[string]map[string]string{}, settling: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/"+string(service)+"/aws4_request") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if service == AWSElastiCache {
			lab.elastiCache(w, r)
		} else {
			lab.memoryDB(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func (lab *awsCacheStandIn) refuse(w http.ResponseWriter, code string) {
	w.WriteHeader(http.StatusBadRequest)
	if lab.service == AWSElastiCache {
		_, _ = w.Write([]byte("<ErrorResponse><Error><Type>Sender</Type><Code>" + code + "</Code><Message>stand-in</Message></Error></ErrorResponse>"))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "com.amazonaws.memorydb#" + code, "message": "stand-in"})
}

func (lab *awsCacheStandIn) elastiCache(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := r.PostForm.Get("UserId")
	switch r.PostForm.Get("Action") {
	case "CreateUser":
		if _, exists := lab.users[id]; exists {
			lab.refuse(w, "UserAlreadyExists")
			return
		}
		lab.users[id] = map[string]string{"password": r.PostForm.Get("Passwords.member.1"), "access": r.PostForm.Get("AccessString"), "engine": r.PostForm.Get("Engine")}
		lab.settling[id] = true
	case "ModifyUser":
		lab.users[id]["password"], lab.users[id]["access"] = r.PostForm.Get("Passwords.member.1"), r.PostForm.Get("AccessString")
	case "ModifyUserGroup":
		member := r.PostForm.Get("UserIdsToAdd.member.1")
		if r.PostForm.Get("UserGroupId") != "orders-group" {
			lab.refuse(w, "UserGroupNotFound")
			return
		}
		if lab.settling[member] {
			lab.settling[member] = false
			lab.refuse(w, "InvalidUserState")
			return
		}
		if !slices.Contains(lab.group, member) {
			lab.group = append(lab.group, member)
		}
	case "DeleteUser":
		if _, exists := lab.users[id]; !exists {
			lab.refuse(w, "UserNotFound")
			return
		}
		delete(lab.users, id)
		lab.group = slices.DeleteFunc(lab.group, func(m string) bool { return m == id })
	default:
		lab.refuse(w, "InvalidAction")
		return
	}
	_, _ = w.Write([]byte("<Response><ResponseMetadata><RequestId>stand-in</RequestId></ResponseMetadata></Response>"))
}

func (lab *awsCacheStandIn) memoryDB(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserName, AccessString, ACLName string
		UserNamesToAdd                  []string
		AuthenticationMode              struct {
			Type      string
			Passwords []string
		}
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch r.Header.Get("X-Amz-Target") {
	case "AmazonMemoryDB.CreateUser":
		if _, exists := lab.users[in.UserName]; exists {
			lab.refuse(w, "UserAlreadyExistsFault")
			return
		}
		lab.users[in.UserName] = map[string]string{"password": in.AuthenticationMode.Passwords[0], "access": in.AccessString}
		lab.settling[in.UserName] = true
	case "AmazonMemoryDB.UpdateUser":
		lab.users[in.UserName]["password"], lab.users[in.UserName]["access"] = in.AuthenticationMode.Passwords[0], in.AccessString
	case "AmazonMemoryDB.UpdateACL":
		member := in.UserNamesToAdd[0]
		if in.ACLName != "orders-group" {
			lab.refuse(w, "ACLNotFoundFault")
			return
		}
		if lab.settling[member] {
			lab.settling[member] = false
			lab.refuse(w, "InvalidUserStateFault")
			return
		}
		if !slices.Contains(lab.group, member) {
			lab.group = append(lab.group, member)
		}
	case "AmazonMemoryDB.DeleteUser":
		if _, exists := lab.users[in.UserName]; !exists {
			lab.refuse(w, "UserNotFoundFault")
			return
		}
		delete(lab.users, in.UserName)
		lab.group = slices.DeleteFunc(lab.group, func(m string) bool { return m == in.UserName })
	default:
		lab.refuse(w, "UnknownOperationException")
		return
	}
	_, _ = w.Write([]byte("{}"))
}

func TestAWSCacheLeaseIsAnRBACUserInTheGroupA239(t *testing.T) {
	for _, service := range []AWSCacheService{AWSElastiCache, AWSMemoryDB} {
		t.Run(string(service), func(t *testing.T) {
			lab, srv := newAWSCacheStandIn(t, service)
			b, err := NewAWSCacheUsersBackend(AWSCacheUsersConfig{
				Service: service, Endpoint: srv.URL, Region: "us-east-1", AccessKeyID: "AKIALAB", SecretAccessKey: []byte("lab-secret"),
				UserGroup: "orders-group", RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get", "hget"}}},
				HTTPClient: srv.Client(), PollInterval: time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			req := GenerateRequest{Role: "reader", LeaseID: "lease-0001"}
			user, credential, err := b.CreateCredential(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Username, Password string
				UserGroup          string `json:"user_group"`
			}
			if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 || got.UserGroup != "orders-group" {
				t.Fatalf("credential %+v (%v)", got, err)
			}
			stored := lab.users[user]
			if stored["password"] != got.Password || stored["access"] != "on ~orders:* -@all +get +hget +ping" || !slices.Equal(lab.group, []string{user}) {
				t.Fatalf("stored user %v, group %v", stored, lab.group)
			}
			if service == AWSElastiCache && stored["engine"] != "redis" {
				t.Fatalf("engine %q", stored["engine"])
			}
			// A retry replaces the same user's password; it adds no user.
			again, credential2, err := b.CreateCredential(context.Background(), req)
			var got2 struct{ Password string }
			_ = json.Unmarshal(credential2, &got2)
			if err != nil || again != user || len(lab.users) != 1 || lab.users[user]["password"] != got2.Password || got2.Password == got.Password {
				t.Fatalf("retry: %q (%v); users %v", again, err, lab.users)
			}
			if err := b.Revoke(context.Background(), user); err != nil || len(lab.users) != 0 || len(lab.group) != 0 {
				t.Fatalf("revoke: %v; users %v group %v", err, lab.users, lab.group)
			}
			if err := b.Revoke(context.Background(), user); err != nil {
				t.Fatalf("a second revocation of a deleted user: %v", err)
			}
			for _, foreign := range []string{"default", "trstctl-admin", "app-reader-0123456789", "trstctl_reader_0123456789", "trstctl-reader-01234"} {
				if err := b.Revoke(context.Background(), foreign); err == nil {
					t.Errorf("deleted %q, a user this provider did not create", foreign)
				}
			}
		})
	}
}

func TestAWSCacheConfigA239(t *testing.T) {
	base := AWSCacheUsersConfig{Service: AWSElastiCache, Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: []byte("s"), UserGroup: "orders-group",
		RolePolicies: map[string]redisacl.Role{"r": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}}}
	if b, err := NewAWSCacheUsersBackend(base); err != nil || b.signer.endpoint != "https://elasticache.us-east-1.amazonaws.com" {
		t.Fatalf("elasticache defaults: %v", err)
	} else {
		b.Close()
	}
	memory := base
	memory.Service = AWSMemoryDB
	if b, err := NewAWSCacheUsersBackend(memory); err != nil || b.signer.endpoint != "https://memory-db.us-east-1.amazonaws.com" {
		t.Fatalf("memorydb defaults: %v", err)
	} else {
		b.Close()
	}
	for name, mutate := range map[string]func(*AWSCacheUsersConfig){
		"unknown service":    func(c *AWSCacheUsersConfig) { c.Service = "dynamodb" },
		"bad group":          func(c *AWSCacheUsersConfig) { c.UserGroup = "orders group" },
		"bad engine":         func(c *AWSCacheUsersConfig) { c.Engine = "memcached" },
		"engine on memorydb": func(c *AWSCacheUsersConfig) { c.Service, c.Engine = AWSMemoryDB, "redis" },
		"unsafe command": func(c *AWSCacheUsersConfig) {
			c.RolePolicies = map[string]redisacl.Role{"r": {KeyPrefixes: []string{"orders:"}, Commands: []string{"flushall"}}}
		},
		"wildcard key prefix": func(c *AWSCacheUsersConfig) {
			c.RolePolicies = map[string]redisacl.Role{"r": {KeyPrefixes: []string{"*"}, Commands: []string{"get"}}}
		},
		"no roles":       func(c *AWSCacheUsersConfig) { c.RolePolicies = nil },
		"no credentials": func(c *AWSCacheUsersConfig) { c.SecretAccessKey = nil },
	} {
		c := base
		mutate(&c)
		if b, err := NewAWSCacheUsersBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if got := queryEscape("on ~orders:* +get"); got != "on%20~orders%3A%2A%20%2Bget" {
		t.Fatalf("query escape %q", got)
	}
	if _, err := url.ParseQuery("AccessString=" + queryEscape("on ~orders:* -@all +get")); err != nil {
		t.Fatal(err)
	}
}
