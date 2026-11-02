// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/redisacl"
)

// AWSCacheService names the managed Redis/Valkey service whose RBAC users a
// lease is: ElastiCache (Query API, user groups) or MemoryDB (JSON API, ACLs).
type AWSCacheService string

const (
	AWSElastiCache AWSCacheService = "elasticache"
	AWSMemoryDB    AWSCacheService = "memorydb"
)

var (
	awsCacheGroup  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,39}$`)
	awsCacheUserID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	awsCacheCode   = regexp.MustCompile(`<Code>([A-Za-z0-9.]+)</Code>`)
)

// AWSCacheUsersConfig configures the ElastiCache and MemoryDB providers (A239):
// each lease is an RBAC user with a generated password and its role's access
// string - literal key prefixes and explicit commands, compiled by redisacl as
// for the Redis provider - added to one user group (ElastiCache) or ACL
// (MemoryDB); revocation deletes the user, which AWS removes from every group
// and cluster.
type AWSCacheUsersConfig struct {
	Service AWSCacheService
	// Endpoint is https://elasticache.<region>.amazonaws.com or
	// https://memory-db.<region>.amazonaws.com by default.
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	// UserGroup is the ElastiCache user group ID, or the MemoryDB ACL name.
	UserGroup string
	// Engine is ElastiCache's user engine: redis (default) or valkey.
	Engine         string
	RolePolicies   map[string]redisacl.Role
	UsernamePrefix string
	HTTPClient     HTTPDoer
	// PollInterval spaces the status polls while a user or group settles.
	PollInterval time.Duration
}

// AWSCacheUsersBackend issues ElastiCache or MemoryDB RBAC users.
type AWSCacheUsersBackend struct {
	service      AWSCacheService
	signer       *AWSIAMBackend
	userGroup    string
	engine       string
	access       map[string]string
	prefix       string
	pollInterval time.Duration
}

// NewAWSCacheUsersBackend validates cfg.
func NewAWSCacheUsersBackend(cfg AWSCacheUsersConfig) (*AWSCacheUsersBackend, error) {
	label := "dynsecret aws-" + string(cfg.Service)
	switch cfg.Service {
	case AWSElastiCache:
		if cfg.Endpoint == "" {
			cfg.Endpoint = "https://elasticache." + cfg.Region + ".amazonaws.com"
		}
		if cfg.Engine == "" {
			cfg.Engine = "redis"
		}
		if cfg.Engine != "redis" && cfg.Engine != "valkey" {
			return nil, fmt.Errorf("%s: engine must be redis or valkey", label)
		}
	case AWSMemoryDB:
		if cfg.Endpoint == "" {
			cfg.Endpoint = "https://memory-db." + cfg.Region + ".amazonaws.com"
		}
		if cfg.Engine != "" {
			return nil, fmt.Errorf("%s: engine is an ElastiCache setting", label)
		}
	default:
		return nil, errors.New("dynsecret: unknown AWS cache service")
	}
	if !awsCacheGroup.MatchString(cfg.UserGroup) {
		return nil, fmt.Errorf("%s: the user group or ACL must be a plain AWS name", label)
	}
	b := &AWSCacheUsersBackend{service: cfg.Service, userGroup: cfg.UserGroup, engine: cfg.Engine, access: map[string]string{},
		prefix: cfg.UsernamePrefix, pollInterval: cfg.PollInterval}
	if b.pollInterval <= 0 {
		b.pollInterval = 2 * time.Second
	}
	for role, policy := range cfg.RolePolicies {
		rules, err := redisacl.Compile(policy)
		if err != nil {
			return nil, fmt.Errorf("%s: role %q: %w", label, role, err)
		}
		// A new RBAC user holds nothing; -@all states it, then the role's own
		// keys and commands, and PING so clients can probe a connection.
		b.access[role] = "on " + strings.Join(rules[:len(policy.KeyPrefixes)], " ") + " -@all " +
			strings.Join(rules[len(policy.KeyPrefixes):], " ") + " +ping"
	}
	if len(b.access) == 0 {
		return nil, fmt.Errorf("%s: every allowed role needs key prefixes and commands in redis_acl_roles", label)
	}
	signer, err := NewAWSIAMBackend(AWSIAMConfig{Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, Region: cfg.Region,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey, SessionToken: cfg.SessionToken})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	b.signer = signer
	return b, nil
}

// Create implements Backend.
func (b *AWSCacheUsersBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user ID derives from the
// lease: a retry after an uncertain attempt finds the user (already exists)
// and replaces its password and access string instead of adding one. The user
// joins the group once AWS reports it active; if that fails it is deleted.
func (b *AWSCacheUsersBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New(b.label() + ": static credentials are not served")
	}
	access, ok := b.access[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("%s: role %q has no access policy", b.label(), req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 40, "-")
	if err != nil {
		return "", nil, err
	}
	if !awsCacheUserID.MatchString(user) {
		return "", nil, fmt.Errorf("%s: generated user ID %q is not plain", b.label(), user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	code, err := b.upsertUser(ctx, user, access, password, false)
	if err == nil && (code == "UserAlreadyExists" || code == "UserAlreadyExistsFault") {
		code, err = b.upsertUser(ctx, user, access, password, true)
	}
	if err == nil && code != "" {
		err = fmt.Errorf("AWS answered %s", code)
	}
	if err != nil {
		return "", nil, fmt.Errorf("%s: create user %s: %w", b.label(), user, err)
	}
	if err := b.join(ctx, user); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("%s: add %s to %s: %w", b.label(), user, b.userGroup, err)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username  string           `json:"username"`
		Password  secret.JSONBytes `json:"password"`
		UserGroup string           `json:"user_group"`
	}{Username: user, Password: password, UserGroup: b.userGroup})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// upsertUser creates the user, or with modify replaces its password and access
// string. It returns AWS's error code for a refusal it reports.
func (b *AWSCacheUsersBackend) upsertUser(ctx context.Context, user, access string, password []byte, modify bool) (string, error) {
	if b.service == AWSElastiCache {
		action := "CreateUser"
		if modify {
			action = "ModifyUser"
		}
		form := []byte("Action=" + action + "&Version=2015-02-02&UserId=" + user + "&AccessString=" + queryEscape(access) + "&Passwords.member.1=")
		form = appendFormEscaped(form, password)
		if !modify {
			form = append(form, "&UserName="+user+"&Engine="+b.engine+"&NoPasswordRequired=false"...)
		}
		defer secret.Wipe(form)
		return b.query(ctx, form)
	}
	target := "AmazonMemoryDB.CreateUser"
	if modify {
		target = "AmazonMemoryDB.UpdateUser"
	}
	body, err := json.Marshal(struct { // #nosec G117 -- the new user's password goes to the MemoryDB API over the guarded client and is not kept (CWE-200)
		UserName           string `json:"UserName"`
		AccessString       string `json:"AccessString"`
		AuthenticationMode struct {
			Type      string             `json:"Type"`
			Passwords []secret.JSONBytes `json:"Passwords"`
		} `json:"AuthenticationMode"`
	}{UserName: user, AccessString: access, AuthenticationMode: struct {
		Type      string             `json:"Type"`
		Passwords []secret.JSONBytes `json:"Passwords"`
	}{Type: "password", Passwords: []secret.JSONBytes{password}}})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(body)
	return b.jsonCall(ctx, target, body)
}

// join adds the user to the group once both have settled: AWS creates users
// asynchronously and refuses to change a user or group that is modifying.
func (b *AWSCacheUsersBackend) join(ctx context.Context, user string) error {
	for attempt := 0; ; attempt++ {
		var code string
		var err error
		if b.service == AWSElastiCache {
			code, err = b.query(ctx, []byte("Action=ModifyUserGroup&Version=2015-02-02&UserGroupId="+b.userGroup+"&UserIdsToAdd.member.1="+user))
		} else {
			body, _ := json.Marshal(map[string]any{"ACLName": b.userGroup, "UserNamesToAdd": []string{user}})
			code, err = b.jsonCall(ctx, "AmazonMemoryDB.UpdateACL", body)
		}
		switch {
		case err != nil:
			return err
		case code == "", code == "DuplicateUserName", code == "UserAlreadyInGroup":
			return nil
		case code != "InvalidUserState" && code != "InvalidUserGroupState" && code != "InvalidACLStateFault" && code != "InvalidUserStateFault":
			return fmt.Errorf("AWS answered %s", code)
		case attempt >= 30:
			return fmt.Errorf("AWS still answered %s after %d attempts", code, attempt+1)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.pollInterval):
		}
	}
}

// Revoke implements Backend: the user is deleted, and AWS removes it from every
// group and cluster, after which its next AUTH fails. Only users this provider
// issued are deleted; one already gone counts as revoked.
func (b *AWSCacheUsersBackend) Revoke(ctx context.Context, ref string) error {
	if !awsCacheUserID.MatchString(ref) || !issuedPrincipalNameWith(b.prefix, ref, '-') {
		return fmt.Errorf("%s: refusing to delete %q, which this provider did not create", b.label(), ref)
	}
	var code string
	var err error
	if b.service == AWSElastiCache {
		code, err = b.query(ctx, []byte("Action=DeleteUser&Version=2015-02-02&UserId="+ref))
	} else {
		body, _ := json.Marshal(map[string]string{"UserName": ref})
		code, err = b.jsonCall(ctx, "AmazonMemoryDB.DeleteUser", body)
	}
	if err == nil && code != "" && code != "UserNotFound" && code != "UserNotFoundFault" {
		err = fmt.Errorf("AWS answered %s", code)
	}
	if err != nil {
		return fmt.Errorf("%s: delete user %s: %w", b.label(), ref, err)
	}
	return nil
}

// query sends an ElastiCache Query API request; a refusal returns its code.
func (b *AWSCacheUsersBackend) query(ctx context.Context, form []byte) (string, error) {
	status, body, err := b.send(ctx, "application/x-www-form-urlencoded; charset=utf-8", "", form, "elasticache")
	if err != nil || status/100 == 2 {
		return "", err
	}
	if m := awsCacheCode.FindSubmatch(body); m != nil {
		return string(m[1]), nil
	}
	return "", fmt.Errorf("HTTP %d", status)
}

// jsonCall sends a MemoryDB JSON API request; a refusal returns its __type.
func (b *AWSCacheUsersBackend) jsonCall(ctx context.Context, target string, body []byte) (string, error) {
	status, response, err := b.send(ctx, "application/x-amz-json-1.1", target, body, "memorydb")
	if err != nil || status/100 == 2 {
		return "", err
	}
	var failure struct {
		Type string `json:"__type"`
	}
	if json.Unmarshal(response, &failure) == nil && failure.Type != "" {
		return failure.Type[strings.LastIndex(failure.Type, "#")+1:], nil
	}
	return "", fmt.Errorf("HTTP %d", status)
}

func (b *AWSCacheUsersBackend) send(ctx context.Context, contentType, target string, body []byte, service string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.signer.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	b.signer.signV4(req, body, b.signer.now().UTC(), service)
	resp, err := b.signer.doer.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", b.label(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return 0, nil, fmt.Errorf("%s: read the response: %w", b.label(), err)
	}
	return resp.StatusCode, response, nil
}

func (b *AWSCacheUsersBackend) label() string { return "dynsecret aws-" + string(b.service) }

// queryEscape percent-encodes a value for a Query API body (the access string's
// spaces, tildes and plus signs).
func queryEscape(value string) string { return string(appendFormEscaped(nil, []byte(value))) }

// Close wipes the AWS credentials.
func (b *AWSCacheUsersBackend) Close() { b.signer.Close() }
