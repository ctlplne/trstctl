// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// kafkaSCRAMIterations is the PBKDF2 work factor of leased credentials; Kafka
// accepts 4096 to 16384.
const kafkaSCRAMIterations = 8192

var (
	kafkaOperations = map[string]kadm.ACLOperation{
		"read": kadm.OpRead, "write": kadm.OpWrite, "describe": kadm.OpDescribe, "describe_configs": kadm.OpDescribeConfigs,
		"create": kadm.OpCreate, "delete": kadm.OpDelete, "alter": kadm.OpAlter, "alter_configs": kadm.OpAlterConfigs,
	}
	kafkaResourceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,249}$`)
	kafkaUser         = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
)

// KafkaResource is one ACL resource: a topic, consumer group or transactional
// ID, by exact name or by name prefix.
type KafkaResource struct {
	Type   string
	Name   string
	Prefix bool
}

// KafkaClause grants its operations on each of its resources.
type KafkaClause struct {
	Operations []string
	Resources  []KafkaResource
}

// ParseKafkaGrant reads a role binding: clauses "<operations> on <resources>"
// separated by ";", for example "read,describe on topic:orders; read on
// group:orders-app". A resource is topic:, group: or transactional_id: and a
// name; a name ending in * is a prefix (topic:logs-*), and a bare * is refused.
func ParseKafkaGrant(binding string) ([]KafkaClause, error) {
	var clauses []KafkaClause
	for _, text := range strings.Split(binding, ";") {
		ops, resources, ok := strings.Cut(strings.TrimSpace(text), " on ")
		if !ok {
			return nil, errors.New(`expected "<operations> on <resources>", for example "read,describe on topic:orders"`)
		}
		var clause KafkaClause
		for _, op := range strings.Split(ops, ",") {
			op = strings.TrimSpace(op)
			if _, known := kafkaOperations[op]; !known {
				return nil, fmt.Errorf("operation %q is not one of read, write, describe, describe_configs, create, delete, alter or alter_configs", op)
			}
			clause.Operations = append(clause.Operations, op)
		}
		for _, item := range strings.Split(resources, ",") {
			kind, name, _ := strings.Cut(strings.TrimSpace(item), ":")
			resource := KafkaResource{Type: kind, Name: strings.TrimSuffix(name, "*"), Prefix: strings.HasSuffix(name, "*")}
			if kind != "topic" && kind != "group" && kind != "transactional_id" {
				return nil, fmt.Errorf("resource %q is not topic:, group: or transactional_id: and a name", item)
			}
			if !kafkaResourceName.MatchString(resource.Name) {
				return nil, fmt.Errorf("resource %q needs a plain name or name prefix (a bare * would grant every %s)", item, kind)
			}
			clause.Resources = append(clause.Resources, resource)
		}
		clauses = append(clauses, clause)
	}
	return clauses, nil
}

// KafkaConfig configures the Kafka provider (A239): each lease is a
// SCRAM-SHA-512 user with a generated password and only its role's ACLs.
// Revocation deletes the ACLs, which the broker enforces on the user's next
// request even on a connection already open, and then the credential, so its
// next login fails.
type KafkaConfig struct {
	// Addr is a bootstrap broker's host:port: its SASL_SSL listener, or, with
	// AllowPlaintext, SASL_PLAINTEXT at a literal loopback or private IP.
	Addr string
	// TLSServerName, when set, is the name every broker's certificate must
	// carry; otherwise each broker's advertised host name. TLSCAPEM pins a
	// private CA; system roots when empty.
	TLSServerName  string
	TLSCAPEM       []byte
	AllowPlaintext bool
	// AdminUser and AdminPassword are a SCRAM-SHA-512 user allowed to alter
	// user SCRAM credentials and create and delete ACLs (ALTER on the cluster).
	AdminUser      string
	AdminPassword  []byte
	RoleBindings   map[string]string
	UsernamePrefix string
}

// kafkaACLs is one CreateACLs request: Principal is allowed each operation on
// each named resource (resource type to names), by exact name or by prefix.
type kafkaACLs struct {
	Principal  string
	Operations []string
	Prefix     bool
	Names      map[string][]string
}

// kafkaAdmin is what the backend asks of the cluster.
type kafkaAdmin interface {
	// UpsertSCRAM creates the user's SCRAM-SHA-512 credential or replaces its
	// password.
	UpsertSCRAM(ctx context.Context, user string, password []byte) error
	CreateACLs(ctx context.Context, acls kafkaACLs) error
	// DeleteACLs deletes every ACL that names the principal.
	DeleteACLs(ctx context.Context, principal string) error
	// DeleteSCRAM deletes the user's credential; one already gone is not an
	// error.
	DeleteSCRAM(ctx context.Context, user string) error
	Close()
}

// KafkaBackend issues Kafka SCRAM users.
type KafkaBackend struct {
	addr          string
	tls           bool
	serverName    string
	caPEM         []byte
	adminUser     string
	adminPassword *secret.Buffer
	grants        map[string][]KafkaClause
	prefix        string
	connect       func(ctx context.Context) (kafkaAdmin, error)
}

// NewKafkaBackend validates cfg.
func NewKafkaBackend(cfg KafkaConfig) (*KafkaBackend, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Addr))
	if err != nil || host == "" || port == "" {
		return nil, errors.New("dynsecret kafka: addr must be host:port")
	}
	b := &KafkaBackend{addr: net.JoinHostPort(host, port), tls: !cfg.AllowPlaintext, serverName: cfg.TLSServerName,
		caPEM: append([]byte(nil), cfg.TLSCAPEM...), adminUser: strings.TrimSpace(cfg.AdminUser),
		grants: map[string][]KafkaClause{}, prefix: cfg.UsernamePrefix}
	address := net.ParseIP(host)
	switch {
	case cfg.AllowPlaintext:
		if !kafkaPlaintextAddress(b.addr) || cfg.TLSServerName != "" || len(cfg.TLSCAPEM) > 0 {
			return nil, errors.New("dynsecret kafka: plaintext SASL is allowed only to a literal loopback or private IP, with no TLS settings")
		}
	case b.serverName == "" && address != nil:
		return nil, errors.New("dynsecret kafka: tls_server_name is required when addr is an IP address")
	}
	if b.adminUser == "" || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret kafka: the administrator's SCRAM user and password are required")
	}
	for role, binding := range cfg.RoleBindings {
		clauses, err := ParseKafkaGrant(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret kafka: role %q: %w", role, err)
		}
		b.grants[role] = clauses
	}
	if len(b.grants) == 0 {
		return nil, errors.New("dynsecret kafka: every allowed role needs ACLs in role_bindings")
	}
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	b.connect = b.dialAdmin
	return b, nil
}

// kafkaPlaintextAddress reports whether hostPort is a literal loopback or
// private IP, the only place plaintext SASL may go (the bootstrap broker and
// every broker it advertises).
func kafkaPlaintextAddress(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	address := net.ParseIP(host)
	return err == nil && address != nil && (address.IsLoopback() || address.IsPrivate())
}

// dialAdmin builds an admin client that authenticates as the administrator
// (SCRAM-SHA-512) over verified TLS through the crypto boundary, or over the
// allowed plaintext.
func (b *KafkaBackend) dialAdmin(context.Context) (kafkaAdmin, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(b.addr),
		kgo.ClientID("trstctl"),
		kgo.Dialer(b.dialBroker),
		kgo.DialTimeout(10*time.Second),
		kgo.RetryTimeout(30*time.Second),
		kgo.SASL(scram.Sha512(func(context.Context) (scram.Auth, error) {
			var auth scram.Auth
			// franz-go takes the password as a string; it is converted for the
			// session's authentication and not kept by the backend.
			err := b.adminPassword.Use(func(password []byte) error {
				auth = scram.Auth{User: b.adminUser, Pass: secrettext.String(password)}
				return nil
			})
			return auth, err
		})),
	)
	if err != nil {
		return nil, fmt.Errorf("dynsecret kafka: admin client: %w", err)
	}
	return kadmAdmin{client: kadm.NewClient(client)}, nil
}

// kadmAdmin is kafkaAdmin over franz-go's admin client.
type kadmAdmin struct{ client *kadm.Client }

func (a kadmAdmin) UpsertSCRAM(ctx context.Context, user string, password []byte) error {
	altered, err := a.client.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{{
		User: user, Mechanism: kadm.ScramSha512, Iterations: kafkaSCRAMIterations, Password: secrettext.String(password),
	}})
	if err == nil {
		err = altered.Error()
	}
	return err
}

func (a kadmAdmin) CreateACLs(ctx context.Context, acls kafkaACLs) error {
	ops := make([]kadm.ACLOperation, 0, len(acls.Operations))
	for _, op := range acls.Operations {
		ops = append(ops, kafkaOperations[op])
	}
	pattern := kadm.ACLPatternLiteral
	if acls.Prefix {
		pattern = kadm.ACLPatternPrefixed
	}
	results, err := a.client.CreateACLs(ctx, kadm.NewACLs().Allow(acls.Principal).Operations(ops...).ResourcePatternType(pattern).
		MaybeTopics(acls.Names["topic"]...).MaybeGroups(acls.Names["group"]...).MaybeTransactionalIDs(acls.Names["transactional_id"]...))
	if err != nil {
		return err
	}
	for _, result := range results {
		if result.Err != nil {
			return fmt.Errorf("%s on %s %q: %w", result.Operation, result.Type, result.Name, result.Err)
		}
	}
	return nil
}

func (a kadmAdmin) DeleteACLs(ctx context.Context, principal string) error {
	results, err := a.client.DeleteACLs(ctx, kadm.NewACLs().Allow(principal).AllowHosts().AnyResource().Operations().
		ResourcePatternType(kadm.ACLPatternAny))
	if err != nil {
		return err
	}
	for _, result := range results {
		if result.Err != nil {
			return result.Err
		}
	}
	return nil
}

func (a kadmAdmin) DeleteSCRAM(ctx context.Context, user string) error {
	altered, err := a.client.AlterUserSCRAMs(ctx, []kadm.DeleteSCRAM{{User: user, Mechanism: kadm.ScramSha512}}, nil)
	if err == nil {
		err = altered.Error()
	}
	if errors.Is(err, kerr.ResourceNotFound) {
		return nil
	}
	return err
}

func (a kadmAdmin) Close() { a.client.Close() }

func (b *KafkaBackend) dialBroker(ctx context.Context, _, hostPort string) (net.Conn, error) {
	if !b.tls {
		if !kafkaPlaintextAddress(hostPort) {
			return nil, fmt.Errorf("dynsecret kafka: refusing plaintext to %s, which is not a literal loopback or private IP", hostPort)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", hostPort)
	}
	name := b.serverName
	if name == "" {
		name, _, _ = net.SplitHostPort(hostPort)
	}
	return mtls.DialVerifiedTCP(ctx, hostPort, name, b.caPEM)
}

// Create implements Backend.
func (b *KafkaBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease: a retry after an uncertain attempt replaces the same user's password
// and re-creates its ACLs (an existing ACL is unchanged) instead of adding a
// user. If the ACLs fail, the credential this attempt set is deleted again.
func (b *KafkaBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret kafka: static credentials are not served")
	}
	clauses, ok := b.grants[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret kafka: role %q has no ACLs", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	if !kafkaUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret kafka: generated user name %q is not plain", user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	admin, err := b.connect(ctx)
	if err != nil {
		return "", nil, err
	}
	defer admin.Close()
	if err := admin.UpsertSCRAM(ctx, user, password); err != nil {
		return "", nil, fmt.Errorf("dynsecret kafka: set the SCRAM credential: %w", err)
	}
	if err := grantKafkaACLs(ctx, admin, user, clauses); err != nil {
		if cleanup := removeKafkaUser(ctx, admin, user); cleanup != nil {
			return "", nil, fmt.Errorf("%w (and removing the new user failed: %v)", err, cleanup)
		}
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username  string           `json:"username"`
		Password  secret.JSONBytes `json:"password"`
		Mechanism string           `json:"mechanism"`
	}{Username: user, Password: password, Mechanism: "SCRAM-SHA-512"})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// grantKafkaACLs allows the user each clause's operations on its resources:
// one request for exact names and one for prefixes per clause.
func grantKafkaACLs(ctx context.Context, admin kafkaAdmin, user string, clauses []KafkaClause) error {
	for _, clause := range clauses {
		for _, prefix := range []bool{false, true} {
			acls := kafkaACLs{Principal: "User:" + user, Operations: clause.Operations, Prefix: prefix, Names: map[string][]string{}}
			for _, r := range clause.Resources {
				if r.Prefix == prefix {
					acls.Names[r.Type] = append(acls.Names[r.Type], r.Name)
				}
			}
			if len(acls.Names) == 0 {
				continue
			}
			if err := admin.CreateACLs(ctx, acls); err != nil {
				return fmt.Errorf("dynsecret kafka: create ACLs: %w", err)
			}
		}
	}
	return nil
}

// Revoke implements Backend: the user's ACLs are deleted (its open connections
// are refused from the next request), then its credential (the next login
// fails). Only users this provider names are touched; a user already gone
// counts as revoked.
func (b *KafkaBackend) Revoke(ctx context.Context, ref string) error {
	if !kafkaUser.MatchString(ref) || !strings.HasPrefix(ref, sanitizeFragment(b.prefix, defaultDynsecretPrefix)+"_") {
		return fmt.Errorf("dynsecret kafka: refusing to revoke %q, which this provider did not create", ref)
	}
	admin, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer admin.Close()
	return removeKafkaUser(ctx, admin, ref)
}

func removeKafkaUser(ctx context.Context, admin kafkaAdmin, user string) error {
	if err := admin.DeleteACLs(ctx, "User:"+user); err != nil {
		return fmt.Errorf("dynsecret kafka: delete ACLs: %w", err)
	}
	if err := admin.DeleteSCRAM(ctx, user); err != nil {
		return fmt.Errorf("dynsecret kafka: delete the SCRAM credential: %w", err)
	}
	return nil
}

// Close wipes the administrator's password.
func (b *KafkaBackend) Close() { b.adminPassword.Destroy() }
