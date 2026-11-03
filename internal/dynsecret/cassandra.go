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

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// cassandraBcryptCost is the work factor of a leased role's password hash,
// Cassandra's own default (auth_bcrypt_gensalt_log2_rounds).
const cassandraBcryptCost = 10

// cassandraAuthenticator is the only authenticator the administrator's
// password is sent to.
const cassandraAuthenticator = "org.apache.cassandra.auth.PasswordAuthenticator"

// cassandraName is a role name this provider double-quotes into CQL: the
// leases it creates and the roles it grants.
var cassandraName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// CassandraConfig configures the Cassandra provider (A239): each lease is a
// login role with a generated password, granted only its allowed role's
// Cassandra roles. Revocation drops the role: its next login fails, and a
// connection already open loses the granted permissions as soon as the node's
// role and permission caches expire (roles_validity and permissions_validity,
// 2 s by default).
type CassandraConfig struct {
	// Addr is a node's native-protocol host:port: client encryption on, or,
	// with AllowPlaintext, plaintext at a literal loopback or private IP.
	// Only this node is contacted.
	Addr string
	// TLSServerName, when set, is the name the node's certificate must carry;
	// otherwise Addr's host. TLSCAPEM pins a private CA; system roots when
	// empty.
	TLSServerName  string
	TLSCAPEM       []byte
	AllowPlaintext bool
	// AdminUser and AdminPassword are a login role allowed to create, alter
	// and drop roles and grant the bound roles (CREATE, ALTER, DROP and
	// AUTHORIZE on ALL ROLES, or a superuser).
	AdminUser     string
	AdminPassword []byte
	// RoleBindings maps each allowed role to the existing Cassandra roles its
	// leases are granted, comma separated, for example "orders_reader"; each
	// carries the permissions the lease should have.
	RoleBindings   map[string]string
	UsernamePrefix string
}

// cassandraAdmin runs one CQL statement as the administrator.
type cassandraAdmin interface {
	Exec(ctx context.Context, statement string) error
	Close()
}

// CassandraBackend issues Cassandra login roles.
type CassandraBackend struct {
	addr          string
	tls           bool
	serverName    string
	caPEM         []byte
	adminUser     string
	adminPassword *secret.Buffer
	roles         map[string][]string
	prefix        string
	connect       func(ctx context.Context) (cassandraAdmin, error)
}

// NewCassandraBackend validates cfg and seals the administrator's password.
func NewCassandraBackend(cfg CassandraConfig) (*CassandraBackend, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Addr))
	if err != nil || host == "" || port == "" {
		return nil, errors.New("dynsecret cassandra: addr must be host:port")
	}
	b := &CassandraBackend{addr: net.JoinHostPort(host, port), tls: !cfg.AllowPlaintext, serverName: cfg.TLSServerName,
		caPEM: append([]byte(nil), cfg.TLSCAPEM...), adminUser: strings.TrimSpace(cfg.AdminUser),
		roles: map[string][]string{}, prefix: cfg.UsernamePrefix}
	switch {
	case cfg.AllowPlaintext:
		if !kafkaPlaintextAddress(b.addr) || cfg.TLSServerName != "" || len(cfg.TLSCAPEM) > 0 {
			return nil, errors.New("dynsecret cassandra: plaintext is allowed only to a literal loopback or private IP, with no TLS settings")
		}
	case b.serverName == "" && net.ParseIP(host) != nil:
		return nil, errors.New("dynsecret cassandra: tls_server_name is required when addr is an IP address")
	}
	if b.serverName == "" {
		b.serverName = host
	}
	if b.adminUser == "" || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret cassandra: the administrator's role and password are required")
	}
	for role, binding := range cfg.RoleBindings {
		for _, name := range strings.Split(binding, ",") {
			name = strings.TrimSpace(name)
			if !cassandraName.MatchString(name) {
				return nil, fmt.Errorf("dynsecret cassandra: role %q: %q is not a plain Cassandra role name", role, name)
			}
			b.roles[role] = append(b.roles[role], name)
		}
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret cassandra: every allowed role needs Cassandra roles in role_bindings")
	}
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	b.connect = b.dialAdmin
	return b, nil
}

// Create implements Backend.
func (b *CassandraBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The role's name derives from the
// lease and every step finds what an earlier attempt left (the role gets the
// new password, a membership it already has stays), so a retry after an
// uncertain attempt converges on one role. Only the password's bcrypt hash
// travels in CQL (HASHED PASSWORD). If a grant fails, the new role is dropped
// again.
func (b *CassandraBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret cassandra: static credentials are not served")
	}
	grants, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret cassandra: role %q has no Cassandra roles", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	if !cassandraName.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret cassandra: generated role name %q is not plain", user)
	}
	password, err := randomPolicyPassword(32)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	hash, err := crypto.HashBcrypt(password, cassandraBcryptCost)
	if err != nil {
		return "", nil, err
	}
	admin, err := b.connect(ctx)
	if err != nil {
		return "", nil, err
	}
	defer admin.Close()
	quoted := `"` + user + `"`
	for _, statement := range []string{
		"CREATE ROLE IF NOT EXISTS " + quoted + " WITH HASHED PASSWORD = '" + string(hash) + "' AND LOGIN = true AND SUPERUSER = false",
		"ALTER ROLE " + quoted + " WITH HASHED PASSWORD = '" + string(hash) + "' AND LOGIN = true",
	} {
		if err := admin.Exec(ctx, statement); err != nil {
			return "", nil, fmt.Errorf("dynsecret cassandra: create role %s failed (%s)", user, cassandraErrorCode(err))
		}
	}
	for _, grant := range grants {
		err := admin.Exec(ctx, "GRANT "+`"`+grant+`"`+" TO "+quoted)
		if err != nil && !cassandraAlreadyMember(err) {
			if cleanup := admin.Exec(ctx, "DROP ROLE IF EXISTS "+quoted); cleanup != nil {
				return "", nil, fmt.Errorf("dynsecret cassandra: grant %s to %s failed (%s), and dropping the new role failed (%s)",
					grant, user, cassandraErrorCode(err), cassandraErrorCode(cleanup))
			}
			return "", nil, fmt.Errorf("dynsecret cassandra: grant %s to %s failed (%s)", grant, user, cassandraErrorCode(err))
		}
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Username: user, Password: password})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the role is dropped, which removes its
// memberships and permissions, so its next login fails and an open
// connection is refused once the node's caches expire. Only roles this
// provider names are touched; one already gone counts as revoked.
func (b *CassandraBackend) Revoke(ctx context.Context, ref string) error {
	if !cassandraName.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret cassandra: refusing to revoke %q, which this provider did not create", ref)
	}
	admin, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer admin.Close()
	if err := admin.Exec(ctx, `DROP ROLE IF EXISTS "`+ref+`"`); err != nil {
		return fmt.Errorf("dynsecret cassandra: drop role %s failed (%s)", ref, cassandraErrorCode(err))
	}
	return nil
}

// Close wipes the administrator's password.
func (b *CassandraBackend) Close() { b.adminPassword.Destroy() }

// cassandraAlreadyMember reports Cassandra's refusal to grant a role the
// grantee already has, which a retry after an uncertain grant meets.
func cassandraAlreadyMember(err error) bool {
	var request gocql.RequestError
	return errors.As(err, &request) && request.Code() == gocql.ErrCodeInvalid && strings.Contains(request.Message(), " is a member of ")
}

// cassandraErrorCode names a failure by Cassandra's error code only: a
// server message can quote the statement.
func cassandraErrorCode(err error) string {
	var request gocql.RequestError
	if errors.As(err, &request) {
		return fmt.Sprintf("Cassandra error 0x%04x", request.Code())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	return "connection error"
}

// dialAdmin opens a session to the configured node only, logged in as the
// administrator.
func (b *CassandraBackend) dialAdmin(ctx context.Context) (cassandraAdmin, error) {
	cluster := gocql.NewCluster(b.addr)
	cluster.Dialer = cassandraDialer{backend: b}
	cluster.Authenticator = cassandraPasswordAuth{user: b.adminUser, password: b.adminPassword}
	cluster.DisableInitialHostLookup = true
	cluster.Events.DisableNodeStatusEvents = true
	cluster.Events.DisableTopologyEvents = true
	cluster.Events.DisableSchemaEvents = true
	cluster.NumConns = 1
	cluster.Timeout = 15 * time.Second
	cluster.ConnectTimeout = 10 * time.Second
	session, err := cluster.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("dynsecret cassandra: admin session failed (%s)", cassandraErrorCode(err))
	}
	return gocqlAdmin{session: session}, nil
}

type gocqlAdmin struct{ session *gocql.Session }

func (a gocqlAdmin) Exec(ctx context.Context, statement string) error {
	return a.session.Query(statement).Consistency(gocql.Quorum).ExecContext(ctx)
}

func (a gocqlAdmin) Close() { a.session.Close() }

// cassandraDialer reaches the node over verified TLS, or plaintext only to a
// literal loopback or private IP.
type cassandraDialer struct{ backend *CassandraBackend }

func (d cassandraDialer) DialContext(ctx context.Context, _, hostPort string) (net.Conn, error) {
	if !d.backend.tls {
		if !kafkaPlaintextAddress(hostPort) {
			return nil, fmt.Errorf("dynsecret cassandra: refusing plaintext to %s, which is not a literal loopback or private IP", hostPort)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", hostPort)
	}
	return mtls.DialVerifiedTCP(ctx, hostPort, d.backend.serverName, d.backend.caPEM)
}

// cassandraPasswordAuth answers Cassandra's PasswordAuthenticator (SASL
// PLAIN) from the sealed password, and sends nothing to another
// authenticator.
type cassandraPasswordAuth struct {
	user     string
	password *secret.Buffer
}

func (a cassandraPasswordAuth) Challenge(req []byte) ([]byte, gocql.Authenticator, error) {
	if string(req) != cassandraAuthenticator {
		return nil, nil, fmt.Errorf("dynsecret cassandra: the node asks for authenticator %q, not %s; no credential sent", req, cassandraAuthenticator)
	}
	var resp []byte
	err := a.password.Use(func(password []byte) error {
		resp = make([]byte, 0, 2+len(a.user)+len(password))
		resp = append(append(append(append(resp, 0), a.user...), 0), password...)
		return nil
	})
	return resp, nil, err
}

func (cassandraPasswordAuth) Success([]byte) error { return nil }
