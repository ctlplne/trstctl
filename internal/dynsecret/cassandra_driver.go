// SPDX-License-Identifier: BUSL-1.1

//go:build !gofuzz

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The Cassandra driver is left out of fuzz builds (cassandra_gofuzz.go).

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
