// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SAP/go-hdb/driver/dial"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/netsec"
)

func TestAdmittedPostgresProfileMatchesNativeFields(t *testing.T) {
	for _, key := range []string{"PGSERVICE", "PGAPPNAME", "PGTZ", "PGOPTIONS", "PGTARGETSESSIONATTRS", "PGSSLSNI", "PGSSLNEGOTIATION"} {
		t.Setenv(key, "")
	}
	for _, raw := range []string{
		`host=db.test user=reader password='plain \'word' dbname=orders sslmode=disable connect_timeout=5 application_name=review`,
		"postgresql://reader:plain%20word@db.test:6432/orders?sslmode=disable&connect_timeout=5&application_name=review",
	} {
		admitted, err := postgresDriverConfig([]byte(raw), nil, dbdsn.Admin)
		if err != nil {
			t.Fatal(err)
		}
		nativeInput := raw + " sslrootcert='' sslcert='' sslkey=''"
		if bytes.HasPrefix([]byte(raw), []byte("postgresql://")) {
			nativeInput = raw + "&sslrootcert=&sslcert=&sslkey="
		}
		native, err := pgx.ParseConfig(nativeInput)
		if err != nil {
			t.Fatal("pinned PostgreSQL parser refused the inert reference profile")
		}
		if admitted.Host != native.Host || admitted.Port != native.Port || admitted.User != native.User || admitted.Password != native.Password ||
			admitted.Database != native.Database || admitted.ConnectTimeout != native.ConnectTimeout ||
			admitted.RuntimeParams["application_name"] != native.RuntimeParams["application_name"] || admitted.TLSConfig != nil {
			t.Fatal("admitted PostgreSQL fields differ from the pinned driver")
		}
	}
	t.Setenv("PGSERVICE", "unused")
	t.Setenv("PGAPPNAME", "ambient")
	config, err := postgresDriverConfig([]byte("host=db.test user=reader password=plain dbname=orders sslmode=disable"), nil, dbdsn.Admin)
	if err != nil || config.RuntimeParams["application_name"] != "" || config.DialFunc == nil || config.LookupFunc == nil {
		t.Fatal("the per-attempt PostgreSQL configuration consulted ambient settings or lost its socket hooks")
	}
}

// CR-274/CR-071: only an explicit refusal on the fallback socket itself may
// authorize its plaintext startup. A refusal on another socket is not enough.
func TestNativePostgresPreferPlaintextRequiresRefusal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	profile, err := postgresDriverConfig([]byte("host="+host+" port="+port+" user=review dbname=orders sslmode=prefer"),
		&DatabaseTransport{Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true})}, dbdsn.Admin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	newConnection := func() (net.Conn, net.Conn) {
		t.Helper()
		conn, err := profile.DialFunc(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		peer, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		_ = peer.SetDeadline(deadline)
		return conn, peer
	}
	assertPlain := func(answer byte, allowed bool) {
		t.Helper()
		conn, peer := newConnection()
		startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
		type result struct {
			n   int
			err error
		}
		written := make(chan result, 1)
		go func() {
			n, err := conn.Write(startup)
			written <- result{n, err}
		}()
		probe := make([]byte, 8)
		if _, err := io.ReadFull(peer, probe); err != nil || !bytes.Equal(probe, []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			t.Fatalf("fallback did not probe its own socket: probe=%x err=%v", probe, err)
		}
		if _, err := peer.Write([]byte{answer}); err != nil {
			t.Fatal(err)
		}
		if allowed {
			got := make([]byte, len(startup))
			if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, startup) {
				t.Fatalf("explicitly refused fallback did not send startup: got=%x err=%v", got, err)
			}
		}
		out := <-written
		if allowed && (out.n != len(startup) || out.err != nil) || !allowed && (out.n != 0 || out.err == nil) {
			t.Fatalf("plaintext startup permission = %t, want %t", out.n > 0 && out.err == nil, allowed)
		}
	}
	negotiate := func(answer byte) {
		t.Helper()
		conn, peer := newConnection()
		sslRequest := []byte{0, 0, 0, 8, 4, 210, 22, 47}
		if _, err := conn.Write(sslRequest); err != nil {
			t.Fatal("the configured driver could not start TLS")
		}
		var received [8]byte
		if _, err := io.ReadFull(peer, received[:]); err != nil || !bytes.Equal(received[:], sslRequest) {
			t.Fatal("the TLS request did not reach the configured endpoint")
		}
		if _, err := peer.Write([]byte{answer}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, received[:1]); err != nil || received[0] != answer {
			t.Fatal("the driver did not receive the TLS negotiation response")
		}
		_ = conn.Close()
	}
	assertPlain('S', false)
	negotiate('N')
	assertPlain('S', false)
	assertPlain('N', true)
	negotiate('S')
	assertPlain('S', false)
}

// CR-088: the admitted URI's explicit query host must survive workload issuance.
func TestPostgresWorkloadCredentialPreservesAnExplicitQueryHost(t *testing.T) {
	dsn := []byte("postgresql:///orders?host=db.test&port=6432&user=review")
	admin, err := dbdsn.Parse(dbdsn.Postgres, dsn, dbdsn.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Wipe()
	credential, err := postgresCredentialDSN(dsn, "workload", []byte("plain"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := dbdsn.Parse(dbdsn.Postgres, credential, dbdsn.Credential)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	if !slices.Equal(admin.Hosts, target.Hosts) || admin.Database != target.Database || target.User != "workload" {
		t.Fatal("the issued credential changed the admitted destination")
	}
}

// CR-274: a driver error may carry the upstream login and connection details.
func TestPostgresCredentialOpenKeepsDriverDetailsPrivate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	const visibleOnlyToTheDriver = "private_fixture_database"
	credential := []byte("host=" + host + " port=" + port + " user=review dbname=" + visibleOnlyToTheDriver + " sslmode=disable")
	transport := &DatabaseTransport{Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true})}
	if conn, err := OpenPostgresCredential(ctx, credential, transport); conn != nil ||
		!errors.Is(err, ErrSignInUnreachable) || strings.Contains(err.Error(), visibleOnlyToTheDriver) {
		t.Fatalf("verification returned a nonpublic decision: %v", err)
	}
}

func TestAdmittedMySQLProfileMatchesNativeFields(t *testing.T) {
	const raw = "reader:plain@word@tcp(db.test:3306)/orders?parseTime=true&readTimeout=5s&clientFoundRows=true"
	target, err := dbdsn.Parse(dbdsn.MySQL, []byte(raw), dbdsn.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	admitted, err := mysqlTargetConfig(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	native, err := mysql.ParseDSN(raw)
	if err != nil {
		t.Fatal("pinned MySQL parser refused the inert reference profile")
	}
	if admitted.Net != native.Net || admitted.Addr != native.Addr || admitted.DBName != native.DBName ||
		admitted.User != native.User || admitted.Passwd != native.Passwd || admitted.ReadTimeout != 5*time.Second ||
		admitted.ParseTime != native.ParseTime || admitted.ClientFoundRows != native.ClientFoundRows || admitted.AllowAllFiles || admitted.DialFunc == nil {
		t.Fatal("admitted MySQL fields differ from the pinned driver or lack socket policy")
	}
}

func TestAdmittedMongoProfileMatchesNativeFields(t *testing.T) {
	fixture := url.URL{Scheme: "mongodb", User: url.UserPassword("reader", "plain@word"), Host: "db.test:27017", Path: "/orders",
		RawQuery: "authSource=admin;directConnection=true&tls=false"}
	raw := fixture.String()
	target, err := dbdsn.Parse(dbdsn.Mongo, []byte(raw), dbdsn.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	native, err := connstring.ParseAndValidate(raw)
	if err != nil {
		t.Fatal("pinned MongoDB parser refused the inert reference profile")
	}
	if !slices.Equal(target.Hosts, native.Hosts) || target.User != native.Username || !bytes.Equal(target.Password, []byte(native.Password)) ||
		target.Database != native.Database || target.AuthSource != native.AuthSource || target.Options["directconnection"] != "true" || !native.DirectConnection {
		t.Fatal("admitted MongoDB fields differ from the pinned driver")
	}
}

// CR-274: the pinned driver supports early 4.2 nodes where isMaster is the
// only topology probe. An authorization refusal must not trigger a retry.
func TestMongoTopologyProbePreservesLegacyServers(t *testing.T) {
	for _, code := range []int32{0, 59, 13} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			var commands []string
			reply, err := readMongoTopologyProbe(func(name string) *mongo.SingleResult {
				commands = append(commands, name)
				var err error
				if code != 0 && name == "hello" {
					err = mongo.CommandError{Code: code}
				}
				return mongo.NewSingleResultFromDocument(bson.D{{Key: "ismaster", Value: true}}, err, nil)
			})
			if code == 13 {
				if err == nil || !slices.Equal(commands, []string{"hello"}) {
					t.Fatal("a server authorization error retried the topology probe")
				}
				return
			}
			if err != nil || !reply.Lookup("ismaster").Boolean() {
				t.Fatal("the compatible topology command did not read the server")
			}
			if code == 59 && !slices.Equal(commands, []string{"hello", "isMaster"}) ||
				code == 0 && !slices.Equal(commands, []string{"hello"}) {
				t.Fatal("the connector used the wrong topology command sequence")
			}
		})
	}
}

func TestMongoNativeDiscoveryBoundsAndPreservesExplicitOptions(t *testing.T) {
	probe, err := bson.Marshal(bson.D{{Key: "hosts", Value: bson.A{"seed.test:27017", "member.test:27017", "seed.test:27017"}}})
	if err != nil {
		t.Fatal(err)
	}
	peers, err := appendMongoMembers([]string{"seed.test:27017"}, bson.Raw(probe))
	if err != nil || !slices.Equal(peers, []string{"seed.test:27017", "member.test:27017"}) {
		t.Fatal("an admissible replica membership list was lost")
	}
	tooMany := make(bson.A, dbdsn.MaxHosts+1)
	for i := range tooMany {
		tooMany[i] = "member.test:27017"
	}
	probe, err = bson.Marshal(bson.D{{Key: "hosts", Value: tooMany}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendMongoMembers(nil, bson.Raw(probe)); err == nil {
		t.Fatal("MongoDB discovery admitted an oversized membership list")
	}
	profile := dbdsn.Target{AuthSource: "explicit", ExplicitAuthSource: true, Options: map[string]string{"replicaset": "review"}}
	if !mergeMongoTXT(&profile, "authSource=default&replicaSet=ignored&loadBalanced=false") ||
		profile.AuthSource != "explicit" || profile.Options["replicaset"] != "review" || profile.Options["loadbalanced"] != "false" {
		t.Fatal("MongoDB TXT defaults replaced an explicit setting")
	}
	if mergeMongoTXT(&profile, "tls=true") {
		t.Fatal("MongoDB TXT accepted an option outside its discovery allowance")
	}
}

// PLAN-SIB-74: concurrent native Strict connections must each receive their
// own TLS configuration, and the connector must check the selected host.
func TestMSSQLStrictNativeConnectorKeepsPerConnectionTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const attempts = 4
	accepted := make(chan error, 1)
	go func() {
		for range attempts {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- err
				return
			}
			// A socket that closes during an ordinary TLS startup. The test
			// never emulates a TDS login or handles credential bytes.
			_ = conn.Close()
		}
		accepted <- nil
	}()
	profile := url.URL{Scheme: "sqlserver", User: url.UserPassword("reader", "plain"), Host: listener.Addr().String(),
		RawQuery: "database=orders&encrypt=strict"}
	target, err := dbdsn.Parse(dbdsn.MSSQL, []byte(profile.String()), dbdsn.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	var checked atomic.Int32
	dialer := netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true, CheckName: func(host string) error {
		if host != "127.0.0.1" {
			return netsec.ErrSSRFBlocked
		}
		checked.Add(1)
		return nil
	}})
	db, err := mssqlProfileDB(mssqlProfileURL(target, target.Database), target.User, target.Password, &DatabaseTransport{Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var group sync.WaitGroup
	for range attempts {
		group.Go(func() {
			if err := db.PingContext(ctx); err == nil {
				t.Error("the closed native TLS connection reported success")
			}
		})
	}
	group.Wait()
	select {
	case err := <-accepted:
		if err != nil || checked.Load() != attempts {
			t.Fatal("native Strict sessions did not use distinct admitted sockets")
		}
	case <-ctx.Done():
		t.Fatal("a native Strict attempt bypassed the instrumented connector")
	}
}

func TestHANANativeConnectorChecksItsConfiguredListener(t *testing.T) {
	fixture := url.URL{Scheme: "hdb", Host: "hana.test:39041", User: url.UserPassword("reader", "plain")}
	checked := false
	dialer := netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{CheckName: func(host string) error {
		checked = host == "hana.test"
		return netsec.ErrSSRFBlocked
	}})
	if db, err := OpenHANAExecutorWithTransport(t.Context(), []byte(fixture.String()), &DatabaseTransport{Dialer: dialer}); db != nil || err == nil || !checked {
		t.Fatal("the native HANA connector failed to enforce the configured name guard")
	}
}

func TestNativeSQLDialersEnforceTheirAdmittedListeners(t *testing.T) {
	newEndpoint := func() string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return ln.Addr().String()
	}
	initial, routed, other := newEndpoint(), newEndpoint(), newEndpoint()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	operator := netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true})
	oracle := &oracleDirectDial{endpoint: initial, dialer: operator}
	conn, err := oracle.DialContext(ctx, "tcp", initial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := oracle.DialContext(ctx, "tcp", initial); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatal("Oracle followed a second native dial")
	}
	mssql := &mssqlProfileDial{initial: initial, routes: []string{routed}, dialer: operator}
	if _, err := mssql.DialContext(ctx, "udp", initial); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatal("SQL Server contacted a non-TCP protocol")
	}
	conn, err = mssql.DialContext(ctx, "tcp", initial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := mssql.DialContext(ctx, "tcp", other); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatal("SQL Server dialed an unapproved routed listener")
	}
	conn, err = mssql.DialContext(ctx, "tcp", routed)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := mssql.DialContext(ctx, "tcp", routed); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatal("SQL Server followed more than one native routing hop")
	}
	hana := hanaProfileDial{endpoint: initial, dialer: operator}
	if _, err := hana.DialContext(ctx, routed, dial.DialerOptions{}); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatal("HANA opened a different listener than its admitted route")
	}
	conn, err = hana.DialContext(ctx, initial, dial.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
