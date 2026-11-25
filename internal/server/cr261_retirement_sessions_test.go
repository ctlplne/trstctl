// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
)

func TestCR261MongoRetireEndsAnOpenSession(t *testing.T) {
	lab := startLabMongo(t)
	passwordBytes, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes)
	for _, user := range []string{"cr261_a", "cr261_b"} {
		if _, err := lab.eval(`db.getSiblingDB("orders").createUser({user:"` + user + `",pwd:"` + password + `",roles:[{role:"readWrite",db:"orders"}]})`); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	adminURI := (&url.URL{Scheme: "mongodb", User: url.UserPassword("root", lab.rootPassword), Host: lab.addr, Path: "/orders", RawQuery: "authSource=admin&directConnection=true"}).String()
	admin, err := dynsecret.OpenMongoAdmin(ctx, []byte(adminURI))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	backend, err := dynsecret.NewMongoBackend(admin, dynsecret.MongoConfig{Database: "orders", RotationAccounts: map[string][2]string{"orders": {"cr261_a", "cr261_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	client, err := mongo.Connect(options.Client().ApplyURI(lab.uri("cr261_a", password)).SetMaxPoolSize(1).SetMinPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	collection := client.Database("orders").Collection("cr261")
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "step", Value: "before"}}); err != nil {
		t.Fatalf("open lease session before retirement: %v", err)
	}
	if err := backend.Revoke(ctx, "cr261_a"); err != nil {
		t.Fatalf("retire reported failure: %v", err)
	}
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "step", Value: "after"}}); err == nil {
		t.Fatal("retirement completed while an already-open MongoDB session could still write")
	}
}

func TestCR261PostgresRetireRefusesAnUnkillableSession(t *testing.T) {
	adminDSN, stop := startPAMPostgres(t)
	defer stop()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	superuser, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = superuser.Close(context.Background()) }()
	passwordBytes, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes)
	for _, statement := range []string{
		`CREATE ROLE cr261_admin LOGIN CREATEROLE PASSWORD '` + password + `'`,
		`CREATE TABLE cr261_test(id int)`,
		`GRANT SELECT ON cr261_test TO cr261_admin WITH GRANT OPTION`,
	} {
		if _, err := superuser.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	adminURL, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	adminURL.User = url.UserPassword("cr261_admin", password)
	caPEM, err := os.ReadFile(adminURL.Query().Get("sslrootcert")) // #nosec G304 -- CA is the test-owned file from startPAMPostgres (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport := &dynsecret.DatabaseTransport{Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true}), CAPEM: caPEM, ServerName: "localhost"}
	limitedAdmin, err := pgx.Connect(ctx, adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limitedAdmin.Exec(ctx, `CREATE ROLE cr261_a LOGIN PASSWORD '`+password+`'`); err != nil {
		t.Fatal(err)
	}
	_ = limitedAdmin.Close(ctx)
	if _, err := superuser.Exec(ctx, `GRANT SELECT ON cr261_test TO cr261_a`); err != nil {
		t.Fatal(err)
	}
	leaseURL, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	leaseURL.User = url.UserPassword("cr261_a", password)
	session, err := pgx.Connect(ctx, leaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close(context.Background()) }()
	var count int
	if err := session.QueryRow(ctx, `SELECT count(*) FROM cr261_test`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	backend, err := dynsecret.NewPostgresBackend(dynsecret.PostgresConfig{DSN: []byte(adminURL.String()), Transport: transport, Database: "postgres", RotationAccounts: map[string][2]string{"orders": {"cr261_a", "cr261_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	retireErr := backend.Revoke(ctx, "cr261_a")
	readErr := session.QueryRow(ctx, `SELECT count(*) FROM cr261_test`).Scan(&count)
	t.Logf("retire error: %v; same-session read error: %v", retireErr, readErr)
	if retireErr == nil && readErr == nil {
		t.Fatal("retirement completed while an unkillable PostgreSQL session could still read")
	}
	if retireErr == nil {
		t.Fatal("limited administrator unexpectedly retired the open session")
	}
	privileged, err := dynsecret.NewPostgresBackend(dynsecret.PostgresConfig{DSN: []byte(adminDSN), Transport: transport, Database: "postgres", RotationAccounts: map[string][2]string{"orders": {"cr261_a", "cr261_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer privileged.Close()
	if err := privileged.Revoke(ctx, "cr261_a"); err != nil {
		t.Fatalf("privileged retry failed to end the session: %v", err)
	}
	if err := session.QueryRow(ctx, `SELECT count(*) FROM cr261_test`).Scan(&count); err == nil {
		t.Fatal("privileged retirement reported success while the old PostgreSQL session still read")
	}
}
