// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"bytes"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
)

func TestDatabaseProfilesKeepAdmittedRoutingAndBytePasswords(t *testing.T) {
	for _, tt := range []struct {
		driver, dsn, user, password, database, auth string
		hosts                                       []string
	}{
		{Postgres, "host=db.test\vuser=reader\fpassword='one two' dbname=orders\n", "reader", "one two", "orders", "", []string{"db.test:5432"}},
		{Postgres, "postgresql://reader:one%2Btwo@DB.test:6432,replica.test/orders?ssl=true", "reader", "one+two", "orders", "", []string{"db.test:6432", "replica.test:5432"}},
		{MySQL, "reader:one@two@tcp(db.test)/orders?parseTime=true\r\n", "reader", "one@two", "orders", "", []string{"db.test:3306"}},
		{Mongo, "mongodb://reader:one%40two@db.test/orders?authSource=admin;tls=true", "reader", "one@two", "orders", "admin", []string{"db.test:27017"}},
		{Oracle, "oracle://reader:one%20two@db.test/orders?SSL=TRUE", "reader", "one two", "orders", "", []string{"db.test:1521"}},
		{MSSQL, "sqlserver://reader:one%20two@db.test?database=orders&encrypt=mandatory", "reader", "one two", "orders", "", []string{"db.test:1433"}},
		{HANA, "hdb://reader:one%20two@db.test:39041?defaultSchema=ORDERS", "reader", "one two", "", "", []string{"db.test:39041"}},
	} {
		t.Run(tt.driver, func(t *testing.T) {
			target, err := Parse(tt.driver, []byte(tt.dsn), Admin)
			if err != nil {
				t.Fatal(err)
			}
			if target.User != tt.user || !bytes.Equal(target.Password, []byte(tt.password)) || target.Database != tt.database ||
				target.AuthSource != tt.auth || !slices.Equal(target.Hosts, tt.hosts) {
				t.Fatal("driver profile changed an admitted connection field")
			}
			target.Wipe()
			if target.Password != nil || target.passwordBuffer != nil {
				t.Fatal("parsed password survived release of its locked storage")
			}
		})
	}
}

func TestDatabaseProfilesRefuseAmbiguousOrUnboundedAuthority(t *testing.T) {
	for _, tt := range []struct{ driver, dsn string }{
		{Postgres, "host=db.test user=reader dbname=orders database=other"},
		{Postgres, "postgres://reader:plain@db.test/orders?ssl=true&sslmode=disable"},
		{Postgres, "postgres://reader:plain@db.test/orders?%64bname=other"},
		{Mongo, "mongodb://reader:plain@db.test/orders?tls=true;ssl=false"},
		{Mongo, "mongodb://reader:plain@db.test,replica.test/orders?directConnection=true"},
		{Mongo, "mongodb://reader:plain@db.test/orders?connect=direct&directConnection=false"},
		{MySQL, "reader:plain@tcp(db.test:3306)/orders?loc=unsupported"},
		{Oracle, "oracle://reader:plain@db.test/orders?timeout=1&READ+TIMEOUT=1"},
		{MSSQL, "sqlserver://reader:plain@db.test/instance?database=orders"},
		{HANA, "hdb://reader:plain@db.test:39041?databaseName=redirect"},
		{Postgres, strings.Repeat("x", MaxBytes+1)},
		{Postgres, "postgres://reader:plain@" + strings.Repeat("db.test,", MaxHosts) + "db.test/orders"},
	} {
		t.Run(tt.driver, func(t *testing.T) {
			target, err := Parse(tt.driver, []byte(tt.dsn), Admin)
			target.Wipe()
			if err == nil {
				t.Fatal("the driver profile accepted ambiguous connection authority")
			}
		})
	}
}

// CR-276: refuse a provider route before issuing material the gateway cannot use.
func TestPostgresGatewayRejectsUnsupportedProviderOptions(t *testing.T) {
	for _, option := range []string{
		"sslnegotiation=direct", "target_session_attrs=primary", "search_path=orders",
		"statement_timeout=1000", "lock_timeout=1000",
	} {
		t.Run(option, func(t *testing.T) {
			profile, err := Parse(Postgres, []byte("host=db.test user=reader dbname=orders "+option), Admin)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Wipe()
			if _, err := GatewayTLSMode(Postgres, profile, false); !errors.Is(err, ErrGatewayRoute) {
				t.Fatal("gateway admission accepted a native-only option")
			}
		})
	}
	profile, err := Parse(Postgres, []byte("host=db.test user=reader dbname=orders sslnegotiation=postgres"), Gateway)
	if err != nil {
		t.Fatal("the gateway must accept standard PostgreSQL SSL negotiation")
	}
	profile.Wipe()
}

// CR-276: the workload database and the authentication database are distinct.
func TestMongoGatewayBindsBothDatabaseFields(t *testing.T) {
	route := GatewayRoute{Revision: GatewayRouteRevision, ProviderID: "review", Hosts: []string{"db.test:27017"},
		Database: "orders", TLS: GatewayVerifiedTLS, Source: OperatorFileSource}
	for _, tc := range []struct {
		name, path, auth string
		allowed          bool
	}{
		{name: "same route", path: "/orders", auth: "orders", allowed: true},
		{name: "unspecified initial database", path: "/", auth: "orders", allowed: true},
		{name: "different initial database", path: "/other", auth: "orders"},
		{name: "different auth database", path: "/orders", auth: "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := []byte("mongodb://reader:plain@db.test:27017" + tc.path + "?authSource=" + tc.auth)
			if err := route.CheckCredential(Mongo, value, false); (err == nil) != tc.allowed {
				t.Fatalf("route admission returned %v, allowed = %t", err, tc.allowed)
			}
		})
	}
}

func FuzzDatabaseConnectionProfiles(f *testing.F) {
	for _, raw := range []string{
		"postgresql://reader:plain@db.test/orders?sslmode=disable", "host=db.test user=reader password='plain' dbname=orders",
		"mongodb://reader:plain@db.test/orders?authSource=orders", "reader:plain@tcp(db.test:3306)/orders",
		"oracle://reader:plain@db.test:1521/orders", "sqlserver://reader:plain@db.test:1433?database=orders",
		"hdb://reader:plain@db.test:39041?defaultSchema=ORDERS",
	} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, driver := range []string{Postgres, Mongo, MySQL, Oracle, MSSQL, HANA} {
			for _, purpose := range []Purpose{Admin, Credential, Gateway} {
				profile, err := Parse(driver, raw, purpose)
				if err != nil {
					continue
				}
				profile.Wipe()
				if len(profile.Hosts) == 0 || len(profile.Hosts) > MaxHosts || len(profile.Options) > MaxOptions || purpose != Admin && profile.CAFile != "" {
					t.Fatal("admitted profile escaped its bounds")
				}
				for _, endpoint := range profile.Hosts {
					host, port, err := net.SplitHostPort(endpoint)
					canonical, canonicalErr := TCPAddress(host, port)
					if err != nil || canonicalErr != nil || canonical != endpoint {
						t.Fatal("the parsed profile produced an invalid dial endpoint")
					}
				}
			}
		}
	})
}
