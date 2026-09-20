// SPDX-License-Identifier: BUSL-1.1

package mysql_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/mysql"
)

var errReload = errors.New("TLS reload acknowledgement failed")

type mysqlTLSOps struct {
	*connector.MemoryOps
	certPath, keyPath     string
	calls                 int
	failFirst, failAlways bool
	served                []byte
	seenCerts, seenKeys   [][]byte
}

func (o *mysqlTLSOps) Exec(name string, args []string) error {
	if name != "mysql-tls-reload" || len(args) != 0 {
		return errors.New("expected fixed TLS activation, not a grant-table reload")
	}
	cert, _ := o.File(o.certPath)
	key, _ := o.File(o.keyPath)
	o.calls++
	o.seenCerts = append(o.seenCerts, cert)
	o.seenKeys = append(o.seenKeys, key)
	// Exercise an ambiguous failure after the server accepted the activation.
	// Restoring disk files alone would leave the wrong certificate in memory.
	o.served = bytes.Clone(cert)
	if o.failAlways || o.failFirst && o.calls == 1 {
		return errReload
	}
	return o.MemoryOps.Exec(name, args)
}

func mysqlReloadFixture(t *testing.T, predecessor bool) *mysqlTLSOps {
	t.Helper()
	o := &mysqlTLSOps{MemoryOps: connector.NewMemoryOps(), certPath: "/mysql/tls/server.crt", keyPath: "/mysql/tls/server.key"}
	if predecessor {
		if err := o.WriteFile(o.certPath, []byte("old-public-certificate")); err != nil {
			t.Fatal(err)
		}
		if err := o.WriteFile(o.keyPath, []byte("old-private-test-fixture")); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestMySQLTLSActivationUsesFixedActionAndRepeatsForIdenticalFiles(t *testing.T) {
	o := mysqlReloadFixture(t, true)
	c := mysql.New(o.certPath, o.keyPath)
	dep := connector.NewDeployment("mysql", mysqlCert, mysqlKey)
	for i := 1; i <= 2; i++ {
		// Represents a service which has not adopted the current files (for example
		// a lost reload acknowledgement or a process restart using another context).
		o.served = []byte("old-public-certificate")
		if _, err := connector.Run(context.Background(), c, o, dep); err != nil {
			t.Fatal(err)
		}
		if o.calls != i || !bytes.Equal(o.served, mysqlCert) || !bytes.Equal(o.seenKeys[i-1], mysqlKey) {
			t.Fatal("matching disk bytes hid missing live TLS activation")
		}
	}
}

func TestMySQLTLSActivationRestoresAndReactivatesPredecessor(t *testing.T) {
	o := mysqlReloadFixture(t, true)
	o.failFirst = true
	_, err := connector.Run(context.Background(), mysql.New(o.certPath, o.keyPath), o, connector.NewDeployment("mysql", mysqlCert, mysqlKey))
	if !errors.Is(err, errReload) || !strings.Contains(err.Error(), "predecessor files restored and TLS reload completed") {
		t.Fatalf("missing original failure/recovery evidence: %v", err)
	}
	if o.calls != 2 || !bytes.Equal(o.seenCerts[0], mysqlCert) || !bytes.Equal(o.served, []byte("old-public-certificate")) || !bytes.Equal(o.seenKeys[1], []byte("old-private-test-fixture")) {
		t.Fatal("failed activation did not restore and reload the complete predecessor")
	}
}

func TestMySQLTLSActivationDoesNotClaimMissingOrFailedRecovery(t *testing.T) {
	for _, predecessor := range []bool{false, true} {
		o := mysqlReloadFixture(t, predecessor)
		o.failAlways = true
		_, err := connector.Run(context.Background(), mysql.New(o.certPath, o.keyPath), o, connector.NewDeployment("mysql", mysqlCert, mysqlKey))
		if !errors.Is(err, errReload) {
			t.Fatalf("original failure was lost: %v", err)
		}
		if predecessor {
			if o.calls != 2 || !strings.Contains(err.Error(), "its TLS activation failed") {
				t.Fatalf("failed recovery hidden: %v", err)
			}
		} else if o.calls != 1 || !strings.Contains(err.Error(), "no complete predecessor") {
			t.Fatalf("missing predecessor hidden: %v", err)
		}
	}
}

type mysqlWriteFailureOps struct {
	*mysqlTLSOps
	writes int
	failAt map[int]bool
}

var errMySQLWrite = errors.New("fixture filesystem write refused")

func (o *mysqlWriteFailureOps) WriteFile(path string, value []byte) error {
	o.writes++
	if o.failAt[o.writes] {
		return errMySQLWrite
	}
	return o.MemoryOps.WriteFile(path, value)
}

func TestMySQLTLSActivationReportsFileRecoveryFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failAt      map[int]bool
		reloadFails bool
		want        string
		calls       int
	}{
		{"key write", map[int]bool{2: true}, false, "predecessor files restored", 0},
		{"key write and restore", map[int]bool{2: true, 3: true}, false, "predecessor restore failed", 0},
		{"reload and restore", map[int]bool{3: true}, true, "predecessor restore failed", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &mysqlWriteFailureOps{mysqlTLSOps: mysqlReloadFixture(t, true), failAt: tc.failAt}
			o.failFirst = tc.reloadFails
			_, err := connector.Run(context.Background(), mysql.New(o.certPath, o.keyPath), o, connector.NewDeployment("mysql", mysqlCert, mysqlKey))
			original := errMySQLWrite
			if tc.reloadFails {
				original = errReload
			}
			if !errors.Is(err, original) || !strings.Contains(err.Error(), tc.want) || o.calls != tc.calls {
				t.Fatalf("failure/recovery evidence lost: err=%v calls=%d", err, o.calls)
			}
			if tc.name == "key write" {
				cert, _ := o.File(o.certPath)
				key, _ := o.File(o.keyPath)
				if !bytes.Equal(cert, []byte("old-public-certificate")) || !bytes.Equal(key, []byte("old-private-test-fixture")) {
					t.Fatal("partial write was not restored before reporting failure")
				}
			}
		})
	}
}
