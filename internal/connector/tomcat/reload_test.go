// SPDX-License-Identifier: BUSL-1.1

package tomcat_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/tomcat"
)

var errReload = errors.New("TLS reload acknowledgment failed")

type tomcatTLSOps struct {
	*connector.MemoryOps
	certPath, keyPath     string
	calls                 int
	failFirst, failAlways bool
	served                []byte
	seenCerts, seenKeys   [][]byte
}

func (o *tomcatTLSOps) Exec(name string, args []string) error {
	if name != "tomcat-tls-reload" || len(args) != 0 {
		return errors.New("expected fixed TLS activation, not the unsupported catalina.sh reload command")
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

func tomcatReloadFixture(t *testing.T, predecessor bool) *tomcatTLSOps {
	t.Helper()
	o := &tomcatTLSOps{MemoryOps: connector.NewMemoryOps(), certPath: "/tomcat/tls/server.crt", keyPath: "/tomcat/tls/server.key"}
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

func TestTomcatTLSActivationUsesFixedActionAndRepeatsForIdenticalFiles(t *testing.T) {
	o := tomcatReloadFixture(t, true)
	c := tomcat.New(o.certPath, o.keyPath)
	dep := connector.NewDeployment("tomcat", tomcatCert, tomcatKey)
	for i := 1; i <= 2; i++ {
		// Represents a service which has not adopted the current files (for example
		// a lost reload acknowledgment or a process restart using another context).
		o.served = []byte("old-public-certificate")
		if _, err := connector.Run(context.Background(), c, o, dep); err != nil {
			t.Fatal(err)
		}
		if o.calls != i || !bytes.Equal(o.served, tomcatCert) || !bytes.Equal(o.seenKeys[i-1], tomcatKey) {
			t.Fatal("matching disk bytes hid missing live TLS activation")
		}
	}
}

func TestTomcatTLSActivationRestoresAndReactivatesPredecessor(t *testing.T) {
	o := tomcatReloadFixture(t, true)
	o.failFirst = true
	_, err := connector.Run(context.Background(), tomcat.New(o.certPath, o.keyPath), o, connector.NewDeployment("tomcat", tomcatCert, tomcatKey))
	if !errors.Is(err, errReload) || !strings.Contains(err.Error(), "predecessor files restored and TLS reload completed") {
		t.Fatalf("missing original failure/recovery evidence: %v", err)
	}
	if o.calls != 2 || !bytes.Equal(o.seenCerts[0], tomcatCert) || !bytes.Equal(o.served, []byte("old-public-certificate")) || !bytes.Equal(o.seenKeys[1], []byte("old-private-test-fixture")) {
		t.Fatal("failed activation did not restore and reload the complete predecessor")
	}
}

func TestTomcatTLSActivationDoesNotClaimMissingOrFailedRecovery(t *testing.T) {
	for _, predecessor := range []bool{false, true} {
		o := tomcatReloadFixture(t, predecessor)
		o.failAlways = true
		_, err := connector.Run(context.Background(), tomcat.New(o.certPath, o.keyPath), o, connector.NewDeployment("tomcat", tomcatCert, tomcatKey))
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

type tomcatWriteFailureOps struct {
	*tomcatTLSOps
	writes int
	failAt map[int]bool
}

var errTomcatWrite = errors.New("fixture filesystem write refused")

func (o *tomcatWriteFailureOps) WriteFile(path string, value []byte) error {
	o.writes++
	if o.failAt[o.writes] {
		return errTomcatWrite
	}
	return o.MemoryOps.WriteFile(path, value)
}

func TestTomcatTLSActivationReportsFileRecoveryFailures(t *testing.T) {
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
			o := &tomcatWriteFailureOps{tomcatTLSOps: tomcatReloadFixture(t, true), failAt: tc.failAt}
			o.failFirst = tc.reloadFails
			_, err := connector.Run(context.Background(), tomcat.New(o.certPath, o.keyPath), o, connector.NewDeployment("tomcat", tomcatCert, tomcatKey))
			original := errTomcatWrite
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
