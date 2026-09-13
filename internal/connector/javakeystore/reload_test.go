// SPDX-License-Identifier: MPL-2.0

package javakeystore_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/javakeystore"
)

type javaReloadOps struct {
	*connector.MemoryOps
	path                  string
	failFirst, failAlways bool
	seen                  [][]byte
}

func (o *javaReloadOps) Exec(name string, args []string) error {
	if name != "tomcat-payments" || len(args) != 0 {
		return errors.New("unexpected action or tenant arguments")
	}
	blob, _ := o.File(o.path)
	o.seen = append(o.seen, blob)
	if o.failAlways || o.failFirst && len(o.seen) == 1 {
		return errors.New("reload refused")
	}
	return o.MemoryOps.Exec(name, args)
}

func TestJavaKeystoreReloadFollowsWriteAndRestoresOnFailure(t *testing.T) {
	for _, format := range []javakeystore.Format{javakeystore.FormatPKCS12, javakeystore.FormatJKS} {
		for _, fail := range []bool{false, true} {
			path := "/etc/app/store." + string(format)
			ops := &javaReloadOps{MemoryOps: connector.NewMemoryOps(), path: path, failFirst: fail}
			previous := []byte("previous-protected-keystore")
			if err := ops.WriteFile(path, previous); err != nil {
				t.Fatal(err)
			}
			c := javakeystore.New(path, []byte(password), alias, javakeystore.WithFormat(format), javakeystore.WithReloadAction("tomcat-payments"))
			defer c.Close()
			dep := connector.NewDeployment("app", []byte(certPEM), []byte(keyPEM))
			_, err := connector.Run(context.Background(), c, ops, dep)
			if (err != nil) != fail {
				t.Fatalf("format=%s failure=%v err=%v", format, fail, err)
			}
			if len(ops.seen) == 0 || bytes.Equal(ops.seen[0], previous) {
				t.Fatal("reload ran before the new keystore was written")
			}
			if fail {
				got, _ := ops.File(path)
				if len(ops.seen) != 2 || !bytes.Equal(ops.seen[1], previous) || !bytes.Equal(got, previous) {
					t.Fatal("failed reload did not restore and activate predecessor")
				}
				if !strings.Contains(err.Error(), "predecessor file restored and reload completed") {
					t.Fatal(err)
				}
			} else {
				if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
					t.Fatal(err)
				}
				if len(ops.seen) != 2 || !bytes.Equal(ops.seen[0], ops.seen[1]) {
					t.Fatal("replay skipped activation or changed bytes")
				}
			}
		}
	}
}

func TestJavaKeystoreRefusesUnsafeInputsWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		password []byte
		format   javakeystore.Format
		action   string
	}{
		{[]byte(password), javakeystore.FormatPKCS12, "/bin/sh"},
		{[]byte(password), javakeystore.FormatPKCS12, "reload --all"},
		{[]byte(password), "unknown", ""},
		{[]byte("pássword"), javakeystore.FormatPKCS12, ""},
		{[]byte("password\n"), javakeystore.FormatPKCS12, ""},
	} {
		ops := connector.NewMemoryOps()
		c := javakeystore.New("/etc/app/server.p12", tc.password, alias, javakeystore.WithFormat(tc.format), javakeystore.WithReloadAction(tc.action))
		defer c.Close()
		_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", []byte(certPEM), []byte(keyPEM)))
		if err == nil || len(ops.Files()) != 0 || len(ops.Execs()) != 0 {
			t.Fatal("invalid Java configuration caused an effect")
		}
	}
}

func TestJavaKeystoreDoesNotClaimRecoveryWhenReloadStillFails(t *testing.T) {
	path := "/etc/app/store.p12"
	ops := &javaReloadOps{MemoryOps: connector.NewMemoryOps(), path: path, failAlways: true}
	c := javakeystore.New(path, []byte(password), alias, javakeystore.WithReloadAction("tomcat-payments"))
	defer c.Close()
	dep := connector.NewDeployment("app", []byte(certPEM), []byte(keyPEM))
	_, err := connector.Run(context.Background(), c, ops, dep)
	if err == nil || !strings.Contains(err.Error(), "no predecessor file exists") || len(ops.seen) != 1 {
		t.Fatal("initial failure concealed missing predecessor")
	}
	previous := []byte("predecessor")
	if err := ops.WriteFile(path, previous); err != nil {
		t.Fatal(err)
	}
	ops.seen = nil
	_, err = connector.Run(context.Background(), c, ops, dep)
	if err == nil || !strings.Contains(err.Error(), "its activation failed") || len(ops.seen) != 2 || !reflect.DeepEqual(ops.seen[1], previous) {
		t.Fatal("failed recovery reported success")
	}
}
