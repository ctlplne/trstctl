// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every exported ObjectStore field reaches the overlay through its canonical
// TRSTCTL_OBJECT_STORE_* variable, so an env-configured deployment can set
// every field the file can.
func TestEveryObjectStoreFieldHasEnvWiring(t *testing.T) {
	typ := reflect.TypeOf(ObjectStore{})
	env := map[string]string{}
	want := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key := strings.Replace(backupEnvKey(field.Name), "TRSTCTL_BACKUP_", "TRSTCTL_OBJECT_STORE_", 1)
		switch field.Type.Kind() {
		case reflect.String:
			env[key] = "probe-" + strings.ToLower(field.Name)
		case reflect.Bool:
			env[key] = "true"
		case reflect.Int:
			env[key] = "7"
		default:
			t.Fatalf("ObjectStore.%s is a %s; teach this guard its kind", field.Name, field.Type)
		}
		want[field.Name] = env[key]
	}
	var got ObjectStore
	applyObjectStoreEnv(func(k string) string { return env[k] }, &got)
	value := reflect.ValueOf(got)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if rendered := fmt.Sprint(value.Field(i).Interface()); rendered != want[field.Name] {
			t.Errorf("ObjectStore.%s = %q, want %q from its env variable; add the line in applyObjectStoreEnv", field.Name, rendered, want[field.Name])
		}
	}
}

func validObjectStore() ObjectStore {
	return ObjectStore{
		Endpoint: "https://minio.internal:9000", Bucket: "trstctl-archive", PathStyle: true,
		AccessKeyID: "placeholder-key-id", SecretAccessKeyFile: filepath.Join("/run", "secrets", "s3"),
	}
}

// A configured object store must name its endpoint, bucket and credential
// file; plain http is accepted only for an opted-in loopback endpoint.
func TestObjectStoreValidation(t *testing.T) {
	if errs := validateObjectStore(ObjectStore{}); len(errs) != 0 {
		t.Fatalf("an absent object store failed validation: %v", errs)
	}
	if errs := validateObjectStore(validObjectStore()); len(errs) != 0 {
		t.Fatalf("a complete object store failed validation: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*ObjectStore)
		want   string
	}{
		"no endpoint":            {func(o *ObjectStore) { o.Endpoint = "" }, "object_store.endpoint is required"},
		"plain http":             {func(o *ObjectStore) { o.Endpoint = "http://minio.internal:9000" }, "object_store.endpoint"},
		"endpoint path":          {func(o *ObjectStore) { o.Endpoint = "https://minio.internal:9000/bucket" }, "bare scheme://host"},
		"loopback without https": {func(o *ObjectStore) { o.AllowInsecureLoopback = true }, "allow_insecure_loopback requires"},
		"ca on plain loopback": {func(o *ObjectStore) {
			o.Endpoint, o.AllowInsecureLoopback, o.CAFile = "http://127.0.0.1:9000", true, "/etc/ca.pem"
		}, "ca_file requires an https endpoint"},
		"no bucket":          {func(o *ObjectStore) { o.Bucket = "" }, "object_store.bucket is required"},
		"climbing prefix":    {func(o *ObjectStore) { o.Prefix = "prod/../x" }, "object_store.prefix"},
		"no access key":      {func(o *ObjectStore) { o.AccessKeyID = "" }, "access_key_id is required"},
		"no secret file":     {func(o *ObjectStore) { o.SecretAccessKeyFile = "" }, "secret_access_key_file is required"},
		"bad timeout":        {func(o *ObjectStore) { o.Timeout = "soon" }, "object_store.timeout"},
		"timeout too long":   {func(o *ObjectStore) { o.Timeout = "1h" }, "between 1s and 10m"},
		"too many in flight": {func(o *ObjectStore) { o.MaxInFlight = 65 }, "max_in_flight"},
	} {
		cfg := validObjectStore()
		tc.mutate(&cfg)
		errs := validateObjectStore(cfg)
		if len(errs) == 0 || !strings.Contains(fmt.Sprint(errs), tc.want) {
			t.Errorf("%s: errors = %v, want one mentioning %q", name, errs, tc.want)
		}
	}
}

// One-shot tools resolve just the object_store section from the config file
// and the environment, so an unrelated setting cannot block them.
func TestLoadObjectStoreReadsTheSectionAndItsOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"object_store":{"endpoint":"https://minio.internal:9000","bucket":"from-file","path_style":true,"access_key_id":"AKIA","secret_access_key_file":"/run/secrets/s3"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TRSTCTL_CONFIG_FILE": path, "TRSTCTL_OBJECT_STORE_BUCKET": "from-env"}
	got, err := LoadObjectStore(func(k string) string { return env[k] })
	if err != nil || got.Bucket != "from-env" || got.Endpoint != "https://minio.internal:9000" || !got.PathStyle {
		t.Fatalf("LoadObjectStore = %+v %v", got, err)
	}
	env["TRSTCTL_OBJECT_STORE_ENDPOINT"] = "http://minio.internal:9000"
	if _, err := LoadObjectStore(func(k string) string { return env[k] }); err == nil {
		t.Fatal("an invalid object store section loaded")
	}
	if got, err := LoadObjectStore(func(string) string { return "" }); err != nil || got.Configured() {
		t.Fatalf("no configuration = %+v %v, want an empty section", got, err)
	}
}

// The archive switch needs a configured object store; with an archive
// directory as well, the directory stays readable for earlier report
// artifacts while new archives go to the store.
func TestAuditArchiveObjectStoreNeedsAConfiguredStore(t *testing.T) {
	cfg := Default()
	cfg.Audit.ArchiveObjectStore = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "audit.archive_object_store requires an object_store") {
		t.Fatalf("archive_object_store without a store = %v", err)
	}
	cfg.ObjectStore = validObjectStore()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("archive_object_store with a store = %v", err)
	}
	cfg.Audit.ArchiveDir = "/var/lib/trstctl/archive"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("archive_object_store with an archive directory kept for earlier reports = %v", err)
	}
	env := map[string]string{"TRSTCTL_AUDIT_ARCHIVE_OBJECT_STORE": "true"}
	var overlaid Config
	overlaid.applyEnv(func(k string) string { return env[k] })
	if !overlaid.Audit.ArchiveObjectStore {
		t.Fatal("TRSTCTL_AUDIT_ARCHIVE_OBJECT_STORE does not reach audit.archive_object_store")
	}
}
