// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// backupEnvKey converts an exported Backup field name to its canonical
// environment variable, following the existing TRSTCTL_BACKUP_* names exactly
// (EncryptionKeyFile -> TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE,
// DrillRPO -> TRSTCTL_BACKUP_DRILL_RPO).
func backupEnvKey(field string) string {
	var b strings.Builder
	runes := []rune(field)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prevLower := unicode.IsLower(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLower || (unicode.IsUpper(runes[i-1]) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return "TRSTCTL_BACKUP_" + b.String()
}

// TestEveryBackupFieldHasEnvWiring is the completeness guard for AUD-201
// follow-up A3/V35. Backup.ManifestSigningKeyFile and
// Backup.TrustedManifestKeyFiles shipped with no applyEnv entry while every
// sibling field had one, so env-configured deployments silently could not
// enable manifest signing — backups were written unsigned with no error and
// the failure surfaced at disaster-recovery time. This test probes every
// exported Backup field through its canonical environment variable, so the
// next added field cannot silently miss its wiring.
func TestEveryBackupFieldHasEnvWiring(t *testing.T) {
	typ := reflect.TypeOf(Backup{})
	env := map[string]string{}
	want := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		key := backupEnvKey(field.Name)
		// One probe value per kind. "7m33s" parses as a duration for the
		// Drill* fields and is an inert string for the path fields; CSV fields
		// get two entries to prove list decoding.
		switch field.Type.Kind() {
		case reflect.String:
			env[key] = "7m33s"
			want[field.Name] = "7m33s"
		case reflect.Slice:
			if field.Type.Elem().Kind() != reflect.String {
				t.Fatalf("Backup.%s is a %s; teach this guard its kind", field.Name, field.Type)
			}
			env[key] = "7m33s,14m6s"
			want[field.Name] = "7m33s,14m6s"
		case reflect.Bool:
			env[key] = "true"
			want[field.Name] = "true"
		default:
			t.Fatalf("Backup.%s is a %s; teach this guard its kind", field.Name, field.Type)
		}
	}

	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with backup env probes: %v", err)
	}

	got := reflect.ValueOf(cfg.Backup)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		value := got.Field(i)
		var rendered string
		switch field.Type.Kind() {
		case reflect.String:
			rendered = value.String()
		case reflect.Slice:
			parts := make([]string, value.Len())
			for j := 0; j < value.Len(); j++ {
				parts[j] = value.Index(j).String()
			}
			rendered = strings.Join(parts, ",")
		case reflect.Bool:
			rendered = fmt.Sprintf("%t", value.Bool())
		}
		if rendered != want[field.Name] {
			t.Errorf("Backup.%s did not receive its env probe via %s (got %q, want %q); "+
				"add the setString/setCSV/setBool line in applyEnv",
				field.Name, backupEnvKey(field.Name), rendered, want[field.Name])
		}
	}
}
