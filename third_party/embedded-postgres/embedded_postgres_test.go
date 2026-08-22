// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"reflect"
	"testing"
)

func TestPostgresStartArgsCaptureServerLog(t *testing.T) {
	config := Config{
		binariesPath: "/private/bin",
		dataPath:     "/private/data",
		port:         42405,
	}
	want := []string{
		"/private/bin/bin/pg_ctl", "start", "-w",
		"-D", "/private/data",
		"-l", "/private/runtime/postgres.log",
		"-o", "-p 42405",
	}
	if got := postgresStartArgs(config, "/private/runtime/postgres.log"); !reflect.DeepEqual(got, want) {
		t.Fatalf("postgres start args = %q, want %q", got, want)
	}
}
