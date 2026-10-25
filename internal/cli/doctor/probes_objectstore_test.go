// SPDX-License-Identifier: BUSL-1.1

package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// objectStoreEnv points doctor at a fake S3 store the way an operator's
// TRSTCTL_OBJECT_STORE_* environment points the control plane at theirs.
func objectStoreEnv(t *testing.T, srv *s3test.Server) func(string) string {
	t.Helper()
	secretPath := filepath.Join(t.TempDir(), "s3-secret")
	if err := os.WriteFile(secretPath, srv.Secret, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"TRSTCTL_OBJECT_STORE_ENDPOINT":                srv.URL,
		"TRSTCTL_OBJECT_STORE_BUCKET":                  srv.Bucket,
		"TRSTCTL_OBJECT_STORE_PATH_STYLE":              "true",
		"TRSTCTL_OBJECT_STORE_ALLOW_INSECURE_LOOPBACK": "true",
		"TRSTCTL_OBJECT_STORE_ACCESS_KEY_ID":           srv.AccessKeyID,
		"TRSTCTL_OBJECT_STORE_SECRET_ACCESS_KEY_FILE":  secretPath,
		"TRSTCTL_OBJECT_STORE_PREFIX":                  "deployment-a/",
	}
	return func(k string) string { return env[k] }
}

func runDoctorWithEnv(t *testing.T, getenv func(string) string, args ...string) (Receipt, int) {
	t.Helper()
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	var stdout, stderr bytes.Buffer
	full := append([]string{"--postgres-dsn", testDSN, "--json", receiptPath}, args...)
	code := 0
	if err := Run(context.Background(), full, getenv, &stdout, &stderr); err != nil {
		exit, ok := err.(ExitError)
		if !ok {
			t.Fatalf("doctor returned a non-exit error: %v (stderr %s)", err, stderr.String())
		}
		code = exit.Code
	}
	blob, err := os.ReadFile(receiptPath) // #nosec G304 -- test reads its own tempdir receipt (CWE-22)
	if err != nil {
		t.Fatalf("receipt not written: %v (stderr %s)", err, stderr.String())
	}
	var r Receipt
	if err := json.Unmarshal(blob, &r); err != nil {
		t.Fatalf("receipt does not parse: %v", err)
	}
	return r, code
}

// With an object store configured and --write-probe, the object lane writes a
// marker under one probe tenant's prefix, proves a second probe tenant cannot
// list, read or climb to it, proves the store refuses an overwrite, and
// removes every probe object, verified by a fresh listing.
func TestDoctorObjectStoreLaneProvesPrefixConfinement(t *testing.T) {
	srv := s3test.NewServer(t)
	r, code := runDoctorWithEnv(t, objectStoreEnv(t, srv), "--prove-isolation", "--write-probe")
	if code != 0 {
		t.Fatalf("doctor exit = %d, want 0: %+v", code, r.Probes)
	}
	for _, id := range []string{"OBJ-LEAK", "OBJ-1", "OBJ-2", "OBJ-3", "OBJ-CLEAN"} {
		p := probeByID(t, r, id)
		if p.Status != StatusPass {
			t.Errorf("%s = %s (%s), want pass", id, p.Status, p.Detail)
		}
		if id != "OBJ-LEAK" && id != "OBJ-CLEAN" && p.Limits == "" {
			t.Errorf("%s states no limits", id)
		}
	}
	location, _ := probeByID(t, r, "OBJ-1").Evidence["location"].(string)
	if !strings.HasPrefix(location, "s3://"+srv.Bucket+"/deployment-a/tenant/"+ProbeTenantPrefix) {
		t.Errorf("OBJ-1 location = %q, want the probe tenant's prefix under the deployment root", location)
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Fatalf("doctor left %d objects in the store: %v", len(keys), keys)
	}
	var puts int
	for _, request := range srv.Requests() {
		if strings.HasPrefix(request, "PUT ") {
			puts++
			if !strings.HasPrefix(request, "PUT deployment-a/tenant/"+ProbeTenantPrefix) {
				t.Errorf("doctor wrote outside a probe tenant's prefix: %s", request)
			}
		}
	}
	if puts < 2 {
		t.Fatalf("doctor made %d writes, want the marker and the refused overwrite", puts)
	}
}

// Without --write-probe the lane only lists the reserved probe prefix; the
// write proofs report skip and nothing is written. With no object store
// configured every object probe skips and says why.
func TestDoctorObjectStoreLaneSkipsHonestly(t *testing.T) {
	r, code := runDoctorWithEnv(t, getenvNone, "--prove-isolation")
	if code != 0 {
		t.Fatalf("doctor exit = %d", code)
	}
	for _, id := range []string{"OBJ-LEAK", "OBJ-1", "OBJ-2", "OBJ-3"} {
		if p := probeByID(t, r, id); p.Status != StatusSkip || !strings.Contains(p.Detail, "no object store is configured") {
			t.Errorf("%s with no object store = %s (%q), want an explained skip", id, p.Status, p.Detail)
		}
	}
	srv := s3test.NewServer(t)
	r, code = runDoctorWithEnv(t, objectStoreEnv(t, srv), "--prove-isolation")
	if code != 0 {
		t.Fatalf("read-only doctor exit = %d", code)
	}
	if p := probeByID(t, r, "OBJ-LEAK"); p.Status != StatusPass {
		t.Errorf("OBJ-LEAK = %s (%s), want pass", p.Status, p.Detail)
	}
	for _, id := range []string{"OBJ-1", "OBJ-2", "OBJ-3"} {
		if p := probeByID(t, r, id); p.Status != StatusSkip || !strings.Contains(p.Detail, "--write-probe") {
			t.Errorf("%s without --write-probe = %s (%q), want a skip naming --write-probe", id, p.Status, p.Detail)
		}
	}
	for _, request := range srv.Requests() {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("read-only doctor sent %q to the object store", request)
		}
	}
}

// Anti-vacuity: an object left under the reserved probe prefix fails
// OBJ-LEAK, and a store that replaces an object despite the conditional write
// fails OBJ-3, because archives written to it could be overwritten.
func TestDoctorObjectStoreLaneFailsOnResidueAndOverwrites(t *testing.T) {
	srv := s3test.NewServer(t)
	srv.Seed("deployment-a/tenant/"+ProbeTenantPrefix+"-4abc-8def-0123456789ab/doctor/left-behind", []byte("x"))
	r, code := runDoctorWithEnv(t, objectStoreEnv(t, srv), "--prove-isolation")
	if p := probeByID(t, r, "OBJ-LEAK"); code != 1 || p.Status != StatusFail || !strings.Contains(p.Detail, "1 ") {
		t.Fatalf("leaked probe object: exit %d, OBJ-LEAK = %s (%s), want a failure counting it", code, p.Status, p.Detail)
	}

	overwriting := s3test.NewServer(t)
	overwriting.IgnoreConditionalWrites()
	r, code = runDoctorWithEnv(t, objectStoreEnv(t, overwriting), "--prove-isolation", "--write-probe")
	p := probeByID(t, r, "OBJ-3")
	if code != 1 || p.Status != StatusFail || !strings.Contains(p.Detail, "overwr") {
		t.Fatalf("store without conditional writes: exit %d, OBJ-3 = %s (%s), want a failure saying archives can be overwritten", code, p.Status, p.Detail)
	}
	if clean := probeByID(t, r, "OBJ-CLEAN"); clean.Status != StatusPass {
		t.Fatalf("OBJ-CLEAN after a failed proof = %s (%s), want cleanup to still run", clean.Status, clean.Detail)
	}
	if keys := overwriting.Keys(); len(keys) != 0 {
		t.Fatalf("doctor left %v after a failed proof", keys)
	}
}
