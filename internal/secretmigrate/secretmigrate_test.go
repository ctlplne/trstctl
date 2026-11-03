// SPDX-License-Identifier: BUSL-1.1

package secretmigrate

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/secretjson"
)

// Fabricated values only: none is a credential anywhere.
const (
	prodEnv = `# primary database host
# @tags: database, primary
# @owner: payments-team
DB_HOST=db.prod.internal
export DB_PORT=5432
DB_URL="postgres://app@${DB_HOST}:${DB_PORT}/orders"
# a key the export could not carry
# @exportable: false
SIGNING_KEY=
TLS_BUNDLE="-----BEGIN CERTIFICATE-----
TUlJQ2Zha2U=
-----END CERTIFICATE-----"
GREETING='literal ${NOT_A_REF} text'
SHELL_DEFAULT=${HOME:-/root}
`
	stagingYAML = `api:
  DB_HOST: db.staging.internal
  DB_URL: "postgres://app@${DB_HOST}/orders"
  CROSS: "${production:api/DB_HOST}"
  CHAIN_A: "${CHAIN_B}"
  CHAIN_B: "${CHAIN_C}"
  CHAIN_C: end-of-chain
  NOTES:
    $value: |
      line one
      line two
    $description: two-line note
    $tags: [docs]
  LEGACY_TOKEN:
    $exportable: false
    $description: issued by the old system
  PORTS: [80, 443]
`
	sharedJSON = `[
  {"key": "REGION", "value": "eu-west-1", "folder": "shared", "description": "deployment region", "owner": "platform"},
  {"key": "API_KEY", "value": null, "folder": "shared", "exportable": false},
  {"key": "bad key", "value": "x"}
]`
)

func seededBundle() *Bundle {
	return &Bundle{
		Project: "payments",
		Sources: []Source{
			{Environment: "production", Folder: "api", Format: FormatDotenv, Content: secretjson.StringBytes(prodEnv)},
			{Environment: "staging", Format: FormatYAML, Content: secretjson.StringBytes(stagingYAML)},
			{Environment: "production", Format: FormatJSON, Content: secretjson.StringBytes(sharedJSON)},
		},
		Permissions: []Permission{
			{Subject: "user:ana", Environment: "production", Access: "read"},
			{Subject: "user:ana", Environment: "staging", Access: "read"},
			{Subject: "user:ben", Environment: "production", Access: "write"},
			{Subject: "user:cy", Environment: "production", Folder: "api", Access: "read"},
			{Subject: "group:ops", Environment: "staging", Access: "admin"},
			{Subject: "user:dee", Environment: "production", Access: "read"},
			{Subject: "user:dee", Environment: "staging", Access: "write"},
			{Subject: "user:eve", Environment: "production", Access: "read"},
			{Subject: "user:fay", Environment: "production", Access: "write"},
			{Subject: "*", Environment: "production", Access: "read"},
		},
		Consumers: []Consumer{
			{Name: "orders-api", Subject: "spiffe://payments/orders-api", Environment: "production", Secrets: []string{"api/DB_URL", "shared/REGION"}},
			{Name: "ghost", Subject: "spiffe://payments/ghost", Environment: "staging", Secrets: []string{"api/MISSING"}},
		},
	}
}

func byName(t *testing.T, p *Parsed, name string) *Object {
	t.Helper()
	for _, o := range p.Objects {
		if o.Name == name {
			return o
		}
	}
	t.Fatalf("no object %s in %d objects", name, len(p.Objects))
	return nil
}

// A243 Done-when: a seeded multi-environment export with nested references,
// multiline values and metadata reads into native names, references and
// metadata; nothing the assessment returns holds a value; a credential the
// export could not carry is planned for reissue, never as migrated.
func TestASeededMultiEnvironmentExportIsReadAndAssessedWithoutValuesA243(t *testing.T) {
	b := seededBundle()
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()

	dbURL := byName(t, p, "payments/production/api/DB_URL")
	if string(dbURL.Value) != "postgres://app@${secret.payments/production/api/DB_HOST}:${secret.payments/production/api/DB_PORT}/orders" {
		t.Fatalf("references not translated: %q", dbURL.Value)
	}
	host := byName(t, p, "payments/production/api/DB_HOST")
	if host.Description != "primary database host" || !reflect.DeepEqual(host.Tags, []string{"database", "primary"}) || host.Owner != "payments-team" {
		t.Fatalf("dotenv metadata: %+v", host)
	}
	if tls := byName(t, p, "payments/production/api/TLS_BUNDLE"); !tls.Multiline || !bytes.Contains(tls.Value, []byte("\nTUlJQ2Zha2U=\n")) {
		t.Fatalf("multiline dotenv value: %q", tls.Value)
	}
	if g := byName(t, p, "payments/production/api/GREETING"); string(g.Value) != "literal ${secret.payments/production/api/NOT_A_REF} text" {
		// A single-quoted value is literal text, but the native store reads
		// ${secret.} anywhere; the reference is translated and, since nothing
		// by that name exists, the assessment blocks it below.
		t.Fatalf("single-quoted value: %q", g.Value)
	}
	if s := byName(t, p, "payments/production/api/SHELL_DEFAULT"); string(s.Value) != "${HOME:-/root}" {
		t.Fatalf("a shell default became a reference: %q", s.Value)
	}
	notes := byName(t, p, "payments/staging/api/NOTES")
	if string(notes.Value) != "line one\nline two\n" || notes.Description != "two-line note" || !notes.Multiline {
		t.Fatalf("YAML record: %+v %q", notes, notes.Value)
	}
	if cross := byName(t, p, "payments/staging/api/CROSS"); string(cross.Value) != "${secret.payments/production/api/DB_HOST}" {
		t.Fatalf("cross-environment reference: %q", cross.Value)
	}
	if region := byName(t, p, "payments/production/shared/REGION"); region.Owner != "platform" || string(region.Value) != "eu-west-1" {
		t.Fatalf("JSON record: %+v", region)
	}
	for _, name := range []string{"payments/production/api/SIGNING_KEY", "payments/staging/api/LEGACY_TOKEN", "payments/production/shared/API_KEY"} {
		if o := byName(t, p, name); o.Exportable || o.Value != nil {
			t.Fatalf("%s is not marked non-exportable", name)
		}
	}
	if len(p.Unsupported) != 2 {
		t.Fatalf("unsupported = %+v (want the list value and the bad key)", p.Unsupported)
	}

	a := Assess(p, b, Destination{
		Environments: map[string]EnvironmentState{"production": {Restricted: true}, "staging": {Restricted: true}},
		Versions:     map[string]int{"payments/production/api/DB_HOST": 3},
	}, nil)
	plan := map[string]ObjectPlan{}
	for _, o := range a.Objects {
		plan[o.Name] = o
	}
	switch {
	case plan["payments/production/api/DB_URL"].Action != ActionImport:
		t.Fatalf("DB_URL: %+v", plan["payments/production/api/DB_URL"])
	case plan["payments/production/api/DB_HOST"].ExistingVersion != 3:
		t.Fatal("an existing secret's version is not in the plan")
	case plan["payments/staging/api/CHAIN_A"].Action != ActionImport || plan["payments/staging/api/CHAIN_B"].Action != ActionImport:
		t.Fatal("a resolvable chain of references is blocked")
	case plan["payments/production/api/SIGNING_KEY"].Action != ActionReissue:
		t.Fatal("a non-exportable credential is not planned for reissue")
	case plan["payments/production/api/GREETING"].Action != ActionBlocked ||
		strings.Contains(plan["payments/production/api/GREETING"].Reason, "NOT_A_REF"):
		t.Fatalf("an unresolved reference: %+v", plan["payments/production/api/GREETING"])
	}
	if a.Counts.Reissue != 3 || a.Counts.Unsupported != 2 {
		t.Fatalf("counts = %+v", a.Counts)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"db.prod.internal", "5432", "TUlJQ2Zha2U=", "line one", "eu-west-1", "end-of-chain", "db.staging.internal", "postgres://app@"} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("the assessment carries the value %q", value)
		}
	}
	if !strings.Contains(string(raw), "two-line note") || !strings.Contains(string(raw), "payments-team") {
		t.Fatal("the assessment lost the metadata")
	}
	if a.Consumers[0].Problem != "" || len(a.Consumers[0].Secrets) != 2 || a.Consumers[1].Problem == "" {
		t.Fatalf("consumers = %+v", a.Consumers)
	}

	// The digest covers the values: a changed value changes it.
	before := DigestInput(a, p)
	byName(t, p, "payments/staging/api/CHAIN_C").Value[0] ^= 1
	if bytes.Equal(before, DigestInput(a, p)) {
		t.Fatal("the plan digest does not cover the values")
	}
}

// A243 Done-when: permissions are translated or held for review, never
// broadened.
func TestPermissionsAreTranslatedOrHeldNeverBroadenedA243(t *testing.T) {
	b := seededBundle()
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	a := Assess(p, b, Destination{
		Environments: map[string]EnvironmentState{"production": {Restricted: true}, "staging": {Restricted: true}},
		Members: map[string]Member{
			"user:eve": {Role: RoleDeveloper},                                    // all environments, more than read
			"user:fay": {Role: RoleViewer, Environments: []string{"production"}}, // less than write
		},
	}, nil)
	got := map[string]PermissionPlan{}
	for _, perm := range a.Permissions {
		got[perm.Subject+"@"+perm.Environment+"/"+perm.Folder] = perm
	}
	want := map[string]string{
		"user:ana@production/": PermissionTranslated, "user:ana@staging/": PermissionTranslated,
		"user:ben@production/": PermissionTranslated, "user:cy@production/api": PermissionHeld,
		"group:ops@staging/": PermissionHeld, "user:dee@production/": PermissionHeld, "user:dee@staging/": PermissionHeld,
		"user:eve@production/": PermissionCovered, "user:fay@production/": PermissionHeld, "*@production/": PermissionHeld,
	}
	for key, status := range want {
		if got[key].Status != status {
			t.Errorf("%s: %+v, want %s", key, got[key], status)
		}
	}
	if ana := got["user:ana@production/"]; ana.Role != RoleViewer || !reflect.DeepEqual(ana.Environments, []string{"production", "staging"}) {
		t.Fatalf("read in two environments: %+v", ana)
	}
	if ben := got["user:ben@production/"]; ben.Role != RoleDeveloper || !reflect.DeepEqual(ben.Environments, []string{"production"}) {
		t.Fatalf("write: %+v", ben)
	}
	for _, perm := range a.Permissions {
		if perm.Status != PermissionTranslated && (perm.Role != "" || len(perm.Environments) > 0) {
			t.Fatalf("a held or covered grant carries something to apply: %+v", perm)
		}
	}

	// An environment the export restricted, imported into an open one, is
	// blocked until the operator accepts it.
	open := Assess(p, b, Destination{Environments: map[string]EnvironmentState{"production": {}, "staging": {Restricted: true}}}, nil)
	for _, o := range open.Objects {
		if o.Environment == "production" && o.Action == ActionImport {
			t.Fatalf("%s imports into an open environment the export restricted", o.Name)
		}
	}
	accepted := Assess(p, b, Destination{Environments: map[string]EnvironmentState{"production": {}, "staging": {Restricted: true}}}, []string{"production"})
	if accepted.Environments[0].Name != "production" || !accepted.Environments[0].OpenAccepted || accepted.Counts.Import == open.Counts.Import {
		t.Fatalf("an accepted open environment: %+v", accepted.Environments)
	}
	missing := Assess(p, b, Destination{Environments: map[string]EnvironmentState{"production": {Restricted: true}}}, nil)
	for _, o := range missing.Objects {
		if o.Environment == "staging" && o.Action == ActionImport {
			t.Fatal("an object imports into an environment the project does not have")
		}
	}
}

// A cycle of references is blocked for every object on it, naming the cycle.
func TestAReferenceCycleIsBlockedA243(t *testing.T) {
	b := &Bundle{Project: "payments", Sources: []Source{{Environment: "dev", Format: FormatDotenv,
		Content: secretjson.StringBytes("A=${B}\nB=${C}\nC=${A}\nD=plain\n")}}}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	a := Assess(p, b, Destination{Environments: map[string]EnvironmentState{"dev": {}}}, nil)
	for _, o := range a.Objects {
		blocked := o.Action == ActionBlocked && strings.Contains(o.Reason, "cycle")
		if (o.Key == "D") == blocked {
			t.Fatalf("%s: %+v", o.Key, o)
		}
	}
}

// A malformed source is refused whole rather than half-read.
func TestMalformedSourcesAreRefusedA243(t *testing.T) {
	for name, src := range map[string]Source{
		"format":          {Environment: "dev", Format: "ini", Content: secretjson.StringBytes("A=1")},
		"environment":     {Environment: "Dev Env", Format: FormatDotenv, Content: secretjson.StringBytes("A=1")},
		"folder":          {Environment: "dev", Folder: "../etc", Format: FormatDotenv, Content: secretjson.StringBytes("A=1")},
		"no equals":       {Environment: "dev", Format: FormatDotenv, Content: secretjson.StringBytes("A 1")},
		"open quote":      {Environment: "dev", Format: FormatDotenv, Content: secretjson.StringBytes("A=\"never closed\nB=2")},
		"after quote":     {Environment: "dev", Format: FormatDotenv, Content: secretjson.StringBytes("A=\"x\" y")},
		"json trailing":   {Environment: "dev", Format: FormatJSON, Content: secretjson.StringBytes(`{"A":"1"} {}`)},
		"json scalar":     {Environment: "dev", Format: FormatJSON, Content: secretjson.StringBytes(`"A"`)},
		"yaml alias":      {Environment: "dev", Format: FormatYAML, Content: secretjson.StringBytes("a: &x v\nb: *x\n")},
		"yaml two docs":   {Environment: "dev", Format: FormatYAML, Content: secretjson.StringBytes("a: 1\n---\nb: 2\n")},
		"yaml not a map":  {Environment: "dev", Format: FormatYAML, Content: secretjson.StringBytes("just text\n")},
		"dotenv bad name": {Environment: "dev", Format: FormatDotenv, Content: secretjson.StringBytes("=1")},
	} {
		if p, err := Parse(&Bundle{Project: "payments", Sources: []Source{src}}); err == nil {
			p.Wipe()
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse(&Bundle{Project: "Payments", Sources: []Source{{Environment: "dev", Format: FormatDotenv}}}); err == nil {
		t.Error("a project that is not a slug parsed")
	}
}
