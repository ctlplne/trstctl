// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/secretscan"
)

// soarPack is clients/soar/pack.json and its playbooks (N7).
type soarPack struct {
	Pack string `json:"pack"`
	API  struct {
		Scopes []string `json:"scopes"`
	} `json:"api"`
	Playbooks []string `json:"playbooks"`
}

type soarPlaybook struct {
	ID     string `json:"id"`
	Inputs map[string]struct {
		Required bool `json:"required"`
	} `json:"inputs"`
	Steps []soarStep `json:"steps"`
}

type soarStep struct {
	Name           string            `json:"name"`
	OperationID    string            `json:"operation_id"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	IdempotencyKey string            `json:"idempotency_key"`
	Body           json.RawMessage   `json:"body"`
	Expect         []int             `json:"expect"`
	Assert         map[string]any    `json:"assert"`
	Outputs        map[string]string `json:"outputs"`
	Until          *struct {
		Assert      map[string]any `json:"assert"`
		MaxSeconds  int            `json:"max_seconds"`
		EverySecond int            `json:"every_seconds"`
	} `json:"until"`
}

var soarTemplate = regexp.MustCompile(`\{\{([A-Za-z0-9_.]+)\}\}`)

func loadSOARPack(t *testing.T) (soarPack, []soarPlaybook) {
	t.Helper()
	root := filepath.Join("..", "..", "clients", "soar")
	raw, err := os.ReadFile(filepath.Join(root, "pack.json")) // #nosec G304 -- the repository's own SOAR pack (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var pack soarPack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	var playbooks []soarPlaybook
	for _, rel := range pack.Playbooks {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- a playbook the repository's own pack names (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		var pb soarPlaybook
		if err := json.Unmarshal(raw, &pb); err != nil || pb.ID == "" || len(pb.Steps) == 0 {
			t.Fatalf("%s is not a playbook: %v", rel, err)
		}
		playbooks = append(playbooks, pb)
	}
	return pack, playbooks
}

// fill replaces {{name}} with a value from vars; a reference without a value
// is an error, so a playbook never sends a literal template.
func soarFill(s string, vars map[string]string) (string, error) {
	var missing []string
	out := soarTemplate.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-2]
		v, ok := vars[name]
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unbound template variables %v", missing)
	}
	return out, nil
}

func soarPointer(doc any, pointer string) (any, bool) {
	cur := doc
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func soarAssert(doc any, want map[string]any) error {
	for pointer, value := range want {
		got, ok := soarPointer(doc, pointer)
		if !ok || fmt.Sprint(got) != fmt.Sprint(value) {
			return fmt.Errorf("%s = %v, want %v", pointer, got, value)
		}
	}
	return nil
}

// soarRefusal is a playbook stopping where a SOAR would: a step's response
// status or assert said no (N7-L2).
type soarRefusal struct {
	Step   string
	Reason string
}

func (r *soarRefusal) Error() string { return r.Step + ": " + r.Reason }

// runSOARPlaybook runs a playbook the way a SOAR does: HTTP only, with the
// pack's bearer token and tenant header. between runs while a step waits.
func runSOARPlaybook(t *testing.T, h *servedHarness, token string, pb soarPlaybook, inputs map[string]string, between func()) map[string]string {
	t.Helper()
	vars, refusal := runSOARPlaybookUntilRefused(t, h, token, pb, inputs, between)
	if refusal != nil {
		t.Fatalf("%s/%v", pb.ID, refusal)
	}
	return vars
}

// runSOARPlaybookUntilRefused runs a playbook and returns where it stopped
// when a step refuses, as a SOAR stops the playbook there (N7-L2): no later
// step runs.
func runSOARPlaybookUntilRefused(t *testing.T, h *servedHarness, token string, pb soarPlaybook, inputs map[string]string, between func()) (map[string]string, *soarRefusal) {
	t.Helper()
	vars := map[string]string{}
	for k, v := range inputs {
		vars[k] = v
	}
	for name, in := range pb.Inputs {
		if _, ok := vars[name]; in.Required && !ok {
			t.Fatalf("%s: input %s is required", pb.ID, name)
		}
	}
	for _, step := range pb.Steps {
		path, err := soarFill(step.Path, vars)
		if err != nil {
			t.Fatalf("%s/%s path: %v", pb.ID, step.Name, err)
		}
		var body io.Reader
		if len(step.Body) > 0 {
			filled, err := soarFill(string(step.Body), vars)
			if err != nil {
				t.Fatalf("%s/%s body: %v", pb.ID, step.Name, err)
			}
			body = strings.NewReader(filled)
		}
		send := func() (int, any) {
			t.Helper()
			var reader io.Reader
			if body != nil {
				raw, _ := io.ReadAll(body)
				body = bytes.NewReader(raw)
				reader = bytes.NewReader(raw)
			}
			req, err := http.NewRequest(step.Method, h.ts.URL+path, reader)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", h.tenant)
			if reader != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			if step.IdempotencyKey != "" {
				key, err := soarFill(step.IdempotencyKey, vars)
				if err != nil {
					t.Fatalf("%s/%s key: %v", pb.ID, step.Name, err)
				}
				req.Header.Set("Idempotency-Key", key)
			}
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			raw, _ := io.ReadAll(resp.Body)
			var doc any
			_ = json.Unmarshal(raw, &doc)
			return resp.StatusCode, doc
		}
		status, doc := send()
		if !slices.Contains(step.Expect, status) {
			return vars, &soarRefusal{Step: step.Name, Reason: fmt.Sprintf("HTTP %d, want %v: %v", status, step.Expect, doc)}
		}
		if err := soarAssert(doc, step.Assert); err != nil {
			return vars, &soarRefusal{Step: step.Name, Reason: err.Error()}
		}
		if step.Until != nil {
			deadline := time.Now().Add(time.Duration(step.Until.MaxSeconds) * time.Second)
			for soarAssert(doc, step.Until.Assert) != nil {
				if time.Now().After(deadline) {
					return vars, &soarRefusal{Step: step.Name, Reason: fmt.Sprintf("never reached %v: %v", step.Until.Assert, doc)}
				}
				between()
				status, doc = send()
				if !slices.Contains(step.Expect, status) {
					return vars, &soarRefusal{Step: step.Name, Reason: fmt.Sprintf("HTTP %d while waiting", status)}
				}
			}
		}
		for name, pointer := range step.Outputs {
			if v, ok := soarPointer(doc, pointer); ok {
				vars["steps."+step.Name+"."+name] = fmt.Sprint(v)
			}
		}
	}
	return vars, nil
}

type soarFindingScanner struct{}

func (soarFindingScanner) Scan(_ context.Context, path string) (secretscan.Report, error) {
	return secretscan.Report{Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
		Findings: []secretscan.Finding{{Scanner: "gitleaks", RuleID: "generic-api-key", File: filepath.Base(path), Line: 1,
			Fingerprint: "n7-soar-finding", CredentialRef: "generic-api-key@" + filepath.Base(path)}}}, nil
}

// N7: the response pack in clients/soar is a set of playbooks a SOAR runs
// against trstctl's API. Every step names a served operation by its ID,
// method and path, every operation's permission is among the pack's scopes,
// every mutation carries an Idempotency-Key, and every template variable is
// an input or an earlier step's output. Each playbook then runs against the
// served API over HTTP alone, with a token holding exactly the pack's scopes,
// and reaches its end state; a second run converges instead of acting twice.
func TestServedSOARPlaybookPackN7(t *testing.T) {
	pack, playbooks := loadSOARPack(t)
	h, owner, body := servedPublicBrokerRevocationFixture(t, withSecretsEnabled(t, nil), func(d *Deps) { d.SecretScanner = soarFindingScanner{} })

	// Static conformance against the served document.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/openapi.json", owner, nil)
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Permission  string `json:"x-trstctl-permission"`
		} `json:"paths"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &doc) != nil {
		t.Fatalf("openapi: HTTP %d", status)
	}
	for _, pb := range playbooks {
		bound := map[string]bool{}
		for name := range pb.Inputs {
			bound[name] = true
		}
		for _, step := range pb.Steps {
			templatePath := soarTemplate.ReplaceAllStringFunc(step.Path, func(m string) string { return "{x}" })
			var found bool
			for path, ops := range doc.Paths {
				op, ok := ops[strings.ToLower(step.Method)]
				if !ok || op.OperationID != step.OperationID {
					continue
				}
				if regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "{x}") != templatePath {
					t.Fatalf("%s/%s: %s is served at %s, not %s", pb.ID, step.Name, step.OperationID, path, step.Path)
				}
				if !slices.Contains(pack.API.Scopes, op.Permission) {
					t.Fatalf("%s/%s needs %s, which the pack's scopes %v do not hold", pb.ID, step.Name, op.Permission, pack.API.Scopes)
				}
				found = true
			}
			if !found {
				t.Fatalf("%s/%s: no served %s operation %s", pb.ID, step.Name, step.Method, step.OperationID)
			}
			if step.Method != http.MethodGet && step.IdempotencyKey == "" {
				t.Fatalf("%s/%s mutates without an Idempotency-Key", pb.ID, step.Name)
			}
			for _, m := range soarTemplate.FindAllStringSubmatch(step.Path+string(step.Body)+step.IdempotencyKey, -1) {
				if !bound[m[1]] {
					t.Fatalf("%s/%s uses {{%s}}, which no input or earlier output binds", pb.ID, step.Name, m[1])
				}
			}
			for name := range step.Outputs {
				bound["steps."+step.Name+"."+name] = true
			}
		}
	}

	// A token holding exactly the pack's scopes, as the SOAR's connection does.
	soar := seedScopedToken(t, h.store, h.tenant, pack.API.Scopes...)
	byID := map[string]soarPlaybook{}
	for _, pb := range playbooks {
		byID[pb.ID] = pb
	}
	drain := func() {
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	// revoke-compromised-certificate
	issued := servedBrokerIssue(t, h, owner, "n7-issue", body, http.StatusCreated)
	runSOARPlaybook(t, h, soar, byID["revoke-compromised-certificate"], map[string]string{"certificate_id": issued.CertificateID}, drain)
	runSOARPlaybook(t, h, soar, byID["revoke-compromised-certificate"], map[string]string{"certificate_id": issued.CertificateID}, drain)

	// rotate-leaked-secret: a stored secret and the finding that saw it leak.
	writer := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read")
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", writer, "n7-seed-secret", map[string]any{"name": "payments-db", "value": "first-value"}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("seed secret: HTTP %d %s", status, raw)
	}
	export := filepath.Join(t.TempDir(), "build.log")
	if err := os.WriteFile(export, []byte("export DB=first-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/cicd_log/ingest", writer, "n7-ingest",
		map[string]any{"source": "payments-ci", "artifact_path": export})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &receipt) != nil {
		t.Fatalf("ingest: HTTP %d %s", status, raw)
	}
	var findingID string
	for deadline := time.Now().Add(10 * time.Second); findingID == ""; {
		h.srv.dispatchOnce(context.Background())
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT id::text FROM discovery_findings WHERE tenant_id = $1 AND run_id = $2`, h.tenant, receipt.RunID).Scan(&findingID)
		if time.Now().After(deadline) {
			t.Fatal("the leaked-secret finding was not recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	vars := runSOARPlaybook(t, h, soar, byID["rotate-leaked-secret"], map[string]string{"secret_name": "payments-db", "new_value": "second-value",
		"finding_id": findingID, "ticket": "INC-4711"}, drain)
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, writer, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"triage_status":"remediated"`) || !strings.Contains(string(raw), "secret:payments-db@"+vars["steps.rotate.version"]) {
		t.Fatalf("finding after the playbook: HTTP %d %s", status, raw)
	}
	if strings.Contains(string(raw), "second-value") || h.logContains(t, "second-value") {
		t.Fatal("the rotated value reached a finding or the event log")
	}

	// retire-triggered-honeytoken refuses an untriggered bait, then retires a triggered one.
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", writer, "n7-bait", map[string]any{"name": "n7-bait", "placement": "wiki/ops"})
	var bait struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &bait) != nil {
		t.Fatalf("plant bait: HTTP %d %s", status, raw)
	}
	// N7-L2: before anyone has used it, the playbook refuses at its read
	// step, so it never revokes the bait: an untriggered bait keeps waiting.
	baitState := func() string {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/"+bait.ID, soar, nil)
		var read struct {
			State string `json:"state"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &read) != nil {
			t.Fatalf("read bait: HTTP %d %s", status, raw)
		}
		return read.State
	}
	_, refusal := runSOARPlaybookUntilRefused(t, h, soar, byID["retire-triggered-honeytoken"], map[string]string{"honeytoken_id": bait.ID}, drain)
	if refusal == nil || refusal.Step != "read" || !strings.Contains(refusal.Reason, "/state") {
		t.Fatalf("retiring an untriggered bait = %v, want the playbook to refuse at its read step", refusal)
	}
	if state := baitState(); state != "active" {
		t.Fatalf("after the refused playbook the untriggered bait reads %q, want active", state)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/access/roles", bait.Token, nil); status != http.StatusUnauthorized {
		t.Fatalf("bait use: HTTP %d", status)
	}
	runSOARPlaybook(t, h, soar, byID["retire-triggered-honeytoken"], map[string]string{"honeytoken_id": bait.ID}, drain)
	if state := baitState(); state != "revoked" {
		t.Fatalf("after the playbook a triggered bait reads %q, want revoked", state)
	}
	t.Logf("N7_SOAR_PACK_OK pack=%s playbooks=%d scopes=%v", pack.Pack, len(playbooks), pack.API.Scopes)
}
