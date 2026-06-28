package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// emptyEnv is a getenv that resolves every variable to "" (no overrides), so the
// binary falls back to its built-in single-node defaults.
func emptyEnv(string) string { return "" }

// envFunc builds a getenv backed by a map, for exercising configuration.
func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestRun_VersionFlag encodes the acceptance criterion that the binary reports
// its version and exits cleanly (no error) for both --version and -version.
func TestRun_VersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, emptyEnv, &stdout, &stderr); err != nil {
			t.Fatalf("run(%q) returned error: %v", arg, err)
		}
		out := stdout.String()
		if !strings.Contains(out, "trstctl") {
			t.Errorf("run(%q) printed %q to stdout, want it to contain %q", arg, out, "trstctl")
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("run(%q) printed nothing to stdout", arg)
		}
	}
}

// TestRun_ServeExternalWithoutDSNFailsFast: the serve path fails fast when
// external Postgres is selected without a DSN — no silent fallback (R4.5). The
// bundled default now actually serves an embedded single-node Postgres, so its
// full serve path is exercised by internal/server's bundled test and the
// assembled-server tests in internal/projections, not here.
func TestRun_ServeExternalWithoutDSNFailsFast(t *testing.T) {
	env := envFunc(map[string]string{"TRSTCTL_POSTGRES_MODE": "external"}) // external, no DSN
	err := run(context.Background(), nil, env, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("serving with external Postgres and no DSN should fail fast")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "dsn") && !strings.Contains(low, "postgres") {
		t.Errorf("error %q should name the missing Postgres DSN", err)
	}
}

// TestRun_FIPSRequiredButInactiveFailsClosed is the served-path proof of the
// FIPS power-on self-test (PKIGOV-007 / EXC-CRYPTO-01): when --fips is set but the
// binary is not built with the FIPS module (the default `go test` build is not),
// the boot must FAIL CLOSED with a FIPS-mode error BEFORE the control plane
// serves — so a regulated deployment cannot start under an unvalidated crypto
// stack. The error returns ahead of server.Run, so the test does not boot Postgres.
//
// On a FIPS build (the `make fips-build` CI job) the module is active and there is
// nothing to fail closed on, so the assertion is skipped — the active path is
// covered by internal/crypto's FIPS suite under that build.
func TestRun_FIPSRequiredButInactiveFailsClosed(t *testing.T) {
	if crypto.FIPSEnabled() {
		t.Skip("FIPS module active in this build; the inactive fail-closed path is the non-FIPS build's job")
	}
	for _, src := range []struct {
		name string
		args []string
		env  func(string) string
	}{
		{"flag", []string{"--fips"}, emptyEnv},
		{"env", nil, envFunc(map[string]string{"TRSTCTL_FIPS": "1"})},
	} {
		t.Run(src.name, func(t *testing.T) {
			err := run(context.Background(), src.args, src.env, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("run(--fips) on a non-FIPS build returned nil; want a fail-closed error before serving")
			}
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "fips") || !strings.Contains(low, "self-test") {
				t.Errorf("error %q should name the FIPS self-test failure", err)
			}
		})
	}
}

// TestRun_NoFIPSRequiredDoesNotBlockOnPOST proves the POST's known-answer test
// passes on the default build (FIPS not required), so it does not spuriously
// abort boot. We exercise it via --check-config, which resolves config (and would
// surface a crypto-init panic) without booting the server.
func TestRun_NoFIPSRequiredDoesNotBlockOnPOST(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, emptyEnv, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config) returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "crypto.fips.module_active:") {
		t.Errorf("--check-config should report the FIPS module posture; got %q", stdout.String())
	}
}

func TestRun_CheckConfigPrintsBulkheadLimits(t *testing.T) {
	env := envFunc(map[string]string{
		"TRSTCTL_BULKHEAD_API_WORKERS":    "12",
		"TRSTCTL_BULKHEAD_API_QUEUE":      "300",
		"TRSTCTL_BULKHEAD_OUTBOX_WORKERS": "6",
		"TRSTCTL_BULKHEAD_OUTBOX_QUEUE":   "144",
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"bulkheads.api.workers: 12",
		"bulkheads.api.queue: 300",
		"bulkheads.outbox.workers: 6",
		"bulkheads.outbox.queue: 144",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("--check-config output missing %q:\n%s", want, out)
		}
	}
}

func TestConnectorTargetCLIUsesServedAPI(t *testing.T) {
	type seenReq struct {
		Method  string
		Path    string
		Auth    string
		Tenant  string
		Idem    string
		Payload map[string]any
	}
	var seen []seenReq
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := seenReq{
			Method: r.Method,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Tenant: r.Header.Get("X-Tenant-ID"),
			Idem:   r.Header.Get("Idempotency-Key"),
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&got.Payload)
		}
		seen = append(seen, got)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/connectors/targets":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"target-1","name":"edge/prod","connector":"nginx"}`)
		case "/api/v1/identities/identity-1/connector-target":
			_, _ = io.WriteString(w, `{"id":"identity-1","status":"requested"}`)
		case "/api/v1/connectors/targets/target-1/deploy":
			_, _ = io.WriteString(w, `{"id":"identity-1","status":"deployed"}`)
		default:
			t.Fatalf("unexpected CLI request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	env := envFunc(map[string]string{
		"TRSTCTL_URL":    ts.URL,
		"TRSTCTL_TOKEN":  "tok",
		"TRSTCTL_TENANT": "11111111-1111-1111-1111-111111111111",
	})

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"connector", "target", "create", "--name", "edge/prod", "--connector", "nginx", "--config-json", `{"credential_ref":"secret://connectors/nginx"}`}, env, &stdout, &stderr); err != nil {
		t.Fatalf("connector target create: %v", err)
	}
	if err := run(context.Background(), []string{"connector", "target", "bind", "--identity", "identity-1", "--target", "target-1"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("connector target bind: %v", err)
	}
	if err := run(context.Background(), []string{"connector", "target", "deploy", "--identity", "identity-1", "--target", "target-1", "--reason", "deploy from CLI"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("connector target deploy: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("requests = %+v, want create, bind, deploy", seen)
	}
	for _, got := range seen {
		if got.Auth != "Bearer tok" || got.Tenant != "11111111-1111-1111-1111-111111111111" || got.Idem == "" {
			t.Fatalf("bad auth/tenant/idempotency headers: %+v", got)
		}
	}
	if seen[0].Method != http.MethodPost || seen[0].Path != "/api/v1/connectors/targets" || seen[0].Payload["connector"] != "nginx" {
		t.Fatalf("bad create request: %+v", seen[0])
	}
	if seen[1].Path != "/api/v1/identities/identity-1/connector-target" || seen[1].Payload["target_id"] != "target-1" {
		t.Fatalf("bad bind request: %+v", seen[1])
	}
	if seen[2].Path != "/api/v1/connectors/targets/target-1/deploy" || seen[2].Payload["identity_id"] != "identity-1" || seen[2].Payload["reason"] != "deploy from CLI" {
		t.Fatalf("bad deploy request: %+v", seen[2])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestReadyCheckTargetsReadyzAndFailsClosedOnDependency503(t *testing.T) {
	if readyProbePath != "/readyz" {
		t.Fatalf("readyProbePath = %q, want /readyz", readyProbePath)
	}
	if healthProbePath != "/healthz" {
		t.Fatalf("healthProbePath = %q, want /healthz", healthProbePath)
	}
	var gotPaths []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPaths = append(gotPaths, r.URL.Path)
		status := http.StatusOK
		if r.URL.Path == readyProbePath {
			status = http.StatusServiceUnavailable
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(`{"status":"degraded","checks":{"db":"down"}}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
	if err := probeURL(client, "http://127.0.0.1:8443"+healthProbePath, "health check"); err != nil {
		t.Fatalf("liveness probe should stay green for shallow /healthz: %v", err)
	}
	err := probeURL(client, "http://127.0.0.1:8443"+readyProbePath, "readiness check")
	if err == nil {
		t.Fatal("readiness probe must fail closed on /readyz 503")
	}
	if strings.Join(gotPaths, ",") != "/healthz,/readyz" {
		t.Fatalf("probe paths = %q, want /healthz then /readyz", gotPaths)
	}
	if !strings.Contains(err.Error(), "readiness check") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("readiness failure should name the probe and status, got %v", err)
	}
}

// TestRun_UnknownFlagIsError ensures bad input fails loudly rather than booting.
func TestRun_UnknownFlagIsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--no-such-flag"}, emptyEnv, &stdout, &stderr); err == nil {
		t.Fatal("run with an unknown flag returned nil, want an error")
	}
}

// TestRun_HelpExitsCleanly ensures -h/--help is treated as a clean exit, not an
// error (flag.ErrHelp must not propagate as a failure).
func TestRun_HelpExitsCleanly(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, emptyEnv, &stdout, &stderr); err != nil {
			t.Errorf("run(%q) returned error %v, want clean exit", arg, err)
		}
	}
}

// TestRun_CheckConfigDefault encodes that --check-config resolves and prints the
// effective configuration and exits cleanly. With no environment the binary
// reports its self-contained single-node defaults (bundled Postgres, embedded
// NATS).
func TestRun_CheckConfigDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, emptyEnv, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"bundled", "embedded"} {
		if !strings.Contains(out, want) {
			t.Errorf("check-config output %q missing %q", out, want)
		}
	}
}

// TestRun_CheckConfigExternalTargets encodes the S7.4 acceptance that pointing
// at external Postgres/NATS is a supported, exercised configuration: the binary
// resolves the external targets from the environment and reports them, with the
// DSN password redacted.
func TestRun_CheckConfigExternalTargets(t *testing.T) {
	env := envFunc(map[string]string{
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://trstctl:s3cretpw@db.example.com:5432/trstctl?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://nats.example.com:4222",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config, external) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"external", "db.example.com", "nats.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("check-config output %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "s3cretpw") {
		t.Errorf("check-config output leaked the DSN password: %q", out)
	}
}

func TestRun_CheckConfigAgentChannel(t *testing.T) {
	env := envFunc(map[string]string{
		"TRSTCTL_AGENT_CHANNEL_ENABLED":            "true",
		"TRSTCTL_AGENT_CHANNEL_ADDR":               ":9443",
		"TRSTCTL_AGENT_CHANNEL_SERVER_NAME":        "agents.example.com",
		"TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE":       "/var/lib/trstctl/agent-ca.crt",
		"TRSTCTL_AGENT_CHANNEL_HEARTBEAT_INTERVAL": "45s",
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config, agent_channel) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"agent_channel.enabled: true",
		"agent_channel.addr: :9443",
		"agent_channel.server_name: agents.example.com",
		"agent_channel.ca_cert_file: /var/lib/trstctl/agent-ca.crt",
		"agent_channel.heartbeat_interval: 45s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check-config output %q missing %q", out, want)
		}
	}
}

// TestRun_InvalidConfigFailsFast encodes that an invalid configuration is
// rejected before the control plane boots — external Postgres with no DSN must
// be an error, not a silent fallback.
func TestRun_InvalidConfigFailsFast(t *testing.T) {
	env := envFunc(map[string]string{"TRSTCTL_POSTGRES_MODE": "external"}) // no DSN
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err == nil {
		t.Fatal("run with external Postgres and no DSN returned nil, want a configuration error")
	}
}

// TestRun_CheckConfigShowsTelemetryOff encodes the S7.5 default: --check-config
// reports telemetry as disabled when the operator has not opted in.
func TestRun_CheckConfigShowsTelemetryOff(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, emptyEnv, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config): %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "telemetry") {
		t.Errorf("check-config output %q should report telemetry status", out)
	}
	if !strings.Contains(out, "telemetry.enabled: false") {
		t.Errorf("check-config output %q should show telemetry disabled by default", out)
	}
}
