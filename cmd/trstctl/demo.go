// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/server"
)

// Single-box demo mode: the control plane starts a colocated host agent (A5).
//
// Evaluating this product needs two installs — a control plane and an agent —
// and until you have both, nothing the product is FOR can be demonstrated. No
// deploy executes, no endpoint verifies, no renewal lands on a host. The whole
// wedge is the agent doing work in the estate, so a single-box evaluation that
// omits the agent evaluates the part that does not matter.
//
// This is also the cheapest defense against the defect this program keeps
// finding. Six times now a capability has been complete, tested and unreachable
// from the running binary, and every one of them would have been obvious the
// first time somebody drove it end to end on one machine. `--demo` makes that
// one command.
//
// The agent is EXEC'd, never linked. cmd/trstctl-agent must not link the
// control plane — docs/agent_binary_import_boundary_test.go pins it — and
// importing the agent here to save a process would put the two on the same
// side of a boundary the product's whole architecture rests on. Two binaries
// talking over the real channel is also what a real deployment does, so the
// demo exercises the actual path rather than a convenient shortcut.

// demoAgentBinary is the sibling executable name looked up next to this one.
const demoAgentBinary = "trstctl-agent"

// demoAgentName is the colocated agent's identity. Fixed so a restart re-enrolls
// as the same agent rather than accumulating one record per demo run.
const demoAgentName = "demo-host-agent"

// ApplyDemoDefaults turns on what a single-box demo needs, and reports what it
// changed so the operator is never guessing which settings are theirs.
//
// The agent channel is OFF by default and the claimable-job allowlist is EMPTY
// by default — both correct, both fail-closed, and both fatal to a demo: with
// the channel off the agent has nothing to dial, and with no claimable kinds the
// job ledger is served but hands nothing out, so the agent enrolls successfully
// and then sits there doing nothing. That is the most misleading possible demo,
// because it looks like it is working.
//
// These are forced ONLY under --demo, and every change is logged. A flag that
// silently rewrites an operator's configuration would be worse than one that
// refuses.
func ApplyDemoDefaults(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var changed []string
	if !cfg.AgentChannel.Enabled {
		cfg.AgentChannel.Enabled = true
		changed = append(changed, "agent_channel.enabled=true (the colocated agent has nothing to dial otherwise)")
	}
	if len(cfg.AgentChannel.ClaimableJobKinds) == 0 {
		// A conservative set: the read-only and host-local kinds a one-box demo
		// can actually complete. Deliberately NOT connector.deploy — a demo
		// should not mutate an appliance nobody meant to point it at.
		cfg.AgentChannel.ClaimableJobKinds = []string{"discovery.run", "endpoint.verify", "connector.test"}
		changed = append(changed, "agent_channel.claimable_job_kinds=[discovery.run endpoint.verify connector.test] "+
			"(an empty allowlist serves the ledger and hands out nothing, so the agent would enroll and idle)")
	}
	return changed
}

// demoDialAddr turns a listen address into one the colocated agent can dial.
func demoDialAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":9443" // the shipped default the fleet manifests point agents at
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

// runDemoAgent supervises a colocated agent for the lifetime of ctx.
//
// It waits for the control plane to answer, mints a host-role bootstrap token
// through the SERVED API rather than reaching into the store, writes it to a
// 0600 file, and execs the sibling agent binary.
//
// Every failure here is fatal to the process, and that is deliberate. `--demo`
// is an explicit request for a colocated agent; a run that serves the control
// plane and silently omits the agent looks like it worked, and "looks like it
// worked" is the exact failure mode this flag exists to prevent. Refusing
// loudly, naming what was missing, is the honest outcome.
func runDemoAgent(ctx context.Context, cfg *config.Config, apiToken string, stderr io.Writer) error {
	binary, err := demoAgentPath()
	if err != nil {
		return err
	}
	base, err := demoBaseURL(cfg)
	if err != nil {
		return err
	}
	if err := waitForControlPlane(ctx, base, stderr); err != nil {
		return err
	}
	token, err := mintDemoEnrollmentToken(ctx, base, apiToken)
	if err != nil {
		return fmt.Errorf("demo: mint an agent enrollment token: %w", err)
	}
	// 0600, and in a directory the OS will clean up. The agent refuses an
	// inline token because process arguments expose bearer credentials to
	// anything that can read /proc; the demo respects that rather than
	// special-casing itself.
	dir, err := os.MkdirTemp("", "trstctl-demo-")
	if err != nil {
		return fmt.Errorf("demo: create token directory: %w", err)
	}
	tokenPath := filepath.Join(dir, "bootstrap.token")
	if err := os.WriteFile(tokenPath, token, 0o600); err != nil {
		return fmt.Errorf("demo: write bootstrap token: %w", err)
	}

	args := []string{
		"--enroll-url", base,
		"--server", demoDialAddr(cfg.AgentChannel.Addr),
		"--name", demoAgentName,
		"--bootstrap-token-file", tokenPath,
	}
	// The agent pins the control plane's agent CA. Loopback SANs are always
	// added to that certificate, so a colocated agent can verify a localhost
	// connection — but it still needs the bundle to verify against.
	if bundle := strings.TrimSpace(cfg.AgentChannel.CACertFile); bundle != "" {
		args = append(args, "--ca-bundle", bundle)
	}
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- binary resolved beside this executable, args are our own config (CWE-78)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("demo: agent stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("demo: agent stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("demo: start %s: %w", binary, err)
	}
	_, _ = fmt.Fprintf(stderr, "demo: colocated host agent started (pid %d, %s)\n", cmd.Process.Pid, binary)

	// The agent's output is prefixed and forwarded rather than swallowed. On one
	// box the agent's refusals ARE the demo's diagnostics, and a demo that hid
	// them would reproduce the silence this flag exists to break.
	go forwardPrefixed(stdoutPipe, stderr, "agent")
	go forwardPrefixed(stderrPipe, stderr, "agent")

	go func() {
		<-ctx.Done()
		// Best-effort cleanup of the token file; CommandContext kills the agent.
		_ = os.RemoveAll(dir)
	}()
	return nil
}

// demoAPIToken mints the credential the demo uses to ask for an enrollment token.
//
// Through server.RunTokenCreate — the same path `trstctl token create` uses, and
// the same path the API authenticates against. Minting rather than requiring one
// is what makes --demo a single command; a demo that first told you to run two
// other commands would not be the thing A5 asked for.
//
// TRSTCTL_DEMO_API_TOKEN overrides it, so an evaluator who already has a token
// (or is pointing the demo at an existing tenant) is not forced to mint another.
func demoAPIToken(ctx context.Context, cfg *config.Config, getenv func(string) string) (string, error) {
	if existing := strings.TrimSpace(getenv("TRSTCTL_DEMO_API_TOKEN")); existing != "" {
		return existing, nil
	}
	raw, err := server.RunTokenCreate(ctx, cfg, server.TokenCreateOptions{
		TenantID:   demoTenantID,
		TenantName: "demo",
		Subject:    "demo-bootstrap",
	})
	if err != nil {
		return "", fmt.Errorf("mint a demo API token: %w", err)
	}
	// Copied before the wipe: the returned buffer is zeroed, and the demo needs
	// the value for the life of the process rather than the life of the call.
	token := string(raw)
	secret.Wipe(raw)
	return token, nil
}

// demoTenantID is the fixed tenant a demo runs in, so a restart reuses the same
// tenant instead of stranding the previous run's data behind a new UUID.
const demoTenantID = "00000000-0000-4000-8000-00000000d3m0"

// demoAgentPath resolves the sibling agent binary.
func demoAgentPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("demo: locate this executable: %w", err)
	}
	candidate := filepath.Join(filepath.Dir(self), demoAgentBinary)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	// Fall back to PATH before giving up, so `go run` and a dev shell both work.
	if found, err := exec.LookPath(demoAgentBinary); err == nil {
		return found, nil
	}
	return "", fmt.Errorf(
		"demo: no %s binary beside %s or on PATH. --demo starts a colocated host agent and "+
			"cannot without one; build it with `make build` (which writes both binaries to ./bin) "+
			"and run the server from there", demoAgentBinary, filepath.Dir(self))
}

// demoBaseURL is the local address the agent dials.
func demoBaseURL(cfg *config.Config) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.Server.Addr) == "" {
		return "", errors.New("demo: no server address is configured for the agent to dial")
	}
	addr := cfg.Server.Addr
	// A bare ":8080" is a listen address, not a dial address.
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	scheme := "https"
	if cfg.Server.TLS.Mode == "off" || cfg.Server.TLS.Mode == "" {
		scheme = "http"
	}
	return scheme + "://" + addr, nil
}

// waitForControlPlane blocks until /healthz answers or ctx ends.
func waitForControlPlane(ctx context.Context, base string, stderr io.Writer) error {
	// Dials this process's own listener. InsecureLoopbackClient pins the dialer
	// to loopback so a misconfigured address cannot turn a health probe into an
	// outbound request, and tolerates the self-signed cert a demo serves.
	client := netsec.InsecureLoopbackClient(2 * time.Second)
	deadline := time.Now().Add(60 * time.Second)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("demo: control plane at %s did not become healthy within 60s, so the "+
				"colocated agent was not started", base)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		_ = stderr
	}
}

// mintDemoEnrollmentToken asks the SERVED API for a host-role bootstrap token.
//
// Through the API on purpose. Reaching into the store would let the demo work
// while the served enrollment path was broken, which is precisely the class of
// bug a single-box demo exists to surface.
func mintDemoEnrollmentToken(ctx context.Context, base, apiToken string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{"roles": []string{"host"}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/enrollment-tokens",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Idempotency-Key", "demo-agent-enrollment")
	resp, err := netsec.InsecureLoopbackClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enrollment-token request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("decode enrollment token: %w", err)
	}
	if strings.TrimSpace(out.Token) == "" {
		return nil, errors.New("enrollment-token response carried no token")
	}
	return []byte(out.Token), nil
}

// forwardPrefixed copies the agent's output with a prefix so one terminal shows
// which side said what.
func forwardPrefixed(src io.Reader, dst io.Writer, prefix string) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		_, _ = fmt.Fprintf(dst, "[%s] %s\n", prefix, scanner.Text())
	}
}
