// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretscli"
)

// `trstctl-cli access agent` (A257): start an agent or CI job with
// gateway-only access to the accounts its delegated task allows. With the
// caller's token (in CI, an access bundle run's token that acts as the agent)
// it requests a reviewed session for each named account, waits for the
// approvals, opens each session through its gateway and serves each session's
// tunnel on a loopback address from this process. The command runs with
// instructions for reaching the accounts and no credential: the caller's token
// and every TRSTCTL_*TOKEN* variable are removed from its environment, the
// session tickets stay in this process, and the gateway signs in for it. When
// the command exits, its sessions are revoked.

// agentAccount is one --account TYPE/ID:ROLE.
type agentAccount struct {
	TargetType, TargetID, Role string
}

func parseAgentAccount(spec string) (agentAccount, error) {
	kind, rest, ok := strings.Cut(strings.TrimSpace(spec), "/")
	id, role, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || kind == "" || id == "" || role == "" || strings.ContainsAny(id+role, "/: ") {
		return agentAccount{}, fmt.Errorf("--account %q: want TYPE/ID:ROLE, such as postgres/orders-db:readonly", spec)
	}
	return agentAccount{TargetType: kind, TargetID: id, Role: role}, nil
}

func (a agentAccount) String() string { return a.TargetType + "/" + a.TargetID + " as " + a.Role }

func accessAgentUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl access agent --account TYPE/ID:ROLE [--account ...] --reason TEXT --method METHOD --payload-file FILE")
	_, _ = fmt.Fprintln(w, "         [--ttl 15m] [--ssh-principal NAME] [--approval-wait 30m] [--instructions FILE] [--keep] -- <cmd> [args]")
	_, _ = fmt.Fprintln(w, "\nRequests a reviewed session for each account with your token (in CI, an access bundle run's token that acts as the")
	_, _ = fmt.Fprintln(w, "agent: a run may reach only the accounts its bundles delegate), waits for the approvals, and runs the command with a")
	_, _ = fmt.Fprintln(w, "loopback tunnel to each session's gateway and instructions for reaching them (TRSTCTL_ACCESS_INSTRUCTIONS). The")
	_, _ = fmt.Fprintln(w, "command gets no credential: your token is removed from its environment and the gateway signs in for it. Its sessions")
	_, _ = fmt.Fprintln(w, "are revoked when it exits unless --keep is given. METHOD and FILE are the attestation the sessions are opened with.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl access agent --account postgres/orders-db:readonly --reason \"nightly report\" \\")
	_, _ = fmt.Fprintln(w, "           --method github_oidc --payload-file \"$OIDC_TOKEN_FILE\" -- ./report-agent")
}

// agentSession is one opened gateway session and its local tunnel.
type agentSession struct {
	account    agentAccount
	id         string
	expiresAt  time.Time
	direct     bool // delivered with its credential, not through a gateway: always revoked
	delivery   gatewayDelivery
	ticket     string
	listener   net.Listener
	line       string
	kubeconfig string
}

func runAccessAgent(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	fs := flag.NewFlagSet("trstctl-cli access agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var accountSpecs accessRunFlags
	fs.Var(&accountSpecs, "account", "an account the command may reach, as TYPE/ID:ROLE (repeatable)")
	reason := fs.String("reason", "", "why the command needs the accounts (shown to the approvers)")
	method := fs.String("method", "", "attestation method the sessions are opened with")
	payloadFile := fs.String("payload-file", "", "file holding the attestation payload")
	ttl := fs.Duration("ttl", 15*time.Minute, "session lifetime")
	sshPrincipal := fs.String("ssh-principal", "", "SSH accounts: the login the session is for")
	approvalWait := fs.Duration("approval-wait", 30*time.Minute, "how long to wait for the approvals")
	instructionsPath := fs.String("instructions", "", "write the instructions here (default: a private directory removed at exit)")
	keep := fs.Bool("keep", false, "leave the sessions open when the command exits (they still expire)")
	fs.Usage = func() { accessAgentUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 || len(accountSpecs) == 0 || strings.TrimSpace(*reason) == "" || *method == "" || *payloadFile == "" {
		accessAgentUsage(stderr)
		return 2
	}
	if server == "" || token == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server and --token (or TRSTCTL_SERVER and TRSTCTL_TOKEN) are required")
		return 2
	}
	if *ttl <= 0 || *ttl%time.Second != 0 || *approvalWait <= 0 {
		_, _ = fmt.Fprintln(stderr, "error: --ttl must be a positive whole number of seconds; --approval-wait must be positive")
		return 2
	}
	var accounts []agentAccount
	for _, spec := range accountSpecs {
		account, err := parseAgentAccount(spec)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		accounts = append(accounts, account)
	}
	raw, err := os.ReadFile(*payloadFile) // #nosec G304 -- the operator names their own attestation payload file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error: read the attestation payload:", err)
		return 2
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	secret.Wipe(raw)
	httpClient, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: CA file: %v\n", err)
		return 2
	}
	dir, err := os.MkdirTemp("", "trstctl-agent-*")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	l := &agentLauncher{ctx: ctx, client: httpClient, server: server, token: token, tenant: tenant, stderr: stderr}
	var sessions []*agentSession
	tunnels, stopTunnels := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// When the command is done: stop accepting connections, revoke the
	// sessions (the gateway then closes theirs), and give the tunnels a
	// moment to drain.
	defer func() {
		for _, s := range sessions {
			if s.listener != nil {
				_ = s.listener.Close()
			}
		}
		l.ctx = context.WithoutCancel(ctx)
		for _, s := range sessions {
			if s.direct || !*keep {
				l.revoke(s)
			}
		}
		stopTunnels()
		drained := make(chan struct{})
		go func() { wg.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(10 * time.Second):
		}
	}()
	pending := make([]agentPending, 0, len(accounts))
	for _, account := range accounts {
		p, err := l.request(account, *reason, *method, payload, int64(ttl.Seconds()), *sshPrincipal)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", account, err)
			return 1
		}
		pending = append(pending, p)
	}
	for _, p := range pending {
		if err := l.awaitApproval(p, *approvalWait); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", p.account, err)
			return 1
		}
		s, err := l.open(p)
		if s != nil {
			sessions = append(sessions, s)
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", p.account, err)
			return 1
		}
	}
	for i, s := range sessions {
		if err := l.serve(tunnels, &wg, s, dir, i+1); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", s.account, err)
			return 1
		}
	}
	instructions := *instructionsPath
	if instructions == "" {
		instructions = filepath.Join(dir, "instructions.md")
	}
	if err := os.WriteFile(instructions, []byte(agentInstructions(sessions)), 0o600); err != nil {
		_, _ = fmt.Fprintln(stderr, "error: write the instructions:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "access agent: %d session(s) ready; instructions in %s\n", len(sessions), instructions)

	runErr := secretscli.New(tenant, nil, auditsink.Nop{}).WithoutEnv(agentDropsEnv).
		InjectIO(ctx, agentVariables(sessions, instructions), argv, stdin, stdout, stderr)
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		return 0
	case errors.As(runErr, &exitErr):
		return exitErr.ExitCode()
	default:
		_, _ = fmt.Fprintf(stderr, "error: %v\n", runErr)
		return 1
	}
}

// agentDropsEnv names what the launched command must not inherit: every
// control-plane token variable (TRSTCTL_TOKEN, TRSTCTL_ADMIN_TOKEN, ...).
func agentDropsEnv(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "TRSTCTL_") && strings.Contains(upper, "TOKEN")
}

// agentVariables are what the launched command is given on top of the
// launcher's environment: where to reach each account. A single PostgreSQL,
// MySQL or Kubernetes account also gets the variables its stock client reads.
func agentVariables(sessions []*agentSession, instructions string) map[string][]byte {
	out := map[string][]byte{"TRSTCTL_ACCESS_INSTRUCTIONS": []byte(instructions)}
	byType := map[string][]*agentSession{}
	for i, s := range sessions {
		prefix := fmt.Sprintf("TRSTCTL_ACCESS_%d_", i+1)
		out[prefix+"TYPE"], out[prefix+"TARGET"], out[prefix+"ROLE"] = []byte(s.account.TargetType), []byte(s.account.TargetID), []byte(s.account.Role)
		out[prefix+"ADDR"] = []byte(s.listener.Addr().String())
		byType[s.account.TargetType] = append(byType[s.account.TargetType], s)
	}
	if only := byType["postgres"]; len(only) == 1 {
		local := only[0].listener.Addr().(*net.TCPAddr)
		out["PGHOST"], out["PGPORT"], out["PGSSLMODE"] = []byte(local.IP.String()), []byte(strconv.Itoa(local.Port)), []byte("disable")
	}
	if only := byType["mysql"]; len(only) == 1 {
		local := only[0].listener.Addr().(*net.TCPAddr)
		out["MYSQL_HOST"], out["MYSQL_TCP_PORT"] = []byte(local.IP.String()), []byte(strconv.Itoa(local.Port))
	}
	if only := byType["kubernetes"]; len(only) == 1 {
		out["KUBECONFIG"] = []byte(only[0].kubeconfig)
	}
	return out
}

// agentInstructions tells the launched command how to reach its accounts.
func agentInstructions(sessions []*agentSession) string {
	var b strings.Builder
	b.WriteString("# Access for this task\n\n")
	b.WriteString("You hold no credential for these accounts and need none. Each address below is a tunnel this launcher\n")
	b.WriteString("serves; the gateway signs in as the session's own account for you, and every session is recorded.\n")
	b.WriteString("Connect only to these addresses: no other account is part of this task.\n")
	for i, s := range sessions {
		fmt.Fprintf(&b, "\n%d. %s %s as %s, until %s\n", i+1, s.account.TargetType, s.account.TargetID, s.account.Role,
			s.expiresAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "   address: %s (environment TRSTCTL_ACCESS_%d_ADDR)\n", s.listener.Addr(), i+1)
		if s.line != "" {
			fmt.Fprintf(&b, "   client: %s\n", s.line)
		}
	}
	return b.String()
}

type agentLauncher struct {
	ctx                   context.Context
	client                *http.Client
	server, token, tenant string
	stderr                io.Writer
}

// agentPending is a requested session waiting for its approvals.
type agentPending struct {
	account           agentAccount
	body              map[string]any
	approvalRequestID string
	intentDigest      string
}

func (l *agentLauncher) call(method, path string, body any) (int, []byte, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	key := ""
	if method != http.MethodGet {
		key = generateIdempotencyKey()
	}
	return do(l.ctx, l.client, l.server, method, path, nil, raw, l.token, l.tenant, key, "")
}

func (l *agentLauncher) request(account agentAccount, reason, method, payload string, ttlSeconds int64, sshPrincipal string) (agentPending, error) {
	body := map[string]any{"request_id": uuid.NewString(), "target_type": account.TargetType, "target_id": account.TargetID,
		"role": account.Role, "reason": reason, "method": method, "payload_base64": payload, "ttl_seconds": ttlSeconds}
	if account.TargetType == "ssh" {
		body["ssh_principal"] = sshPrincipal
	}
	status, raw, err := l.call(http.MethodPost, "/api/v1/access/session-requests", body)
	if err != nil {
		return agentPending{}, fmt.Errorf("request a session: %w", err)
	}
	var pending struct {
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &pending) != nil || pending.ApprovalRequestID == "" {
		return agentPending{}, fmt.Errorf("request a session: status %d: %s", status, problemDetail(raw))
	}
	_, _ = fmt.Fprintf(l.stderr, "access agent: %s waits for %d approval(s) of request %s\n", account, pending.RequiredApprovals, pending.ApprovalRequestID)
	return agentPending{account: account, body: body, approvalRequestID: pending.ApprovalRequestID, intentDigest: pending.IntentDigest}, nil
}

func (l *agentLauncher) awaitApproval(p agentPending, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		status, raw, err := l.call(http.MethodGet, "/api/v1/access/session-requests/"+p.approvalRequestID, nil)
		if err != nil {
			return fmt.Errorf("read approval progress: %w", err)
		}
		var progress struct {
			Status string `json:"status"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &progress) != nil {
			return fmt.Errorf("read approval progress: status %d: %s", status, problemDetail(raw))
		}
		switch progress.Status {
		case "approved":
			return nil
		case "pending":
		default:
			return fmt.Errorf("request %s is %s", p.approvalRequestID, progress.Status)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("request %s was not approved within %s", p.approvalRequestID, wait)
		}
		select {
		case <-l.ctx.Done():
			return l.ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// open activates an approved session. A session delivered directly (with
// its credential in the reply) is revoked at once: the launcher gives a
// command gateway sessions only.
func (l *agentLauncher) open(p agentPending) (*agentSession, error) {
	p.body["approval_request_id"], p.body["intent_digest"] = p.approvalRequestID, p.intentDigest
	status, raw, err := l.call(http.MethodPost, "/api/v1/access/sessions", p.body)
	defer secret.Wipe(raw)
	if err != nil {
		return nil, fmt.Errorf("open the session: %w", err)
	}
	var opened struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
		Delivery  string    `json:"delivery"`
		Gateway   *struct {
			gatewayDelivery
			Ticket string `json:"ticket"`
		} `json:"gateway"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &opened) != nil || opened.ID == "" {
		return nil, fmt.Errorf("open the session: status %d: %s", status, problemDetail(raw))
	}
	s := &agentSession{account: p.account, id: opened.ID, expiresAt: opened.ExpiresAt}
	if opened.Delivery != "gateway" || opened.Gateway == nil || opened.Gateway.Ticket == "" || opened.Gateway.Address == "" ||
		opened.Gateway.SPIFFEID == "" || opened.Gateway.CAPEM == "" {
		s.direct = true
		return s, errors.New("the account is not delivered through a gateway; the launcher opens gateway sessions only (the session is revoked)")
	}
	s.delivery, s.ticket = opened.Gateway.gatewayDelivery, opened.Gateway.Ticket
	_, _ = fmt.Fprintf(l.stderr, "access agent: %s opened as session %s until %s\n", p.account, s.id, s.expiresAt.UTC().Format(time.RFC3339))
	return s, nil
}

// serve listens on a loopback address for the session and carries each
// connection to its gateway, as access sessions connect does.
func (l *agentLauncher) serve(ctx context.Context, wg *sync.WaitGroup, s *agentSession, dir string, n int) error {
	var hostKey string
	if s.account.TargetType == "ssh" {
		var err error
		if hostKey, err = probeGatewayHostKey(ctx, s.delivery, s.id, s.ticket); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.listener = ln
	prefix := filepath.Join(dir, fmt.Sprintf("account-%d", n))
	s.kubeconfig = prefix + ".kubeconfig"
	if s.line, err = gatewayClientLine(s.account.TargetType, ln.Addr().(*net.TCPAddr), hostKey, prefix+".known_hosts", s.kubeconfig); err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		go func() { <-ctx.Done(); _ = ln.Close() }()
		var conns sync.WaitGroup
		defer conns.Wait()
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				if err := tunnelToGateway(ctx, local, s.delivery, s.id, s.ticket); err != nil {
					_, _ = fmt.Fprintf(l.stderr, "access agent: %s: %v\n", s.account, err)
				}
			}()
		}
	}()
	return nil
}

// revoke ends a session when the command is done with it; one that has
// already ended (an operator's termination, its deadline, the agent identity's
// revocation) needs nothing.
func (l *agentLauncher) revoke(s *agentSession) {
	status, raw, err := l.call(http.MethodPost, "/api/v1/access/sessions/"+s.id+"/revoke", map[string]any{"reason": "the launched command exited"})
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(l.stderr, "warning: revoke session %s: %v (it expires at %s)\n", s.id, err, s.expiresAt.UTC().Format(time.RFC3339))
	case status == http.StatusAccepted:
		_, _ = fmt.Fprintf(l.stderr, "access agent: session %s revoked\n", s.id)
	case status == http.StatusConflict:
		_, _ = fmt.Fprintf(l.stderr, "access agent: session %s had already ended\n", s.id)
	default:
		_, _ = fmt.Fprintf(l.stderr, "warning: revoke session %s: status %d: %s (it expires at %s)\n", s.id, status, problemDetail(raw),
			s.expiresAt.UTC().Format(time.RFC3339))
	}
}
