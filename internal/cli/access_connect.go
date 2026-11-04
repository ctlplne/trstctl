// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// runAccessConnect is "trstctl access sessions connect <session-id>" (A254):
// it reads a gateway-delivered session, listens on a loopback address, and
// carries each local connection to the session's gateway over TLS verified
// against the gateway's agent certificate, opening with the session's ticket.
// Stock clients (psql, mysql, mongosh, redis-cli, curl, kubectl, ssh) connect to the local address; neither they nor
// this command ever receive the upstream credential. For an SSH session it
// first learns the gateway's SSH host key through that verified tunnel and
// writes it to a known_hosts file for the ssh command it prints.
func runAccessConnect(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	fs := flag.NewFlagSet("access sessions connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ticketFile := fs.String("ticket-file", "", "file holding the session's one-time ticket (from the open)")
	listen := fs.String("listen", "127.0.0.1:0", "loopback address the local client connects to")
	knownHosts := fs.String("known-hosts", "", "SSH sessions: file to write the gateway's host key to (default: the ticket file with .known_hosts appended)")
	kubeconfig := fs.String("kubeconfig", "", "Kubernetes sessions: file to write a kubeconfig for the tunnel to (default: the ticket file with .kubeconfig appended)")
	// The session ID may come before or after the flags.
	var sessionID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sessionID, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if sessionID == "" && fs.NArg() == 1 {
		sessionID = fs.Arg(0)
	} else if fs.NArg() != 0 {
		sessionID = ""
	}
	if sessionID == "" || *ticketFile == "" {
		_, _ = fmt.Fprintln(stderr, "usage: trstctl access sessions connect <session-id> --ticket-file FILE [--listen 127.0.0.1:PORT]")
		return 2
	}
	host, _, err := net.SplitHostPort(*listen)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		_, _ = fmt.Fprintln(stderr, "trstctl: --listen must be a loopback address")
		return 2
	}
	raw, err := os.ReadFile(*ticketFile) // #nosec G304 -- the operator names their own ticket file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl: read ticket:", err)
		return 1
	}
	ticket := strings.TrimSpace(string(raw))
	secret.Wipe(raw)
	httpClient, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl:", err)
		return 1
	}
	delivery, targetType, err := readGatewayDelivery(ctx, httpClient, server, token, tenant, sessionID)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl:", err)
		return 1
	}
	var hostKey string
	if targetType == "ssh" {
		if hostKey, err = probeGatewayHostKey(ctx, delivery, sessionID, ticket); err != nil {
			_, _ = fmt.Fprintln(stderr, "trstctl:", err)
			return 1
		}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl: listen:", err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	_, _ = fmt.Fprintf(stdout, "session %s: connect your client to %s (gateway %s)\n", sessionID, ln.Addr(), delivery.Address)
	if targetType == "ssh" {
		path := *knownHosts
		if path == "" {
			path = *ticketFile + ".known_hosts"
		}
		local := ln.Addr().(*net.TCPAddr)
		entry := fmt.Sprintf("[%s]:%d %s\n", local.IP, local.Port, hostKey)
		if err := os.WriteFile(path, []byte(entry), 0o600); err != nil {
			_, _ = fmt.Fprintln(stderr, "trstctl: write known_hosts:", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "ssh -p %d -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes %s\n", local.Port, path, local.IP)
	}
	if targetType == "mysql" {
		// The gateway answers the client's handshake and signs in as the
		// session's account; the client sends no password.
		local := ln.Addr().(*net.TCPAddr)
		_, _ = fmt.Fprintf(stdout, "mysql -h %s -P %d\n", local.IP, local.Port)
	}
	if targetType == "mongodb" {
		// The gateway signs in as the session's user; the client sends no
		// credential (its own sign-in is refused).
		local := ln.Addr().(*net.TCPAddr)
		_, _ = fmt.Fprintf(stdout, "mongosh mongodb://%s:%d/?directConnection=true\n", local.IP, local.Port)
	}
	if targetType == "kubernetes" {
		// A kubeconfig that names the tunnel and no user: the gateway adds
		// the session's token to every request.
		path := *kubeconfig
		if path == "" {
			path = *ticketFile + ".kubeconfig"
		}
		local := ln.Addr().(*net.TCPAddr)
		config := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: trstctl-gateway\n  cluster:\n    server: http://%s:%d\n"+
			"users:\n- name: trstctl-session\n  user: {}\ncontexts:\n- name: trstctl-session\n  context:\n    cluster: trstctl-gateway\n    user: trstctl-session\n"+
			"current-context: trstctl-session\n", local.IP, local.Port)
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			_, _ = fmt.Fprintln(stderr, "trstctl: write kubeconfig:", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "kubectl --kubeconfig %s get pods\n", path)
	}
	if targetType == "clickhouse" {
		// ClickHouse's HTTP interface: the gateway signs each request in as
		// the session's user; the client sends no credential.
		local := ln.Addr().(*net.TCPAddr)
		_, _ = fmt.Fprintf(stdout, "curl http://%s:%d/ --data-binary 'SELECT 1'\n", local.IP, local.Port)
	}
	if targetType == "redis" {
		// The gateway signs in as the session's user; the client sends no
		// AUTH (one it sends is refused).
		local := ln.Addr().(*net.TCPAddr)
		_, _ = fmt.Fprintf(stdout, "redis-cli -h %s -p %d\n", local.IP, local.Port)
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	var wg sync.WaitGroup
	for {
		local, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return 0
			}
			_, _ = fmt.Fprintln(stderr, "trstctl: accept:", err)
			return 1
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tunnelToGateway(ctx, local, delivery, sessionID, ticket); err != nil {
				_, _ = fmt.Fprintln(stderr, "trstctl:", err)
			}
		}()
	}
}

type gatewayDelivery struct {
	Address  string `json:"address"`
	SPIFFEID string `json:"spiffe_id"`
	CAPEM    string `json:"ca_pem"`
}

func readGatewayDelivery(ctx context.Context, client *http.Client, server, token, tenant, sessionID string) (gatewayDelivery, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+"/api/v1/access/sessions/"+sessionID, nil)
	if err != nil {
		return gatewayDelivery{}, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	resp, err := client.Do(req)
	if err != nil {
		return gatewayDelivery{}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return gatewayDelivery{}, "", fmt.Errorf("read session: status %d", resp.StatusCode)
	}
	var session struct {
		Status     string          `json:"status"`
		TargetType string          `json:"target_type"`
		Delivery   string          `json:"delivery"`
		Gateway    gatewayDelivery `json:"gateway"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		return gatewayDelivery{}, "", err
	}
	switch {
	case session.Delivery != "gateway":
		return gatewayDelivery{}, "", errors.New("this session is not delivered through a gateway")
	case session.Status != "active":
		return gatewayDelivery{}, "", fmt.Errorf("this session is %s", session.Status)
	case session.Gateway.Address == "" || session.Gateway.SPIFFEID == "" || session.Gateway.CAPEM == "":
		return gatewayDelivery{}, "", errors.New("the session's gateway address or identity is not known")
	}
	return session.Gateway, session.TargetType, nil
}

// probeGatewayHostKey opens one verified connection to learn the SSH host key
// the gateway serves the session with; the gateway's answer arrives over the
// TLS connection verified against its agent certificate.
func probeGatewayHostKey(ctx context.Context, delivery gatewayDelivery, sessionID, ticket string) (string, error) {
	remote, err := mtls.GatewayDial(ctx, delivery.Address, []byte(delivery.CAPEM), delivery.SPIFFEID)
	if err != nil {
		return "", fmt.Errorf("gateway: %w", err)
	}
	defer func() { _ = remote.Close() }()
	if _, err := fmt.Fprintf(remote, "TRSTCTL-GATEWAY/1 %s %s\n", sessionID, ticket); err != nil {
		return "", err
	}
	answer, err := readGatewayAnswer(remote)
	if err != nil {
		return "", err
	}
	key, ok := strings.CutPrefix(answer, "OK ")
	if !ok {
		return "", fmt.Errorf("gateway refused the connection: %s", strings.TrimPrefix(answer, "DENY "))
	}
	if fields := strings.Fields(key); len(fields) != 2 || strings.ContainsAny(key, "\r\n") {
		return "", errors.New("gateway answered with no SSH host key")
	}
	return key, nil
}

// tunnelToGateway opens one verified TLS connection to the gateway, presents
// the ticket, and pipes the local connection through once the gateway admits it.
func tunnelToGateway(ctx context.Context, local net.Conn, delivery gatewayDelivery, sessionID, ticket string) error {
	defer func() { _ = local.Close() }()
	remote, err := mtls.GatewayDial(ctx, delivery.Address, []byte(delivery.CAPEM), delivery.SPIFFEID)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	defer func() { _ = remote.Close() }()
	if _, err := fmt.Fprintf(remote, "TRSTCTL-GATEWAY/1 %s %s\n", sessionID, ticket); err != nil {
		return err
	}
	answer, err := readGatewayAnswer(remote)
	if err != nil {
		return err
	}
	if answer != "OK" && !strings.HasPrefix(answer, "OK ") {
		return fmt.Errorf("gateway refused the connection: %s", strings.TrimPrefix(answer, "DENY "))
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, remote); done <- struct{}{} }()
	<-done
	return nil
}

// readGatewayAnswer reads the gateway's one-line answer without buffering past it.
func readGatewayAnswer(conn net.Conn) (string, error) {
	r := bufio.NewReaderSize(&oneByteReader{conn}, 16)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("gateway answer: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// oneByteReader hands bufio one byte per read, so nothing after the answer
// line is consumed from the connection.
type oneByteReader struct{ c net.Conn }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.c.Read(p[:1])
}
