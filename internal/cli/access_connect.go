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
// Stock clients (psql) connect to the local address; neither they nor this
// command ever receive the upstream credential.
func runAccessConnect(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	fs := flag.NewFlagSet("access sessions connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ticketFile := fs.String("ticket-file", "", "file holding the session's one-time ticket (from the open)")
	listen := fs.String("listen", "127.0.0.1:0", "loopback address the local client connects to")
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
	delivery, err := readGatewayDelivery(ctx, httpClient, server, token, tenant, sessionID)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl:", err)
		return 1
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl: listen:", err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	_, _ = fmt.Fprintf(stdout, "session %s: connect your client to %s (gateway %s)\n", sessionID, ln.Addr(), delivery.Address)
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

func readGatewayDelivery(ctx context.Context, client *http.Client, server, token, tenant, sessionID string) (gatewayDelivery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+"/api/v1/access/sessions/"+sessionID, nil)
	if err != nil {
		return gatewayDelivery{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	resp, err := client.Do(req)
	if err != nil {
		return gatewayDelivery{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return gatewayDelivery{}, fmt.Errorf("read session: status %d", resp.StatusCode)
	}
	var session struct {
		Status   string          `json:"status"`
		Delivery string          `json:"delivery"`
		Gateway  gatewayDelivery `json:"gateway"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		return gatewayDelivery{}, err
	}
	switch {
	case session.Delivery != "gateway":
		return gatewayDelivery{}, errors.New("this session is not delivered through a gateway")
	case session.Status != "active":
		return gatewayDelivery{}, fmt.Errorf("this session is %s", session.Status)
	case session.Gateway.Address == "" || session.Gateway.SPIFFEID == "" || session.Gateway.CAPEM == "":
		return gatewayDelivery{}, errors.New("the session's gateway address or identity is not known")
	}
	return session.Gateway, nil
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
	if answer != "OK" {
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
