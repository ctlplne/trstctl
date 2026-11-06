// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/rdp"
)

var (
	accessGatewayDesktopHelper = flag.String("access-gateway-desktop-helper", "", "protected absolute path to the optional Linux native RDP helper; enables reviewed vaulted desktop sessions inside ticket/mTLS tunnels")
	accessGatewayDesktopLimit  = flag.Int("access-gateway-desktop-limit", 4, "maximum native desktop child processes across the gateway, 1–32")
	accessGatewayListen        = flag.String("access-gateway-listen", "",
		"serve brokered access sessions on this address (A254): clients connect through this agent to a database or "+
			"an SSH server, and it signs in with the session's credential (a database login, or a certificate for a key it "+
			"generates), which it holds in locked memory and never returns. "+
			"Requires the gateway role and access.gateway.session in the control plane's claimable job kinds; "+
			"it never carries MCP traffic. Empty disables it")
	accessGatewayHosts = flag.String("access-gateway-hosts", "",
		"comma-separated host names (or IPs) clients reach the access gateway by; each must be the host of a target's "+
			"gateway_address bound to this agent. Empty uses the host of --access-gateway-listen")
)

// startGateway serves brokered access sessions when it is configured and the
// agent holds the gateway role; the returned function stops it. Its serving
// certificate is signed by the agent CA for the bound host names and renewed
// before it ends; caPEM (the agent channel's CA) verifies what comes back.
func startGateway(ctx context.Context, a *agent.Agent, ch relayChannel, caPEM []byte) func() {
	addr := strings.TrimSpace(*accessGatewayListen)
	if addr == "" {
		return func() {}
	}
	if !agentCarriesRole(a.Roles(), mtls.AgentRoleGateway) {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --access-gateway-listen needs the gateway role; this agent was not granted it, so no session is served")
		return func() {}
	}
	hosts := gatewayHosts(addr, *accessGatewayHosts)
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway: name the host clients reach it by with --access-gateway-hosts")
		return func() {}
	}
	cert, err := mtls.NewRenewingServerCertificate(caPEM, hosts, func(csr []byte) ([]byte, error) {
		signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		resp, err := ch.c.SignGatewayServerCertificate(signCtx, &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: hosts})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, errors.New("gateway serving certificate is not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway serving certificate:", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	go cert.Run(ctx, func(_ time.Time, err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway certificate renewal:", err)
		}
	})
	ln, err := mtls.GatewayListen(addr, cert)
	if err != nil {
		cancel()
		cert.Close()
		fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway:", err)
		return func() {}
	}
	gw, err := accessgateway.New(accessgateway.Config{Channel: ch, Listener: ln, DesktopHelper: strings.TrimSpace(*accessGatewayDesktopHelper), MaxDesktopConnections: *accessGatewayDesktopLimit,
		Logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "trstctl-agent: "+format+"\n", args...) }})
	if err != nil {
		cancel()
		_ = ln.Close()
		cert.Close()
		fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway:", err)
		return func() {}
	}
	go func() {
		if err := gw.Run(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: access gateway stopped:", err)
		}
		cert.Close()
	}()
	return cancel
}

// gatewayHosts is the host names the gateway's certificate names: the flag's
// list, or the listen address's host when it is a specific one.
func gatewayHosts(listen, flagValue string) []string {
	var out []string
	for _, h := range strings.Split(flagValue, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	if len(out) > 0 {
		return out
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return nil
	}
	return []string{host}
}

func desktopHelperReady() bool {
	path := strings.TrimSpace(*accessGatewayDesktopHelper)
	return path != "" && rdp.CheckHelper(path) == nil
}
