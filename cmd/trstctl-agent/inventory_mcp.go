// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/agent"
)

// MCP client configuration inventory (P7): the MCP servers desktop
// assistants and IDEs on this host are configured to start or call, with any
// static credential named by field and never sent.
var inventoryMCPConfigRoots = flag.String("inventory-mcp-config-roots", "",
	"comma-separated directories (home or configuration directories) whose MCP client configuration files the agent reads, by format: each configured server, its transport and program or host, and which fields hold a static credential; values never leave the host, and an unchanged rescan sends nothing")

func reportMCPInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, keyPath string) {
	roots := splitList(*inventoryMCPConfigRoots)
	if len(roots) == 0 {
		return
	}
	state := filepath.Join(filepath.Dir(keyPath), "mcp-inventory.digest")
	resp, sent, err := a.ReportMCPInventory(ctx, ch, roots, state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: MCP client configuration inventory report failed:", err)
		return
	}
	if sent {
		fmt.Printf("trstctl-agent: reported %d MCP servers (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	}
}
