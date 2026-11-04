// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/agent/discovery"
)

// ReportMCPInventory reports the MCP servers configured under roots (P7) when
// they differ from this agent's last report, whose digest it keeps at
// statePath: a rescan with no changes sends nothing, so it writes no event.
// It reports whether it sent a report. Credential values never leave the
// host: findings carry where a static credential is, never what it is.
func (a *Agent) ReportMCPInventory(ctx context.Context, ch ChannelClient, roots []string, statePath string) (*InventoryResponse, bool, error) {
	found, err := discovery.NewMCPClientConfigSource(roots...).Discover(ctx)
	if err != nil {
		return nil, false, err
	}
	digest := discovery.MCPInventoryDigest(found)
	if statePath != "" {
		if prev, err := os.ReadFile(statePath); err == nil && strings.TrimSpace(string(prev)) == digest { // #nosec G304 -- the agent's own state file (CWE-22)
			return nil, false, nil
		}
	}
	var resp *InventoryResponse
	if len(found) > 0 {
		records := discovery.MCPInventoryFindings(found)
		findings := make([]InventoryFinding, 0, len(records))
		for _, r := range records {
			findings = append(findings, InventoryFinding{Kind: discovery.FindingKindMCPServer, Ref: r.Ref, Provenance: r.Provenance,
				Fingerprint: r.Fingerprint, RiskScore: r.RiskScore, Metadata: r.Metadata})
		}
		if resp, err = a.ReportInventory(ctx, ch, discovery.SourceMCPClientConfig, findings); err != nil {
			return nil, false, err
		}
	}
	if statePath != "" {
		if err := writeMCPInventoryState(statePath, digest); err != nil {
			return resp, resp != nil, err
		}
	}
	return resp, resp != nil, nil
}

// writeMCPInventoryState replaces the digest file atomically, readable only by
// the agent.
func writeMCPInventoryState(path, digest string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mcp-inventory-*")
	if err != nil {
		return fmt.Errorf("agent: MCP inventory state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(digest + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: MCP inventory state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: MCP inventory state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: MCP inventory state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("agent: MCP inventory state: %w", err)
	}
	return nil
}
