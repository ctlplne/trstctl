// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/sshinv"
)

const agentAuthorizedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt alice@laptop"

type inventoryReporterStub struct {
	sourceKind string
	findings   []agent.InventoryFinding
}

type blockingInventoryReporter struct {
	entered chan struct{}
	exited  chan struct{}
}

func (s *blockingInventoryReporter) ReportInventory(ctx context.Context, _ agent.ChannelClient, _ string, _ []agent.InventoryFinding) (*agent.InventoryResponse, error) {
	close(s.entered)
	<-ctx.Done()
	close(s.exited)
	return nil, ctx.Err()
}

func TestSSHInventoryDoesNotBlockAgentStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(agentAuthorizedKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter := &blockingInventoryReporter{entered: make(chan struct{}), exited: make(chan struct{})}
	returned := make(chan struct{})
	go func() {
		startSSHInventory(ctx, reporter, nil, sshdiscovery.Config{AuthorizedKeysPaths: []string{path}})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("SSH inventory gated agent startup while its report was blocked")
	}
	select {
	case <-reporter.entered:
	case <-time.After(time.Second):
		t.Fatal("background SSH inventory did not reach its report")
	}
	cancel()
	select {
	case <-reporter.exited:
	case <-time.After(time.Second):
		t.Fatal("background SSH inventory did not stop with the agent context")
	}
}

func (s *inventoryReporterStub) ReportInventory(_ context.Context, _ agent.ChannelClient, sourceKind string, findings []agent.InventoryFinding) (*agent.InventoryResponse, error) {
	s.sourceKind = sourceKind
	s.findings = append([]agent.InventoryFinding(nil), findings...)
	return &agent.InventoryResponse{RunID: "run-ssh", Recorded: len(findings)}, nil
}

func TestShippedAgentReportsConfiguredAuthorizedKeysMetadata(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "authorized_keys")
	if err := os.WriteFile(path, []byte(agentAuthorizedKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reporter := &inventoryReporterStub{}
	if err := reportSSHInventory(context.Background(), reporter, nil, sshdiscovery.Config{
		AuthorizedKeysPaths: []string{path},
	}); err != nil {
		t.Fatal(err)
	}
	if reporter.sourceKind != "ssh" {
		t.Fatalf("source kind = %q, want ssh", reporter.sourceKind)
	}
	if len(reporter.findings) != 1 {
		t.Fatalf("findings = %+v, want one authorized_keys grant", reporter.findings)
	}
	got := reporter.findings[0]
	if got.Kind != "ssh_key" || got.Ref != path || got.Metadata["source"] != sshinv.SourceAuthorizedKeys {
		t.Fatalf("finding identity = %+v", got)
	}
	if got.Metadata["standing_access"] != "true" || got.Metadata["orphaned"] != "false" {
		t.Fatalf("standing-access metadata = %+v", got.Metadata)
	}
	if _, ok := got.Metadata["public_key"]; ok {
		t.Fatalf("wire finding contains public-key bytes: %+v", got.Metadata)
	}
}
