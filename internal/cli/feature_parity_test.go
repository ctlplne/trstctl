package cli_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/featureparity"
)

func TestFeatureParityMapsCatalogRowsToCLICommands(t *testing.T) {
	commands := cliCommandSet(t)

	for _, item := range loadFeatureParityCatalog(t).Items {
		if len(item.CLISurface) == 0 && strings.TrimSpace(item.CLINA) == "" {
			t.Errorf("%s (%s) has no cli_surface commands and no cli_na reason", item.FeatureID, item.Feature)
		}
		if len(item.CLISurface) > 0 && strings.TrimSpace(item.CLINA) != "" {
			t.Errorf("%s (%s) declares both cli_surface and cli_na", item.FeatureID, item.Feature)
		}
		for _, command := range item.CLISurface {
			if strings.TrimSpace(command) == "" {
				t.Errorf("%s (%s) has a blank cli_surface command", item.FeatureID, item.Feature)
				continue
			}
			if !commands[command] {
				t.Errorf("%s (%s) references missing CLI command %q", item.FeatureID, item.Feature, command)
			}
		}
	}
}

func loadFeatureParityCatalog(t *testing.T) featureparity.Catalog {
	t.Helper()
	catalog, err := featureparity.Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	return catalog
}

func cliCommandSet(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, command := range cli.Commands() {
		name := strings.Join(command.Name, " ")
		if out[name] {
			t.Fatalf("CLI command %q is duplicated", name)
		}
		out[name] = true
	}
	if len(out) != 107 {
		t.Fatalf("CLI commands = %d, want 107", len(out))
	}
	return out
}
