// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// AUD32's generated family parity: every catalog row is classified from the
// executable census. Host families restore locally, four appliance families
// re-bind, and every other advertised family is explicitly unsupported.
func TestConnectorCatalogRollbackParityComesFromExecutableFamilies(t *testing.T) {
	seen := make(map[string]bool, len(servedConnectorCatalog))
	for _, item := range servedConnectorCatalog {
		if seen[item.Name] {
			t.Fatalf("duplicate connector catalog family %q", item.Name)
		}
		seen[item.Name] = true
		want := connector.CanRollbackOnHost(item.Name) || connector.CanRollback(item.Name)
		if got := connector.CanExecuteRollback(item.Name); got != want {
			t.Errorf("%s executable rollback=%v, host-or-rebind=%v", item.Name, got, want)
		}
	}
	for _, name := range append(connector.HostRollbackCapableConnectors(), connector.RollbackCapableConnectors()...) {
		if !seen[name] {
			t.Errorf("executable rollback family %q is absent from served connector catalog", name)
		}
	}
}
