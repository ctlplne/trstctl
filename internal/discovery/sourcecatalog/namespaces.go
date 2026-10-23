// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import "strings"

// Product-created discovery sources use these tenant-local name namespaces.
// Tenant-authored generic and CT declarations cannot claim them before the
// product producer records its deterministic source identity.
const (
	AgentSourcePrefix            = "agent:"
	SecretScanSourcePrefix       = "secretscan:"
	SecretRepositorySourcePrefix = "secret-repo:"
	ThirdPartySecretSourcePrefix = "secret-third-party:"
	WeakKeyAuditSourcePrefix     = "weak-key-audit:"
	EndpointChainSourcePrefix    = "endpoint-chain:"
)

type ReservedNamespace struct {
	Prefix   string
	Producer string
}

var reservedNamespaces = [...]ReservedNamespace{
	{AgentSourcePrefix, "authenticated agent inventory"},
	{SecretScanSourcePrefix, "product secret scan"},
	{SecretRepositorySourcePrefix, "repository secret scan"},
	{ThirdPartySecretSourcePrefix, "third-party secret scan"},
	{WeakKeyAuditSourcePrefix, "inventory weak-key audit"},
	{EndpointChainSourcePrefix, "endpoint issuer-chain verification"},
}

// ReservedNamespaces returns a copy for the registration guard and docs.
func ReservedNamespaces() []ReservedNamespace {
	return append([]ReservedNamespace(nil), reservedNamespaces[:]...)
}

func ReservedNamespaceForName(name string) (ReservedNamespace, bool) {
	name = strings.TrimSpace(name)
	for _, namespace := range reservedNamespaces {
		if strings.HasPrefix(name, namespace.Prefix) {
			return namespace, true
		}
	}
	return ReservedNamespace{}, false
}
