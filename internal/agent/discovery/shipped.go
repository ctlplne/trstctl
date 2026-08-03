// SPDX-License-Identifier: MPL-2.0

package discovery

// Advertised capability has to mean shipped capability (truth-integrity 1).
//
// The collector boundary in this package declares five certificate source kinds,
// and the served agents API advertised all of them on every enrolled agent. The
// shipped agent binary constructs enumerators for two of them. An operator
// reading that panel concluded their Windows estate, their PKCS#11 tokens, and
// their Kubernetes Secrets were being inventoried. They were not.
//
// This file is the single list of what the agent binary can actually collect. The
// API advertises from it, and a guard test proves every entry has a constructor
// the agent binary reaches — so the list cannot drift back into a wish.
//
// Adding a kind here without wiring its enumerator into cmd/trstctl-agent fails
// the guard. That is the point: the way to advertise a capability is to ship it.

// ShippedSourceKind is one discovery source kind and how the agent collects it.
type ShippedSourceKind struct {
	// Kind is the source kind constant, matching what findings are reported under.
	Kind string
	// Constructor names the function the agent binary calls to build the
	// enumerator. The guard test greps the agent binary for it.
	Constructor string
	// Flags are the agent flags that enable this source. An empty slice means the
	// source is always active.
	Flags []string
}

// ShippedSourceKinds returns the certificate and credential source kinds the
// shipped agent binary can collect today, in the order the API advertises them.
//
// pkcs11 is BUILD-DEPENDENT, and that is the honest answer rather than a
// hedge. PKCS#11 is a dlopen ABI and needs cgo; the default agent build is
// deliberately cgo-free, because a statically linked binary is what makes a
// fleet rollout predictable. A cgo build carries the reader and advertises the
// kind; a cgo-free build carries neither and advertises neither. The census
// reports what THIS binary can do, which is the only thing an operator's panel
// should ever claim.
//
// windows-store joined this list when its crypt32 enumerator was actually wired
// into the agent binary. On a non-Windows build the source reports an ERROR
// rather than an empty inventory — telling a Linux operator their Windows
// estate is clean would be worse than the original defect, because it would
// arrive with the authority of a scan that never happened.
//
// k8s-secret joined this list when its enumerator was actually wired into the
// agent binary — the read side had existed unwired, which is exactly the state
// that made the advertisement false.
func ShippedSourceKinds() []ShippedSourceKind {
	kinds := []ShippedSourceKind{
		{
			Kind:        SourceFilesystem,
			Constructor: "NewFilesystemSource",
			Flags:       []string{"--inventory-cert-roots"},
		},
		{
			Kind:        SourceTrustStore,
			Constructor: "NewOSTrustStoreSource",
			Flags: []string{
				"--inventory-os-trust-roots",
				"--inventory-java-trust-stores",
				"--inventory-nss-trust-roots",
				"--inventory-browser-trust-roots",
			},
		},
		{
			Kind:        SourceKubernetes,
			Constructor: "NewKubernetesSecretSource",
			Flags:       []string{"--inventory-k8s-secrets"},
		},
		{
			Kind:        SourceWindowsCert,
			Constructor: "NewWindowsCertStoreSource",
			Flags: []string{
				"--inventory-windows-stores",
				"--inventory-windows-location",
			},
		},
		{
			Kind:        SourcePrivateKey,
			Constructor: "NewPrivateKeySource",
			Flags:       []string{"--inventory-private-key-roots"},
		},
		{
			// SSH inventory is collected by the sibling sshdiscovery package
			// rather than a Source in this one; the kind is what the served
			// surface advertises, so it belongs on this list either way.
			Kind:        "ssh",
			Constructor: "sshdiscovery.New",
			Flags: []string{
				"--inventory-ssh-host-key-globs",
				"--inventory-ssh-user-key-globs",
				"--inventory-ssh-authorized-keys",
				"--inventory-ssh-known-hosts",
				"--inventory-ssh-sshd-configs",
			},
		},
	}
	if pkcs11Shipped() {
		kinds = append(kinds, ShippedSourceKind{
			Kind:        SourcePKCS11,
			Constructor: "NewPKCS11CertSource",
			Flags: []string{
				"--inventory-pkcs11-module",
				"--inventory-pkcs11-token",
				"--inventory-pkcs11-pin-file",
			},
		})
	}
	return kinds
}

// IsShippedSourceKind reports whether the agent binary can collect this kind.
func IsShippedSourceKind(kind string) bool {
	for _, s := range ShippedSourceKinds() {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// UnshippedSourceKinds returns the declared source kinds the agent binary cannot
// collect yet. The API uses it to say so plainly rather than staying silent about
// a capability the collector boundary appears to offer.
func UnshippedSourceKinds() []string {
	declared := []string{SourceFilesystem, SourcePKCS11, SourceWindowsCert, SourceKubernetes, SourceTrustStore}
	var out []string
	for _, kind := range declared {
		if !IsShippedSourceKind(kind) {
			out = append(out, kind)
		}
	}
	return out
}
