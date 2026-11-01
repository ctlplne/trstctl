// The trstctl signing clients — a Notation plugin and a PKCS#11 module — are
// their own MPL-2.0 module, so stock signing tools load them without the
// control plane's dependency graph. Standard library only: the private key never
// leaves trstctl's isolated signer; these clients send digests to its
// code-signing API and read the certificate chain that names the key.
module trstctl.com/clients/signing

go 1.26.0
