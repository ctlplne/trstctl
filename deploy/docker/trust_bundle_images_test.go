// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"strings"
	"testing"
)

// Part 1 of the eMudhra response: every image ships one trust bundle, the
// pinned Alpine ca-certificates bundle filtered by the shipped distrust list,
// as /etc/ssl/certs/ca-certificates.crt, and nothing else that Go or OpenSSL
// would read as a root. The Debian images must not install Debian's
// ca-certificates (it links every root as its own file beside the bundle), and
// no image may redirect the store with SSL_CERT_FILE or SSL_CERT_DIR.
func TestEveryImageShipsTheFilteredTrustBundle(t *testing.T) {
	const (
		apk    = "ca-certificates-bundle-20261020-r0.apk"
		filter = "trstctl-trustbundle filter -in /tmp/trust/ca-certificates-bundle.apk -out /out/trust/ca-certificates.crt -report /out/trust/report.json -expect 118"
		copy   = "COPY --from=trust /out/trust/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt"
	)
	for _, path := range []string{"Dockerfile", "Dockerfile.signer-hsm", "Dockerfile.agent-pkcs11", "Dockerfile.nats", "Dockerfile.node", "Dockerfile.postgres", "../demo/Dockerfile.seed"} {
		df := readArtifact(t, path)
		for _, want := range []string{"--checksum=sha256:bb008f6d214b6af7576324659856fb63dc8dcb4373f8345ff706388696f1254d", apk, filter, copy} {
			if !strings.Contains(df, want) {
				t.Errorf("%s does not carry %q: the image would ship a trust store the distrust list has not filtered", path, want)
			}
		}
		if strings.Contains(df, "SSL_CERT_FILE") || strings.Contains(df, "SSL_CERT_DIR") {
			t.Errorf("%s redirects the trust store with SSL_CERT_FILE/SSL_CERT_DIR", path)
		}
	}
	for _, path := range []string{"Dockerfile.signer-hsm", "Dockerfile.agent-pkcs11"} {
		df := readArtifact(t, path)
		for _, line := range strings.Split(df, "\n") {
			if strings.Contains(line, "apt-get install") && strings.Contains(line, "ca-certificates") {
				t.Errorf("%s installs Debian's ca-certificates: %s", path, strings.TrimSpace(line))
			}
		}
	}
	front := readArtifact(t, "../demo/lab/frontdoors/Dockerfile")
	if !strings.Contains(front, "COPY --from=trstctl /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt") || !strings.Contains(front, "rm -rf /etc/ssl/certs/*") {
		t.Error("frontdoors image does not take the control-plane image's filtered bundle as its only store")
	}
	for _, path := range []string{"Dockerfile.node", "../demo/Dockerfile.seed"} {
		if !strings.Contains(readArtifact(t, path), "NODE_OPTIONS=--use-openssl-ca") {
			t.Errorf("%s: Node must read the system store (NODE_OPTIONS=--use-openssl-ca), not its built-in roots", path)
		}
	}
}
